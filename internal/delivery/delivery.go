// Package delivery sends queued messages to remote mail servers, directly
// via MX lookup or through a smarthost, and builds bounce messages.
package delivery

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/DevHatRo/outbound-smtp/internal/config"
	"github.com/DevHatRo/outbound-smtp/internal/store"
)

// Status is the outcome of one delivery attempt for one recipient.
type Status int

// Delivery outcomes.
const (
	Delivered Status = iota // accepted by the remote server
	Deferred                // temporary failure, retry later
	Bounced                 // permanent failure
)

func (s Status) String() string {
	return [...]string{"delivered", "deferred", "bounced"}[s]
}

// Result is what happened to one recipient.
type Result struct {
	Recipient store.Recipient
	Status    Status
	Response  string // remote reply or local error, single line
	Host      string // remote server, "" if none was reached
	TLS       bool
}

// Resolver is the part of net.Resolver that delivery needs.
type Resolver interface {
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// Client delivers messages.
type Client struct {
	cfg      *config.Config
	Resolver Resolver
	// Dial opens the TCP connection; tests point it at a fake server.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// Port is the remote SMTP port for direct delivery.
	Port string
	// StepTimeout bounds each protocol step (greeting, EHLO, MAIL, RCPT, ...).
	StepTimeout time.Duration
	// DataTimeout bounds sending the message and waiting for the final reply.
	DataTimeout time.Duration
}

// New returns a client using the system resolver.
func New(cfg *config.Config) *Client {
	d := &net.Dialer{Timeout: 30 * time.Second}
	return &Client{cfg: cfg, Resolver: net.DefaultResolver, Dial: d.DialContext, Port: "25",
		StepTimeout: 2 * time.Minute, DataTimeout: 10 * time.Minute}
}

// errTLS marks a failed opportunistic STARTTLS, after which the same host is
// retried in plaintext.
var errTLS = errors.New("STARTTLS failed")

const maxHosts = 5

// Deliver makes one attempt to hand msg to the recipients, which all share
// the destination domain. It returns one Result per recipient.
func (c *Client) Deliver(ctx context.Context, msg store.Message, domain string, rcpts []store.Recipient) []Result {
	all := func(st Status, host, format string, a ...any) []Result {
		out := make([]Result, len(rcpts))
		for i, r := range rcpts {
			out[i] = Result{Recipient: r, Status: st, Response: oneLine(fmt.Sprintf(format, a...)), Host: host}
		}
		return out
	}

	smarthost := c.cfg.SmarthostHost != ""
	var hosts []string
	port := c.Port
	if smarthost {
		hosts, port = []string{c.cfg.SmarthostHost}, strconv.Itoa(c.cfg.SmarthostPort)
	} else {
		var st Status
		var err error
		if hosts, st, err = c.mxHosts(ctx, domain); err != nil {
			return all(st, "", "%v", err)
		}
	}

	var lastErr error
	lastHost := ""
	for _, host := range hosts {
		for _, useTLS := range []bool{true, false} {
			results, err := c.session(ctx, host, port, smarthost, useTLS, msg, rcpts)
			if err == nil {
				return results
			}
			lastErr, lastHost = err, host
			// Plaintext fallback only for opportunistic TLS; a smarthost with
			// credentials never downgrades.
			if !errors.Is(err, errTLS) || (smarthost && c.cfg.SmarthostUsername != "") {
				break
			}
		}
		if ctx.Err() != nil {
			break
		}
	}
	// No server gave a definite answer: always temporary. The message bounces
	// when it reaches the maximum queue lifetime.
	return all(Deferred, lastHost, "%v", lastErr)
}

// mxHosts returns the servers to try for a domain, best preference first.
func (c *Client) mxHosts(ctx context.Context, domain string) ([]string, Status, error) {
	mxs, err := c.Resolver.LookupMX(ctx, domain)
	if len(mxs) == 0 {
		var dnsErr *net.DNSError
		if err != nil && (!errors.As(err, &dnsErr) || !dnsErr.IsNotFound) {
			return nil, Deferred, fmt.Errorf("MX lookup for %s failed: %w", domain, err)
		}
		// No MX record: RFC 5321 falls back to the domain's address records.
		if _, err := c.Resolver.LookupHost(ctx, domain); err != nil {
			if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
				return nil, Bounced, fmt.Errorf("5.1.2 domain %s has no MX or address records", domain)
			}
			return nil, Deferred, fmt.Errorf("address lookup for %s failed: %w", domain, err)
		}
		return []string{domain}, 0, nil
	}
	if len(mxs) == 1 && strings.TrimSuffix(mxs[0].Host, ".") == "" {
		return nil, Bounced, fmt.Errorf("5.1.10 domain %s does not accept mail (null MX)", domain) // RFC 7505
	}
	var hosts []string
	for _, mx := range mxs { // LookupMX sorts by preference
		if h := strings.TrimSuffix(mx.Host, "."); h != "" && len(hosts) < maxHosts {
			hosts = append(hosts, h)
		}
	}
	return hosts, 0, nil
}

// session runs one SMTP session. A non-nil error means the session failed
// before the server answered for this message (connection, greeting, TLS),
// so the caller may try elsewhere; otherwise every recipient has a Result.
func (c *Client) session(ctx context.Context, host, port string, smarthost, useTLS bool, msg store.Message, rcpts []store.Recipient) ([]Result, error) {
	network := "tcp4" // many senders have no IPv6 PTR/SPF, which big receivers reject
	if c.cfg.DeliveryIPv6 {
		network = "tcp"
	}
	conn, err := c.Dial(ctx, network, net.JoinHostPort(host, port))
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", host, err)
	}
	defer conn.Close() //nolint:errcheck // best effort; QUIT is sent on the success path
	step := func(d time.Duration) { _ = conn.SetDeadline(time.Now().Add(d)) }
	// Closing (not a deadline, which the next step would overwrite) is what
	// makes cancellation stick. raw is never reassigned, unlike conn.
	raw := conn
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop()

	withCreds := smarthost && c.cfg.SmarthostUsername != ""
	tlsCfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if !withCreds {
		// Opportunistic TLS, as MTAs do between each other: most MX certificates
		// cannot be validated against the recipient domain, and the alternative
		// is plaintext. Credentials are never sent over such a connection.
		tlsCfg.InsecureSkipVerify = true //nolint:gosec // see comment above
	}

	step(c.StepTimeout)
	if smarthost && port == "465" {
		tc := tls.Client(conn, tlsCfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			return nil, fmt.Errorf("TLS handshake with %s: %w", host, err)
		}
		conn = tc
	}
	cl, err := smtp.NewClient(conn, host) // reads the greeting
	if err != nil {
		return nil, fmt.Errorf("greeting from %s: %w", host, err)
	}
	if err := cl.Hello(c.cfg.Hostname); err != nil {
		return nil, fmt.Errorf("EHLO to %s: %w", host, err)
	}
	if _, isTLS := cl.TLSConnectionState(); !isTLS {
		offered, _ := cl.Extension("STARTTLS")
		switch {
		case offered && useTLS:
			if err := cl.StartTLS(tlsCfg); err != nil {
				return nil, fmt.Errorf("%w with %s: %w", errTLS, host, err)
			}
		case withCreds:
			return nil, fmt.Errorf("smarthost %s does not offer STARTTLS; refusing to send credentials in plaintext", host)
		}
	}
	_, usedTLS := cl.TLSConnectionState()
	if withCreds {
		// PlainAuth itself also refuses to run without TLS.
		if err := cl.Auth(smtp.PlainAuth("", c.cfg.SmarthostUsername, c.cfg.SmarthostPassword, host)); err != nil {
			return nil, fmt.Errorf("smarthost authentication at %s: %w", host, err)
		}
	}

	results := make([]Result, len(rcpts))
	for i, r := range rcpts {
		results[i] = Result{Recipient: r, Host: host, TLS: usedTLS}
	}
	setAll := func(err error, only func(i int) bool) {
		st, resp := classify(err)
		for i := range results {
			if only == nil || only(i) {
				results[i].Status, results[i].Response = st, resp
			}
		}
	}

	step(c.StepTimeout)
	if err := cl.Mail(msg.EnvelopeFrom); err != nil {
		// 421 is the server closing the session, not a verdict on this
		// message: let the caller try the next MX.
		var pe *textproto.Error
		if errors.As(err, &pe) && pe.Code == 421 {
			return nil, fmt.Errorf("MAIL at %s: %w", host, err)
		}
		setAll(err, nil)
		return results, nil
	}
	accepted := make([]bool, len(rcpts))
	anyAccepted := false
	for i, r := range rcpts {
		step(c.StepTimeout)
		if err := cl.Rcpt(r.Address); err != nil {
			results[i].Status, results[i].Response = classify(err)
			// RFC 5321 4.5.3.1.10: 552 at RCPT is the legacy "too many
			// recipients" reply and must be treated as temporary.
			var pe *textproto.Error
			if errors.As(err, &pe) && pe.Code == 552 {
				results[i].Status = Deferred
			}
			continue
		}
		accepted[i], anyAccepted = true, true
	}
	if !anyAccepted {
		_ = cl.Quit() // every recipient already has its answer
		return results, nil
	}

	// DATA by hand over textproto, because net/smtp discards the final reply
	// ("250 2.0.0 Ok: queued as ...") that operators want in the log.
	step(c.DataTimeout)
	reply, err := sendData(cl.Text, msg.Body)
	isAccepted := func(i int) bool { return accepted[i] }
	if err != nil {
		setAll(err, isAccepted)
		return results, nil
	}
	for i := range results {
		if accepted[i] {
			results[i].Status, results[i].Response = Delivered, reply
		}
	}
	step(10 * time.Second)
	_ = cl.Quit() // the message is already accepted
	return results, nil
}

func sendData(text *textproto.Conn, body []byte) (reply string, err error) {
	id, err := text.Cmd("DATA")
	if err != nil {
		return "", err
	}
	text.StartResponse(id)
	_, _, err = text.ReadResponse(354)
	text.EndResponse(id)
	if err != nil {
		return "", err
	}
	w := text.DotWriter() // dot-stuffs and ends with CRLF.CRLF
	if _, err := w.Write(body); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	code, msg, err := text.ReadResponse(250)
	if err != nil {
		return "", err
	}
	return oneLine(fmt.Sprintf("%d %s", code, msg)), nil
}

// classify maps an SMTP or network error to a status and a log-safe reply.
// Only a 5xx reply from the server is permanent.
func classify(err error) (Status, string) {
	var pe *textproto.Error
	if errors.As(err, &pe) {
		st := Deferred
		if pe.Code >= 500 && pe.Code < 600 {
			st = Bounced
		}
		return st, oneLine(fmt.Sprintf("%d %s", pe.Code, pe.Msg))
	}
	return Deferred, oneLine(err.Error())
}

// oneLine flattens a reply and caps it at 500 bytes without cutting a rune.
func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	const limit = 500
	if len(s) <= limit {
		return s
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}
