package delivery

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/DevHatRo/outbound-smtp/internal/config"
	"github.com/DevHatRo/outbound-smtp/internal/store"
	"github.com/DevHatRo/outbound-smtp/internal/testutil"
)

type fakeDNS struct {
	mx    map[string][]*net.MX
	hosts map[string]bool
	err   error
}

func notFound(name string) error {
	return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (f fakeDNS) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	if f.err != nil {
		return nil, f.err
	}
	if mx, ok := f.mx[name]; ok {
		return mx, nil
	}
	return nil, notFound(name)
}

func (f fakeDNS) LookupHost(_ context.Context, host string) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.hosts[host] {
		return []string{"192.0.2.1"}, nil
	}
	return nil, notFound(host)
}

type fixture struct {
	sink   *testutil.Sink
	client *Client
	dialed []string
	roots  *x509.CertPool    // trusts the sink's certificate
	dialTo map[string]string // host -> address, instead of the sink
}

// newFixture starts a sink and a client whose every connection lands on it,
// whatever host DNS named. Hosts listed in down refuse the connection.
func newFixture(t *testing.T, sinkTLS bool, dns fakeDNS, down ...string) *fixture {
	t.Helper()
	var tlsCfg *tls.Config
	var roots *x509.CertPool
	if sinkTLS {
		certFile, keyFile, err := testutil.WriteCert(t.TempDir(), time.Now().Add(-time.Hour), time.Now().Add(time.Hour), smarthostName)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			t.Fatal(err)
		}
		tlsCfg = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		roots = x509.NewCertPool()
		roots.AddCert(leaf)
	}
	sink, err := testutil.StartSink(tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sink.Close)
	f := &fixture{sink: sink, roots: roots, dialTo: map[string]string{}}
	f.client = New(&config.Config{Hostname: "relay.example.com", SmarthostPort: 587})
	f.client.Resolver = dns
	f.client.Dial = func(ctx context.Context, _, addr string) (net.Conn, error) {
		f.dialed = append(f.dialed, addr)
		for _, d := range down {
			if strings.HasPrefix(addr, d+":") {
				return nil, errors.New("connection refused")
			}
		}
		to := sink.Addr
		if host, _, _ := net.SplitHostPort(addr); f.dialTo[host] != "" {
			to = f.dialTo[host]
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", to)
	}
	return f
}

const smarthostName = "smarthost.example.net"

func rcpts(addrs ...string) []store.Recipient {
	out := make([]store.Recipient, len(addrs))
	for i, a := range addrs {
		out[i] = store.Recipient{ID: int64(i + 1), Address: a, Domain: "example.org"}
	}
	return out
}

var (
	testMsg = store.Message{ID: "Q1", EnvelopeFrom: "app@example.com", Body: []byte("Subject: x\r\n\r\nline\r\n.leading dot\r\n")}
	twoMX   = fakeDNS{mx: map[string][]*net.MX{"example.org": {{Host: "mx1.example.org.", Pref: 10}, {Host: "mx2.example.org.", Pref: 20}}}}
)

func TestDeliverOverSTARTTLS(t *testing.T) {
	f := newFixture(t, true, twoMX)
	res := f.client.Deliver(context.Background(), testMsg, "example.org", rcpts("ok@example.org", "bounce@example.org", "defer@example.org"))
	want := []struct {
		status Status
		resp   string
	}{{Delivered, "250 "}, {Bounced, "550 5.1.1 User unknown"}, {Deferred, "451 4.2.0 Try again later"}}
	for i, w := range want {
		if res[i].Status != w.status || !strings.HasPrefix(res[i].Response, w.resp) || !res[i].TLS || res[i].Host != "mx1.example.org" {
			t.Errorf("recipient %d: %+v, want %v %q over TLS via mx1", i, res[i], w.status, w.resp)
		}
	}
	msgs := f.sink.Messages()
	if len(msgs) != 1 {
		t.Fatalf("sink got %d messages, want 1", len(msgs))
	}
	m := msgs[0]
	if m.Helo != "relay.example.com" || m.From != "app@example.com" || len(m.To) != 1 || !m.TLS || string(m.Data) != string(testMsg.Body) {
		t.Errorf("sink message = %+v (%q)", m, m.Data)
	}
	if len(f.dialed) != 1 || f.dialed[0] != "mx1.example.org:25" {
		t.Errorf("dialed %v", f.dialed)
	}
}

func TestDeliverPlaintextWhenTLSNotOffered(t *testing.T) {
	f := newFixture(t, false, twoMX)
	res := f.client.Deliver(context.Background(), testMsg, "example.org", rcpts("ok@example.org"))
	if res[0].Status != Delivered || res[0].TLS {
		t.Errorf("result = %+v, want plaintext delivery", res[0])
	}
}

func TestDeliverFallsBackToNextMX(t *testing.T) {
	f := newFixture(t, true, twoMX, "mx1.example.org")
	res := f.client.Deliver(context.Background(), testMsg, "example.org", rcpts("ok@example.org"))
	if res[0].Status != Delivered || res[0].Host != "mx2.example.org" {
		t.Errorf("result = %+v, want delivery via mx2", res[0])
	}
}

// A 421 at MAIL is the server going away, not a verdict: the next MX gets the message.
func TestDeliverTriesNextMXAfter421(t *testing.T) {
	f := newFixture(t, true, twoMX)
	f.sink.Busy.Store(1) // the first session (mx1) is turned away
	res := f.client.Deliver(context.Background(), testMsg, "example.org", rcpts("ok@example.org"))
	if res[0].Status != Delivered || res[0].Host != "mx2.example.org" {
		t.Errorf("result = %+v, want delivery via mx2", res[0])
	}
	if len(f.sink.Messages()) != 1 {
		t.Errorf("sink got %d messages, want exactly 1", len(f.sink.Messages()))
	}
}

// RFC 5321 4.5.3.1.10: 552 at RCPT means "too many recipients", so retry it later.
func TestRcpt552IsTemporary(t *testing.T) {
	f := newFixture(t, true, twoMX)
	res := f.client.Deliver(context.Background(), testMsg, "example.org", rcpts("ok@example.org", "full@example.org"))
	if res[0].Status != Delivered || res[1].Status != Deferred || !strings.HasPrefix(res[1].Response, "552") {
		t.Errorf("results = %+v", res)
	}
}

func TestCancelledContextAbortsDelivery(t *testing.T) {
	f := newFixture(t, true, twoMX)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := f.client.Deliver(ctx, testMsg, "example.org", rcpts("ok@example.org"))
	if res[0].Status != Deferred || len(f.sink.Messages()) != 0 {
		t.Errorf("result = %+v, messages = %d; a cancelled attempt must defer and send nothing", res[0], len(f.sink.Messages()))
	}
}

func TestDeliverAllHostsDownIsTemporary(t *testing.T) {
	f := newFixture(t, true, twoMX, "mx1.example.org", "mx2.example.org")
	res := f.client.Deliver(context.Background(), testMsg, "example.org", rcpts("ok@example.org"))
	if res[0].Status != Deferred || !strings.Contains(res[0].Response, "connection refused") {
		t.Errorf("result = %+v, want deferred", res[0])
	}
}

func TestDeliverDNS(t *testing.T) {
	for name, tc := range map[string]struct {
		dns    fakeDNS
		status Status
		resp   string
		dial   string
	}{
		"implicit MX":    {dns: fakeDNS{hosts: map[string]bool{"example.org": true}}, status: Delivered, dial: "example.org:25"},
		"no such domain": {dns: fakeDNS{}, status: Bounced, resp: "5.1.2"},
		"null MX":        {dns: fakeDNS{mx: map[string][]*net.MX{"example.org": {{Host: "."}}}}, status: Bounced, resp: "5.1.10"},
		"resolver down":  {dns: fakeDNS{err: errors.New("i/o timeout")}, status: Deferred, resp: "i/o timeout"},
	} {
		f := newFixture(t, true, tc.dns)
		res := f.client.Deliver(context.Background(), testMsg, "example.org", rcpts("ok@example.org"))
		if res[0].Status != tc.status || !strings.Contains(res[0].Response, tc.resp) {
			t.Errorf("%s: %+v, want %v containing %q", name, res[0], tc.status, tc.resp)
		}
		if tc.dial != "" && (len(f.dialed) != 1 || f.dialed[0] != tc.dial) {
			t.Errorf("%s: dialed %v, want %s", name, f.dialed, tc.dial)
		}
	}
}

// Nothing goes to a smarthost without verified TLS: not the credentials, and
// not the mail of a smarthost that needs none.
func TestSmarthostNeedsVerifiedTLS(t *testing.T) {
	for _, user := range []string{"user", ""} {
		for name, sinkTLS := range map[string]bool{"no STARTTLS offered": false, "certificate does not verify": true} {
			if user == "" {
				name += ", no credentials"
			}
			f := newFixture(t, sinkTLS, fakeDNS{})
			f.client.cfg.SmarthostHost = smarthostName
			if user != "" {
				f.client.cfg.SmarthostUsername, f.client.cfg.SmarthostPassword = user, "secret"
			}
			res := f.client.Deliver(context.Background(), testMsg, "example.org", rcpts("ok@example.org"))
			if res[0].Status != Deferred {
				t.Errorf("%s: %+v, want deferred", name, res[0])
			}
			if strings.Contains(res[0].Response, "secret") {
				t.Errorf("%s: response leaks the password: %s", name, res[0].Response)
			}
			if n := len(f.sink.Messages()); n != 0 {
				t.Errorf("%s: %d message(s) sent without verified TLS", name, n)
			}
			if len(f.dialed) != 1 || f.dialed[0] != smarthostName+":587" {
				t.Errorf("%s: dialed %v, want one attempt and no plaintext retry", name, f.dialed)
			}
		}
	}
}

func TestSmarthostWithoutCredentialsSkipsMX(t *testing.T) {
	f := newFixture(t, true, fakeDNS{err: errors.New("DNS must not be used")})
	f.client.cfg.SmarthostHost = smarthostName
	f.client.RootCAs = f.roots
	res := f.client.Deliver(context.Background(), testMsg, "example.org", rcpts("ok@example.org"))
	if res[0].Status != Delivered || !res[0].TLS {
		t.Errorf("result = %+v", res[0])
	}
}

// A connection that dies at MAIL has said nothing about the message.
func TestDeliverTriesNextMXWhenConnectionDropsAtMAIL(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close() //nolint:errcheck // test listener
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close() //nolint:errcheck // test connection
		buf := make([]byte, 512)
		_, _ = c.Write([]byte("220 mx1.example.org ESMTP\r\n"))
		_, _ = c.Read(buf) // EHLO
		_, _ = c.Write([]byte("250 mx1.example.org\r\n"))
		_, _ = c.Read(buf) // MAIL, answered by hanging up
	}()
	f := newFixture(t, true, twoMX)
	f.dialTo["mx1.example.org"] = ln.Addr().String()
	res := f.client.Deliver(context.Background(), testMsg, "example.org", rcpts("ok@example.org"))
	if res[0].Status != Delivered || res[0].Host != "mx2.example.org" {
		t.Errorf("result = %+v, want delivery via mx2", res[0])
	}
}

func TestDirectDeliveryRefusesLocalAddresses(t *testing.T) {
	for addr, refused := range map[string]bool{
		"127.0.0.1:25": true, "[::1]:25": true, "0.0.0.0:25": true, "169.254.10.1:25": true,
		"[fe80::1%lo0]:25": true, "[::ffff:127.0.0.1]:25": true,
		"192.0.2.10:25": false, "10.0.0.5:25": false, "[2001:db8::25]:25": false,
	} {
		if err := refuseLocal("tcp", addr, nil); (err != nil) != refused {
			t.Errorf("refuseLocal(%s) = %v, want refused = %v", addr, err, refused)
		}
	}
	if New(&config.Config{}).Dial == nil {
		t.Fatal("no dialer")
	}
	// The real dialer applies it: a domain whose MX is the relay's own host gets no connection.
	_, err := New(&config.Config{}).Dial(context.Background(), "tcp4", "127.0.0.1:25")
	if err == nil || !strings.Contains(err.Error(), "not connecting") {
		t.Errorf("dial to loopback = %v, want a refusal", err)
	}
}

func TestLoginAuth(t *testing.T) {
	// Servers word the prompts differently, or send none: the answers go by position.
	for _, prompts := range [][2]string{{"Username:", "Password:"}, {"User Name", "Password"}, {"", ""}} {
		a := &loginAuth{username: "user", password: "secret"}
		if proto, first, err := a.Start(nil); proto != "LOGIN" || first != nil || err != nil {
			t.Fatalf("Start = %q, %q, %v", proto, first, err)
		}
		for i, want := range []string{"user", "secret"} {
			if got, err := a.Next([]byte(prompts[i]), true); err != nil || string(got) != want {
				t.Errorf("challenge %d %q: answered %q, %v; want %q", i+1, prompts[i], got, err, want)
			}
		}
		if _, err := a.Next([]byte("Password:"), true); err == nil {
			t.Errorf("%q: a third challenge must not be answered", prompts)
		}
		if got, err := a.Next(nil, false); got != nil || err != nil {
			t.Errorf("Next at the end = %q, %v", got, err)
		}
	}
}

func TestBuildDSN(t *testing.T) {
	orig := store.Message{ID: "QORIG", EnvelopeFrom: "app@example.com", FromDomain: "example.com", CreatedAt: 1767225600,
		Body: []byte("From: app@example.com\r\nSubject: original\r\n\r\nSECRET BODY\r\n")}
	dsn := string(BuildDSN("relay.example.com", orig, []Failure{
		{Address: "gone@example.org", Response: "550 5.1.1 User unknown", Host: "mx1.example.org"},
		{Address: "old@example.org", Response: "4.4.7 message expired after 72h0m0s in the queue; last error: timeout"},
	}, time.Unix(1767312000, 0).UTC()))
	for _, want := range []string{
		"From: Mail Delivery System <postmaster@example.com>\r\n", "To: <app@example.com>\r\n", "Auto-Submitted: auto-replied\r\n",
		"multipart/report; report-type=delivery-status;", "Reporting-MTA: dns; relay.example.com\r\n",
		"Final-Recipient: rfc822; gone@example.org\r\nAction: failed\r\nStatus: 5.1.1\r\nRemote-MTA: dns; mx1.example.org\r\n",
		"Final-Recipient: rfc822; old@example.org\r\nAction: failed\r\nStatus: 4.4.7\r\nDiagnostic-Code:",
		"Content-Type: text/rfc822-headers\r\n\r\nFrom: app@example.com\r\nSubject: original\r\n",
	} {
		if !strings.Contains(dsn, want) {
			t.Errorf("DSN lacks %q:\n%s", want, dsn)
		}
	}
	if strings.Contains(dsn, "SECRET BODY") {
		t.Error("DSN must return headers only, not the body")
	}
	if strings.Contains(strings.ReplaceAll(dsn, "\r\n", ""), "\n") {
		t.Error("DSN contains a bare LF")
	}
}

func TestStatusOfReadsOnlyTheReplyPrefix(t *testing.T) {
	for reply, want := range map[string]string{
		"550 5.1.1 User unknown":                 "5.1.1",
		"550-5.7.1 blocked":                      "5.7.1",
		"4.4.7 message expired":                  "4.4.7",
		"550 unavailable at 192.4.2.1":           "5.0.0", // an IP is not a status code
		"554 rejected, see 5.7.1 in the policy":  "5.0.0",
		"connect to mx.example.org: i/o timeout": "5.0.0",
	} {
		if got := statusOf(reply); got != want {
			t.Errorf("statusOf(%q) = %q, want %q", reply, got, want)
		}
	}
	if got := ascii("550 bo\u00eete pleine\t!"); got != "550 bo?te pleine?!" {
		t.Errorf("ascii = %q", got)
	}
}

func TestOneLineIsRuneSafe(t *testing.T) {
	got := oneLine("550 " + strings.Repeat("é", 400) + "\r\nsecond line")
	if len(got) > 503 || !strings.HasSuffix(got, "...") || strings.ContainsAny(got, "\r\n") || strings.ContainsRune(got, '\uFFFD') {
		t.Errorf("oneLine = %q", got)
	}
}
