package smtpd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"

	"github.com/DevHatRo/outbound-smtp/internal/metrics"
	"github.com/DevHatRo/outbound-smtp/internal/password"
	"github.com/DevHatRo/outbound-smtp/internal/store"
	"github.com/DevHatRo/outbound-smtp/internal/tracing"
)

type backend struct {
	s        *Server
	listener string
}

func smtpErr(code int, enh smtp.EnhancedCode, format string, a ...any) *smtp.SMTPError {
	return &smtp.SMTPError{Code: code, EnhancedCode: enh, Message: fmt.Sprintf(format, a...)}
}

var errTemporary = smtpErr(451, smtp.EnhancedCode{4, 3, 0}, "Temporary server error, try again later")

// NewSession runs on every EHLO, including the one after STARTTLS.
func (b *backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	sess := &session{s: b.s, listener: b.listener, ip: remoteIP(c.Conn().RemoteAddr())}
	if _, sess.tls = c.TLSConnectionState(); sess.tls {
		markTLS(c.Conn())
	}
	nets, err := b.s.st.ListNetworks()
	if err != nil {
		b.s.log.Error("load trusted networks", zap.Error(err))
		return nil, errTemporary
	}
	if n := matchNetwork(nets, sess.ip); n != nil {
		sess.who = &principal{source: store.SourceNetwork, ident: n.CIDR, patterns: n.DomainNames(), rate: n.RatePerHour}
	}
	return sess, nil
}

// session is one SMTP session. who stays nil until the client is known to be
// in a trusted network or has authenticated; nothing is relayed before that.
type session struct {
	s        *Server
	listener string
	ip       netip.Addr
	tls      bool
	who      *principal
	from     string
	rcpts    []string
}

func (s *session) Reset()        { s.from, s.rcpts = "", nil }
func (s *session) Logout() error { return nil }

// ---- AUTH ----

// AuthMechanisms offers AUTH only on TLS and never on port 25.
func (s *session) AuthMechanisms() []string {
	if !s.tls || s.listener == Listener25 {
		return nil
	}
	return []string{sasl.Plain, sasl.Login}
}

func (s *session) Auth(mech string) (sasl.Server, error) {
	if !s.tls || s.listener == Listener25 { // defence in depth: go-smtp already refuses
		return nil, smtpErr(538, smtp.EnhancedCode{5, 7, 11}, "Encryption required for authentication")
	}
	switch mech {
	case sasl.Plain:
		return sasl.NewPlainServer(func(identity, username, pw string) error {
			if identity != "" && identity != username {
				return smtp.ErrAuthFailed
			}
			return s.authenticate(username, pw)
		}), nil
	case sasl.Login:
		return &loginServer{auth: s.authenticate}, nil
	}
	return nil, smtpErr(504, smtp.EnhancedCode{5, 5, 4}, "Unsupported authentication mechanism")
}

// loginServer implements the server side of AUTH LOGIN, which go-sasl omits.
type loginServer struct {
	step     int
	username string
	auth     func(username, pw string) error
}

func (l *loginServer) Next(response []byte) (challenge []byte, done bool, err error) {
	if l.step == 0 {
		l.step = 1
		if response == nil { // no initial response: ask for the username
			return []byte("Username:"), false, nil
		}
	}
	if l.step == 1 {
		l.step, l.username = 2, string(response)
		return []byte("Password:"), false, nil
	}
	return nil, true, l.auth(l.username, string(response))
}

func (s *session) authenticate(username, pw string) error {
	srv := s.s
	key, limit := s.ip.String(), srv.cfg.AuthFailureLimit
	if srv.authFail.exhausted(key, limit) {
		srv.m.AuthAttempts.WithLabelValues("blocked").Inc()
		srv.log.Info("authentication blocked", zap.String("reason", "too many failures"), zap.Stringer("client_ip", s.ip))
		return smtpErr(454, smtp.EnhancedCode{4, 7, 0}, "Too many failed authentication attempts, try again later")
	}
	u, err := srv.st.GetUser(username)
	hash := u.PasswordHash
	if errors.Is(err, store.ErrNotFound) {
		hash = srv.dummyHash // same work as for a real user
	} else if err != nil {
		srv.log.Error("load user", zap.Error(err))
		return errTemporary
	}
	srv.hashSem <- struct{}{}
	ok, verr := password.Verify(hash, pw)
	<-srv.hashSem
	if err != nil || verr != nil || !ok {
		srv.authFail.allow(key, limit) // spend one failure token
		srv.m.AuthAttempts.WithLabelValues("failure").Inc()
		srv.log.Info("authentication failed", zap.String("username", username), zap.Stringer("client_ip", s.ip),
			zap.String("listener", s.listener))
		return smtp.ErrAuthFailed
	}
	srv.m.AuthAttempts.WithLabelValues("success").Inc()
	s.who = &principal{source: store.SourceAuth, ident: u.Username, patterns: u.SenderPatterns(), rate: u.RatePerHour}
	return nil
}

// ---- MAIL / RCPT / DATA ----

// reject counts, logs and traces a refusal, and returns the SMTP error.
func (s *session) reject(reason string, e *smtp.SMTPError) error {
	s.s.m.Rejected.WithLabelValues(reason).Inc()
	_, span := tracing.Tracer().Start(context.Background(), "smtp.reject", trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(attribute.String("smtprelay.reason", reason), attribute.String("smtprelay.listener", s.listener),
			attribute.String("smtprelay.sender", s.from), attribute.Int("smtp.response.code", e.Code)))
	span.SetStatus(codes.Error, e.Message)
	span.End()
	fields := []zap.Field{zap.String("reason", reason), zap.String("listener", s.listener), zap.Stringer("client_ip", s.ip),
		zap.String("sender", s.from), zap.Int("code", e.Code), zap.String("response", e.Message)}
	if s.who != nil {
		fields = append(fields, zap.String("source", s.who.source), zap.String("client", s.who.ident))
	}
	s.s.log.Info("message rejected", fields...)
	return e
}

// checkSender applies the sender rules to one address (envelope sender or
// From header): its domain must be configured, exactly, and the principal
// must be allowed to use it.
func (s *session) checkSender(what, addr string) error {
	_, domain, err := store.SplitAddress(addr)
	if err != nil {
		return s.reject(metrics.ReasonSenderNotAllowed, smtpErr(553, smtp.EnhancedCode{5, 1, 7}, "%s address is not valid", what))
	}
	ok, err := s.s.st.DomainExists(domain)
	if err != nil {
		s.s.log.Error("look up domain", zap.Error(err))
		return errTemporary
	}
	if !ok {
		return s.reject(metrics.ReasonSenderNotAllowed, smtpErr(550, smtp.EnhancedCode{5, 7, 1},
			"%s rejected: %s is not a domain this relay sends for", what, domain))
	}
	if !senderAllowed(s.who.patterns, addr) {
		return s.reject(metrics.ReasonSenderNotAllowed, smtpErr(550, smtp.EnhancedCode{5, 7, 1},
			"%s rejected: you are not allowed to send as %s", what, addr))
	}
	return nil
}

func (s *session) Mail(from string, _ *smtp.MailOptions) error {
	s.from = from
	if s.listener == Listener587 && !s.tls {
		return s.reject(metrics.ReasonRelayDenied, smtpErr(530, smtp.EnhancedCode{5, 7, 0}, "Must issue a STARTTLS command first"))
	}
	if s.who == nil {
		if s.listener == Listener25 {
			return s.reject(metrics.ReasonRelayDenied, smtpErr(550, smtp.EnhancedCode{5, 7, 1}, "Relay access denied"))
		}
		return s.reject(metrics.ReasonRelayDenied, smtpErr(530, smtp.EnhancedCode{5, 7, 0}, "Authentication required"))
	}
	if from == "" {
		return s.reject(metrics.ReasonSenderNotAllowed, smtpErr(550, smtp.EnhancedCode{5, 7, 1}, "Null sender is not accepted from clients"))
	}
	if err := s.checkSender("Sender", from); err != nil {
		return err
	}
	limit := s.s.cfg.RateLimitUserPerHour
	if s.who.source == store.SourceNetwork {
		limit = s.s.cfg.RateLimitNetworkPerHour
	}
	if s.who.rate != nil {
		limit = *s.who.rate
	}
	if !s.s.msgRate.allow(s.who.source+":"+s.who.ident, limit) {
		return s.reject(metrics.ReasonRateLimit, smtpErr(451, smtp.EnhancedCode{4, 7, 1}, "Message rate limit exceeded, try again later"))
	}
	return nil
}

func (s *session) Rcpt(to string, _ *smtp.RcptOptions) error {
	if s.who == nil || s.from == "" { // go-smtp enforces the order; never rely on it for relay control
		return s.reject(metrics.ReasonRelayDenied, smtpErr(503, smtp.EnhancedCode{5, 5, 1}, "MAIL first"))
	}
	if _, _, err := store.SplitAddress(to); err != nil {
		return smtpErr(501, smtp.EnhancedCode{5, 1, 3}, "Bad recipient address syntax")
	}
	s.rcpts = append(s.rcpts, to)
	return nil
}

func (s *session) with() string {
	w := "ESMTP"
	if s.tls {
		w += "S"
	}
	if s.who != nil && s.who.source == store.SourceAuth {
		w += "A"
	}
	return w
}

func (s *session) Data(r io.Reader) error {
	srv := s.s
	if s.who == nil || s.from == "" || len(s.rcpts) == 0 {
		return s.reject(metrics.ReasonRelayDenied, smtpErr(503, smtp.EnhancedCode{5, 5, 1}, "MAIL and RCPT first"))
	}
	queueID := store.NewID()
	ctx, span := tracing.Tracer().Start(context.Background(), "smtp.receive", trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(
			attribute.String("smtprelay.queue_id", queueID),
			attribute.String("smtprelay.listener", s.listener),
			attribute.String("smtprelay.source", s.who.source),
			attribute.String("smtprelay.client", s.who.ident),
			attribute.String("smtprelay.sender", s.from),
			attribute.Int("smtprelay.recipients", len(s.rcpts)),
		))
	defer span.End()
	fail := func(err error) error {
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	raw, err := io.ReadAll(r)
	if err != nil {
		if errors.Is(err, smtp.ErrDataTooLarge) {
			return fail(s.reject(metrics.ReasonSize, smtp.ErrDataTooLarge))
		}
		return fail(err)
	}
	msg, fromAddr, fromDomain, err := prepare(raw, queueID, srv.cfg.Hostname, s.with(), time.Now())
	if err != nil {
		text := strings.TrimPrefix(err.Error(), errBadMessage.Error()+": ")
		return fail(s.reject(metrics.ReasonInvalid, smtpErr(554, smtp.EnhancedCode{5, 6, 0}, "Message rejected: %s", text)))
	}
	if err := s.checkSender("From header", fromAddr); err != nil {
		return fail(err)
	}
	span.SetAttributes(attribute.String("smtprelay.from_domain", fromDomain), attribute.Int("smtprelay.size", len(msg)))

	_, signSpan := tracing.Tracer().Start(ctx, "dkim.sign", trace.WithAttributes(attribute.String("smtprelay.from_domain", fromDomain)))
	signed, err := srv.signer.Sign(fromDomain, msg)
	if err != nil {
		signSpan.SetStatus(codes.Error, err.Error())
		signSpan.End()
		srv.m.DKIMSign.WithLabelValues(fromDomain, "error").Inc()
		srv.log.Error("DKIM signing failed, message not accepted", zap.String("queue_id", queueID),
			zap.String("from_domain", fromDomain), zap.Error(err))
		return fail(smtpErr(451, smtp.EnhancedCode{4, 7, 5}, "Cannot DKIM-sign for %s, message not accepted", fromDomain))
	}
	signSpan.End()
	srv.m.DKIMSign.WithLabelValues(fromDomain, "ok").Inc()

	// The client gets 250 only after this transaction is committed.
	err = srv.st.Enqueue(store.Message{
		ID: queueID, EnvelopeFrom: s.from, FromDomain: fromDomain, Source: s.who.source, SourceIdent: s.who.ident,
		Body: signed, Traceparent: tracing.Inject(ctx),
	}, s.rcpts)
	if err != nil {
		srv.log.Error("enqueue failed, message not accepted", zap.String("queue_id", queueID), zap.Error(err))
		return fail(errTemporary)
	}
	srv.m.Accepted.WithLabelValues(s.who.source, fromDomain).Inc()
	srv.log.Info("message accepted",
		zap.String("queue_id", queueID), zap.String("sender", s.from), zap.String("from_domain", fromDomain),
		zap.String("source", s.who.source), zap.String("client", s.who.ident), zap.String("listener", s.listener),
		zap.Stringer("client_ip", s.ip), zap.Bool("tls", s.tls), zap.Int("recipients", len(s.rcpts)),
		zap.Strings("recipient_domains", recipientDomains(s.rcpts)), zap.Int("size", len(signed)),
		zap.String("trace_id", tracing.TraceID(ctx)))
	srv.wake()
	return nil
}

func recipientDomains(rcpts []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range rcpts {
		if _, d, err := store.SplitAddress(r); err == nil && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	sort.Strings(out)
	return out
}
