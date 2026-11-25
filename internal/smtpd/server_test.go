package smtpd

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/zap"

	"github.com/DevHatRo/outbound-smtp/internal/config"
	"github.com/DevHatRo/outbound-smtp/internal/metrics"
	"github.com/DevHatRo/outbound-smtp/internal/password"
	"github.com/DevHatRo/outbound-smtp/internal/store"
	certs "github.com/DevHatRo/outbound-smtp/internal/testutil"
)

const (
	goodPassword = "a-long-enough-password"
	goodMessage  = "From: App <app@example.com>\r\nTo: rcpt@example.org\r\nBcc: hidden@example.org\r\nSubject: hi\r\n\r\nbody\r\n"
)

// fakeSigner marks the message instead of signing it; real DKIM is tested in internal/dkim.
type fakeSigner struct{ fail bool }

func (f fakeSigner) Sign(domain string, msg []byte) ([]byte, error) {
	if f.fail {
		return nil, errors.New("no key")
	}
	return append([]byte("X-Signed-For: "+domain+"\r\n"), msg...), nil
}

type env struct {
	t   *testing.T
	srv *Server
	st  *store.Store
	m   *metrics.Metrics
}

// start runs a server on loopback with example.com configured and a user
// "app". No trusted networks exist unless the test adds one.
func start(t *testing.T, tweak func(*config.Config)) *env {
	t.Helper()
	dir := t.TempDir()
	certFile, keyFile, err := certs.WriteSelfSignedCert(dir, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Hostname: "relay.example.com", EnablePort25: true, Port25StartTLS: true,
		Listen465: "127.0.0.1:0", Listen587: "127.0.0.1:0", Listen25: "127.0.0.1:0",
		TLSCertFile: certFile, TLSKeyFile: keyFile,
		MaxMessageSize: 1 << 20, MaxRecipients: 10, MaxConnections: 100, MaxConnectionsPerIP: 50,
		RateLimitUserPerHour: 1000, RateLimitNetworkPerHour: 1000, AuthFailureLimit: 3,
	}
	if tweak != nil {
		tweak(cfg)
	}
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := password.Hash(goodPassword)
	if err != nil {
		t.Fatal(err)
	}
	for _, err := range []error{
		st.AddDomain("example.com"),
		st.AddDomain("example.net"),
		st.AddUser("app", hash, nil, nil),
		st.AddUser("narrow", hash, nil, []string{"only@example.com"}),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	m := metrics.New("test")
	srv, err := New(cfg, st, fakeSigner{}, zap.NewNop(), m, func() {})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx) // lingering test clients are fine
		if err := st.Close(); err != nil {
			t.Error(err)
		}
	})
	return &env{t: t, srv: srv, st: st, m: m}
}

var insecure = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // self-signed test certificate

// dial connects to a listener; with startTLS it upgrades (587 and 25).
func (e *env) dial(listener string, startTLS bool) *smtp.Client {
	e.t.Helper()
	addr := e.srv.Addr(listener).String()
	var c *smtp.Client
	var err error
	switch {
	case listener == Listener465:
		c, err = smtp.DialTLS(addr, insecure)
	case startTLS:
		c, err = smtp.DialStartTLS(addr, insecure)
	default:
		c, err = smtp.Dial(addr)
	}
	if err != nil {
		e.t.Fatalf("dial %s: %v", listener, err)
	}
	e.t.Cleanup(func() { _ = c.Close() })
	return c
}

func (e *env) trustLoopback(domains ...string) {
	e.t.Helper()
	if err := e.st.AddNetwork(netip.MustParsePrefix("127.0.0.0/8"), nil, domains); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) queued() []store.Recipient {
	e.t.Helper()
	r, err := e.st.ListRecipients("")
	if err != nil {
		e.t.Fatal(err)
	}
	return r
}

// wantCode asserts err is an SMTP error with the given code.
func wantCode(t *testing.T, what string, err error, code int) {
	t.Helper()
	var se *smtp.SMTPError
	if !errors.As(err, &se) || se.Code != code {
		t.Fatalf("%s: got %v, want SMTP %d", what, err, code)
	}
}

func send(c *smtp.Client, from, to, msg string) error {
	return c.SendMail(from, []string{to}, strings.NewReader(msg))
}

// TestNeverAnOpenRelay tries every way of sending without being entitled to.
// After each attempt the queue must still be empty.
func TestNeverAnOpenRelay(t *testing.T) {
	e := start(t, nil)
	auth := func(c *smtp.Client, user string) {
		t.Helper()
		if err := c.Auth(sasl.NewPlainClient("", user, goodPassword)); err != nil {
			t.Fatalf("auth %s: %v", user, err)
		}
	}

	t.Run("587 without STARTTLS", func(t *testing.T) {
		c := e.dial(Listener587, false)
		wantCode(t, "MAIL", c.Mail("app@example.com", nil), 530)
		if c.SupportsAuth(sasl.Plain) {
			t.Error("AUTH must not be offered before STARTTLS")
		}
		if err := c.Auth(sasl.NewPlainClient("", "app", goodPassword)); err == nil {
			t.Error("AUTH over plaintext must fail")
		}
		wantCode(t, "MAIL after plaintext AUTH", c.Mail("app@example.com", nil), 530)
	})
	t.Run("587 with TLS but no auth", func(t *testing.T) {
		wantCode(t, "send", send(e.dial(Listener587, true), "app@example.com", "rcpt@example.org", goodMessage), 530)
	})
	t.Run("465 without auth", func(t *testing.T) {
		wantCode(t, "send", send(e.dial(Listener465, false), "app@example.com", "rcpt@example.org", goodMessage), 530)
	})
	t.Run("25 from an untrusted address", func(t *testing.T) {
		wantCode(t, "send", send(e.dial(Listener25, false), "app@example.com", "rcpt@example.org", goodMessage), 550)
	})
	t.Run("25 never offers AUTH, even with TLS", func(t *testing.T) {
		c := e.dial(Listener25, true)
		if c.SupportsAuth(sasl.Plain) || c.SupportsAuth(sasl.Login) {
			t.Error("AUTH offered on port 25")
		}
		if err := c.Auth(sasl.NewPlainClient("", "app", goodPassword)); err == nil {
			t.Error("AUTH on port 25 must fail")
		}
		wantCode(t, "send", send(c, "app@example.com", "rcpt@example.org", goodMessage), 550)
	})
	t.Run("wrong password and unknown user", func(t *testing.T) {
		c := e.dial(Listener465, false)
		wantCode(t, "wrong password", c.Auth(sasl.NewPlainClient("", "app", "wrong-password-here")), 535)
		wantCode(t, "unknown user", c.Auth(sasl.NewPlainClient("", "ghost", goodPassword)), 535)
		wantCode(t, "MAIL after failed AUTH", c.Mail("app@example.com", nil), 530)
	})
	t.Run("authorization identity of another user", func(t *testing.T) {
		c := e.dial(Listener465, false)
		wantCode(t, "auth", c.Auth(sasl.NewPlainClient("narrow", "app", goodPassword)), 535)
	})
	t.Run("envelope sender in a foreign domain", func(t *testing.T) {
		c := e.dial(Listener465, false)
		auth(c, "app")
		wantCode(t, "MAIL", c.Mail("someone@example.org", nil), 550)
	})
	t.Run("subdomain of a configured domain", func(t *testing.T) {
		c := e.dial(Listener465, false)
		auth(c, "app")
		wantCode(t, "MAIL", c.Mail("app@mail.example.com", nil), 550)
	})
	t.Run("null sender", func(t *testing.T) {
		c := e.dial(Listener465, false)
		auth(c, "app")
		wantCode(t, "MAIL", c.Mail("", nil), 550)
	})
	t.Run("From header in a foreign domain", func(t *testing.T) {
		c := e.dial(Listener465, false)
		auth(c, "app")
		msg := "From: ceo@example.org\r\nSubject: spoof\r\n\r\nbody\r\n"
		wantCode(t, "DATA", send(c, "app@example.com", "rcpt@example.org", msg), 550)
	})
	t.Run("missing, repeated or multi-address From", func(t *testing.T) {
		for _, msg := range []string{
			"Subject: none\r\n\r\nbody\r\n",
			"From: app@example.com\r\nFrom: app@example.com\r\n\r\nbody\r\n",
			"From: app@example.com, other@example.com\r\n\r\nbody\r\n",
		} {
			c := e.dial(Listener465, false)
			auth(c, "app")
			wantCode(t, "DATA", send(c, "app@example.com", "rcpt@example.org", msg), 554)
		}
	})
	t.Run("restricted user sending as another address", func(t *testing.T) {
		c := e.dial(Listener465, false)
		auth(c, "narrow")
		wantCode(t, "MAIL", c.Mail("app@example.com", nil), 550)
		msg := "From: app@example.com\r\n\r\nbody\r\n"
		wantCode(t, "DATA", send(c, "only@example.com", "rcpt@example.org", msg), 550)
	})

	t.Run("user removed while the session is open", func(t *testing.T) {
		hash, err := password.Hash(goodPassword)
		if err != nil {
			t.Fatal(err)
		}
		if err := e.st.AddUser("leaver", hash, nil, nil); err != nil {
			t.Fatal(err)
		}
		c := e.dial(Listener465, false)
		auth(c, "leaver")
		if err := e.st.RemoveUser("leaver"); err != nil {
			t.Fatal(err)
		}
		wantCode(t, "MAIL", c.Mail("app@example.com", nil), 530)
	})
	t.Run("user restricted while the session is open", func(t *testing.T) {
		hash, err := password.Hash(goodPassword)
		if err != nil {
			t.Fatal(err)
		}
		if err := e.st.AddUser("mover", hash, nil, nil); err != nil {
			t.Fatal(err)
		}
		c := e.dial(Listener465, false)
		auth(c, "mover")
		if err := errors.Join(e.st.RemoveUser("mover"), e.st.AddUser("mover", hash, nil, []string{"only@example.com"})); err != nil {
			t.Fatal(err)
		}
		wantCode(t, "MAIL", c.Mail("app@example.com", nil), 550)
	})

	loopback := netip.MustParsePrefix("127.0.0.0/8")
	t.Run("network removed while the session is open", func(t *testing.T) {
		e.trustLoopback()
		c := e.dial(Listener25, false)
		if err := e.st.RemoveNetwork(loopback); err != nil {
			t.Fatal(err)
		}
		wantCode(t, "MAIL", c.Mail("app@example.com", nil), 550)
	})
	t.Run("network restricted while the session is open", func(t *testing.T) {
		e.trustLoopback()
		c := e.dial(Listener25, false)
		if err := e.st.RemoveNetwork(loopback); err != nil {
			t.Fatal(err)
		}
		e.trustLoopback("example.net")
		defer e.st.RemoveNetwork(loopback) //nolint:errcheck // the later subtests must not find it
		wantCode(t, "MAIL", c.Mail("app@example.com", nil), 550)
	})
	t.Run("network restored while the session is open", func(t *testing.T) {
		// Trust comes and goes with the network, in both directions; what
		// the session may send as is still the network's restriction.
		c := e.dial(Listener25, false)
		wantCode(t, "MAIL before trust", c.Mail("app@example.net", nil), 550)
		e.trustLoopback("example.net")
		defer e.st.RemoveNetwork(loopback) //nolint:errcheck // must not outlive the subtest
		wantCode(t, "MAIL as another domain", c.Mail("app@example.com", nil), 550)
		if err := c.Mail("app@example.net", nil); err != nil {
			t.Fatalf("MAIL after the network was trusted: %v", err)
		}
		if err := c.Reset(); err != nil {
			t.Fatal(err)
		}
		if err := e.st.RemoveNetwork(loopback); err != nil {
			t.Fatal(err)
		}
		wantCode(t, "MAIL after removal", c.Mail("app@example.net", nil), 550)
	})
	t.Run("removed user keeps only what the network allows", func(t *testing.T) {
		hash, err := password.Hash(goodPassword)
		if err != nil {
			t.Fatal(err)
		}
		if err := e.st.AddUser("guest", hash, nil, nil); err != nil {
			t.Fatal(err)
		}
		c := e.dial(Listener465, false)
		auth(c, "guest")
		e.trustLoopback("example.net")
		defer e.st.RemoveNetwork(loopback) //nolint:errcheck // must not outlive the subtest
		if err := e.st.RemoveUser("guest"); err != nil {
			t.Fatal(err)
		}
		wantCode(t, "MAIL", c.Mail("app@example.com", nil), 550)
	})

	if q := e.queued(); len(q) != 0 {
		t.Fatalf("open relay: %d recipient(s) were queued: %+v", len(q), q)
	}
	if n := testutil.ToFloat64(e.m.Rejected.WithLabelValues(metrics.ReasonRelayDenied)); n < 5 {
		t.Errorf("relay_denied rejections = %v, want at least 5", n)
	}
}

func TestAuthenticatedSubmission(t *testing.T) {
	e := start(t, nil)
	for _, tc := range []struct {
		listener string
		client   sasl.Client
	}{
		{Listener465, sasl.NewPlainClient("", "app", goodPassword)},
		{Listener587, sasl.NewLoginClient("app", goodPassword)},
	} {
		c := e.dial(tc.listener, true)
		if err := c.Auth(tc.client); err != nil {
			t.Fatalf("%s auth: %v", tc.listener, err)
		}
		if err := send(c, "app@example.com", "rcpt@example.org", goodMessage); err != nil {
			t.Fatalf("%s send: %v", tc.listener, err)
		}
		if err := c.Quit(); err != nil {
			t.Fatal(err)
		}
	}
	q := e.queued()
	if len(q) != 2 {
		t.Fatalf("queued = %d, want 2", len(q))
	}
	m, err := e.st.GetMessage(q[0].MessageID)
	if err != nil {
		t.Fatal(err)
	}
	body := string(m.Body)
	if m.Source != store.SourceAuth || m.SourceIdent != "app" || m.FromDomain != "example.com" || q[0].Domain != "example.org" {
		t.Errorf("message = %+v, recipient = %+v", m, q[0])
	}
	for _, want := range []string{"X-Signed-For: example.com\r\n", "Received: by relay.example.com (DevHatRO SMTP) with ESMTPSA id " + m.ID,
		"\r\nDate: ", "\r\nMessage-ID: <" + strings.ToLower(m.ID) + "@relay.example.com>\r\n", "\r\n\r\nbody\r\n"} {
		if !strings.Contains(body, want) {
			t.Errorf("stored message lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "Bcc") || strings.Contains(body, "127.0.0.1") {
		t.Errorf("stored message leaks Bcc or the client address:\n%s", body)
	}
	if n := testutil.ToFloat64(e.m.Accepted.WithLabelValues("auth", "example.com")); n != 2 {
		t.Errorf("accepted metric = %v, want 2", n)
	}
	// Connections are counted when they close, which is just after QUIT.
	deadline := time.Now().Add(2 * time.Second)
	for testutil.ToFloat64(e.m.Connections.WithLabelValues(Listener587, "true")) != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := testutil.ToFloat64(e.m.Connections.WithLabelValues(Listener587, "true")); n != 1 {
		t.Errorf("connections_total{587,tls=true} = %v, want 1", n)
	}
}

func TestTrustedNetwork(t *testing.T) {
	e := start(t, nil)
	e.trustLoopback("example.com") // restricted to one domain

	// Port 25 in plaintext, no AUTH.
	if err := send(e.dial(Listener25, false), "app@example.com", "rcpt@example.org", goodMessage); err != nil {
		t.Fatalf("trusted send: %v", err)
	}
	// Trust skips AUTH on 587, not TLS.
	wantCode(t, "587 plaintext", send(e.dial(Listener587, false), "app@example.com", "rcpt@example.org", goodMessage), 530)
	if err := send(e.dial(Listener587, true), "app@example.com", "rcpt@example.org", goodMessage); err != nil {
		t.Fatalf("trusted send on 587 with TLS: %v", err)
	}
	// A configured domain outside the network's allow-list.
	wantCode(t, "other domain", e.dial(Listener25, false).Mail("app@example.net", nil), 550)
	wantCode(t, "foreign domain", e.dial(Listener25, false).Mail("app@example.org", nil), 550)

	q := e.queued()
	if len(q) != 2 {
		t.Fatalf("queued = %d, want 2", len(q))
	}
	m, _ := e.st.GetMessage(q[0].MessageID)
	if m.Source != store.SourceNetwork || m.SourceIdent != "127.0.0.0/8" || !strings.Contains(string(m.Body), " with ESMTP id ") {
		t.Errorf("message = %+v", m)
	}
}

func TestPort25WithoutSTARTTLS(t *testing.T) {
	e := start(t, func(c *config.Config) { c.Port25StartTLS = false })
	c := e.dial(Listener25, false)
	if ok, _ := c.Extension("STARTTLS"); ok {
		t.Error("STARTTLS advertised on port 25 although it is switched off")
	}
	if c.SupportsAuth(sasl.Plain) {
		t.Error("AUTH offered on port 25")
	}
	// Still no open relay, and still usable by a trusted network.
	wantCode(t, "untrusted", send(c, "app@example.com", "rcpt@example.org", goodMessage), 550)
	e.trustLoopback()
	if err := send(e.dial(Listener25, false), "app@example.com", "rcpt@example.org", goodMessage); err != nil {
		t.Fatalf("trusted plaintext send: %v", err)
	}
	// The switch must not weaken 587: STARTTLS is still offered and required there.
	sub := e.dial(Listener587, false)
	if ok, _ := sub.Extension("STARTTLS"); !ok {
		t.Error("587 must keep offering STARTTLS")
	}
	wantCode(t, "587 plaintext", sub.Mail("app@example.com", nil), 530)
}

func TestLimits(t *testing.T) {
	e := start(t, func(c *config.Config) {
		c.MaxMessageSize = 2000
		c.RateLimitUserPerHour = 2
		c.MaxConnectionsPerIP = 3
	})

	t.Run("auth failures block the address", func(t *testing.T) {
		c := e.dial(Listener465, false)
		for range 3 {
			wantCode(t, "bad auth", c.Auth(sasl.NewPlainClient("", "app", "wrong-password-here")), 535)
		}
		wantCode(t, "blocked", c.Auth(sasl.NewPlainClient("", "app", goodPassword)), 454)
		if n := testutil.ToFloat64(e.m.AuthAttempts.WithLabelValues("blocked")); n != 1 {
			t.Errorf("blocked metric = %v", n)
		}
		e.srv.authFail = newAuthLimiter(10 * time.Minute) // lift the block for the next subtests
		_ = c.Close()
	})
	t.Run("message size", func(t *testing.T) {
		c := e.dial(Listener465, false)
		if err := c.Auth(sasl.NewPlainClient("", "app", goodPassword)); err != nil {
			t.Fatal(err)
		}
		big := goodMessage + strings.Repeat("0123456789\r\n", 400)
		wantCode(t, "oversized", send(c, "app@example.com", "rcpt@example.org", big), 552)
		_ = c.Close()
	})
	t.Run("recipient rate", func(t *testing.T) {
		c := e.dial(Listener465, false)
		if err := c.Auth(sasl.NewPlainClient("", "app", goodPassword)); err != nil {
			t.Fatal(err)
		}
		// The limit counts recipients. The oversized attempt above already
		// used one of the two tokens, so one message with two recipients
		// gets only the first through.
		if err := c.Mail("app@example.com", nil); err != nil {
			t.Fatal(err)
		}
		if err := c.Rcpt("one@example.org", nil); err != nil {
			t.Fatal(err)
		}
		wantCode(t, "over the rate", c.Rcpt("two@example.org", nil), 451)
		if n := testutil.ToFloat64(e.m.Rejected.WithLabelValues(metrics.ReasonRateLimit)); n != 1 {
			t.Errorf("rate_limit rejections = %v, want 1", n)
		}
		_ = c.Close()
	})
	t.Run("connections per address", func(t *testing.T) {
		time.Sleep(100 * time.Millisecond) // let the closes above be counted
		addr := e.srv.Addr(Listener587).String()
		var open []net.Conn
		defer func() {
			for _, c := range open {
				_ = c.Close()
			}
		}()
		for range 3 {
			c, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			open = append(open, c)
			buf := make([]byte, 4)
			_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
			if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "220 " {
				t.Fatalf("greeting = %q, %v", buf, err)
			}
		}
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		open = append(open, c)
		buf := make([]byte, 4)
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "421 " {
			t.Fatalf("fourth connection got %q, %v; want 421", buf, err)
		}
	})
}

func TestSigningFailureIsTemporaryAndQueuesNothing(t *testing.T) {
	e := start(t, nil)
	e.srv.signer = fakeSigner{fail: true}
	c := e.dial(Listener465, false)
	if err := c.Auth(sasl.NewPlainClient("", "app", goodPassword)); err != nil {
		t.Fatal(err)
	}
	wantCode(t, "unsigned", send(c, "app@example.com", "rcpt@example.org", goodMessage), 451)
	if len(e.queued()) != 0 {
		t.Fatal("an unsigned message was queued")
	}
}

func TestStartFailsWithoutValidCertificate(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	cfg := &config.Config{TLSCertFile: dir + "/missing.crt", TLSKeyFile: dir + "/missing.key"}
	if _, err := New(cfg, st, fakeSigner{}, zap.NewNop(), metrics.New("test"), func() {}); err == nil {
		t.Error("missing certificate must fail")
	}
	cfg.TLSCertFile, cfg.TLSKeyFile, err = certs.WriteSelfSignedCert(dir, time.Now().Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(cfg, st, fakeSigner{}, zap.NewNop(), metrics.New("test"), func() {}); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("expired certificate: got %v", err)
	}
}

// If one port cannot be bound, no listener may be left accepting mail.
func TestStartFailureLeavesNothingListening(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	freeAddr := free.Addr().String()
	_ = free.Close()

	dir := t.TempDir()
	certFile, keyFile, err := certs.WriteSelfSignedCert(dir, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	cfg := &config.Config{Hostname: "relay.example.com", Listen465: freeAddr, Listen587: taken.Addr().String(),
		TLSCertFile: certFile, TLSKeyFile: keyFile, MaxConnections: 100, MaxConnectionsPerIP: 5}
	srv, err := New(cfg, st, fakeSigner{}, zap.NewNop(), metrics.New("test"), func() {})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err == nil {
		t.Fatal("Start must fail when a port is already in use")
	}
	time.Sleep(50 * time.Millisecond)
	if c, err := net.DialTimeout("tcp", freeAddr, time.Second); err == nil {
		_ = c.Close()
		t.Error("the 465 listener kept accepting after Start failed")
	}
}

// A certificate that is not valid yet must not replace the one in use.
func TestFutureCertificateIsNotLoaded(t *testing.T) {
	e := start(t, nil)
	before := e.srv.certs.cert
	dir := t.TempDir()
	certFile, keyFile, err := certs.WriteCert(dir, time.Now().Add(time.Hour), time.Now().Add(48*time.Hour), "localhost")
	if err != nil {
		t.Fatal(err)
	}
	for src, dst := range map[string]string{certFile: e.srv.cfg.TLSCertFile, keyFile: e.srv.cfg.TLSKeyFile} {
		data, _ := os.ReadFile(src)
		if err := os.WriteFile(dst, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.srv.ReloadCert(); err == nil || !strings.Contains(err.Error(), "not valid before") {
		t.Errorf("reload = %v, want a not-yet-valid error", err)
	}
	if e.srv.certs.cert != before {
		t.Error("the certificate in use was replaced by one that is not valid yet")
	}
}

func TestCertificateReload(t *testing.T) {
	e := start(t, nil)
	serial := func() string {
		conn, err := tls.Dial("tcp", e.srv.Addr(Listener465).String(), insecure)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		return conn.ConnectionState().PeerCertificates[0].SerialNumber.String()
	}
	before := serial()
	dir := t.TempDir()
	certFile, keyFile, err := certs.WriteSelfSignedCert(dir, time.Now().Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for src, dst := range map[string]string{certFile: e.srv.cfg.TLSCertFile, keyFile: e.srv.cfg.TLSKeyFile} {
		data, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.srv.certs.watch(ctx, 20*time.Millisecond) // file-change path; SIGHUP calls the same load()
	deadline := time.Now().Add(3 * time.Second)
	for serial() == before {
		if time.Now().After(deadline) {
			t.Fatal("certificate was not reloaded after the files changed")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if exp := testutil.ToFloat64(e.m.CertExpiry); exp < float64(time.Now().Add(47*time.Hour).Unix()) {
		t.Errorf("cert expiry metric not updated: %v", exp)
	}
}

func TestPrepare(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	raw := "From: a@example.com\nSubject: folded\n continuation\nBCC: x@example.org,\r\n\ty@example.org\r\nDate: Thu, 01 Jan 2026 00:00:00 +0000\r\nMessage-ID: <keep@example.com>\r\n\r\nline1\r\nBcc: not a header\r\n"
	out, addr, domain, err := prepare([]byte(raw), "QID", "relay.example.com", "ESMTPS", now)
	if err != nil {
		t.Fatal(err)
	}
	want := "Received: by relay.example.com (DevHatRO SMTP) with ESMTPS id QID;\r\n\tFri, 02 Jan 2026 03:04:05 +0000\r\n" +
		"From: a@example.com\r\nSubject: folded\r\n continuation\r\nDate: Thu, 01 Jan 2026 00:00:00 +0000\r\nMessage-ID: <keep@example.com>\r\n" +
		"\r\nline1\r\nBcc: not a header\r\n"
	if string(out) != want || addr != "a@example.com" || domain != "example.com" {
		t.Errorf("prepare =\n%q\nwant\n%q\n(%s, %s)", out, want, addr, domain)
	}
	// Blind-copy variants go; an empty Date or Message-ID is replaced, not duplicated.
	out, _, _, err = prepare([]byte("From: a@example.com\r\nResent-Bcc: h@example.org\r\nDate:\r\nMessage-ID: \r\n\r\nx\r\n"),
		"QID", "relay.example.com", "ESMTP", now)
	if err != nil {
		t.Fatal(err)
	}
	if s := string(out); strings.Contains(s, "Resent-Bcc") || strings.Count(s, "\nDate:") != 1 || strings.Count(s, "\nMessage-ID:") != 1 ||
		strings.Contains(s, "Date:\r\n") {
		t.Errorf("prepare output:\n%s", s)
	}
	loop := bytes.Repeat([]byte("Received: x\r\n"), maxReceived+1)
	if _, _, _, err := prepare(append(loop, "From: a@example.com\r\n\r\n"...), "Q", "h", "ESMTP", now); !errors.Is(err, errBadMessage) {
		t.Errorf("mail loop: got %v", err)
	}
}

func TestTotalConnectionLimit(t *testing.T) {
	e := start(t, func(c *config.Config) { c.MaxConnections = 1 })
	first := e.dial(Listener587, false)
	c, err := net.Dial("tcp", e.srv.Addr(Listener25).String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close() //nolint:errcheck // test connection
	buf := make([]byte, 4)
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "421 " {
		t.Fatalf("second connection got %q, %v; want 421", buf, err)
	}
	_ = first.Close()
}

// An IPv6 client is counted by its /64, not by each address it can pick.
func TestLimitKey(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.7":           "192.0.2.7",
		"::ffff:192.0.2.7":    "192.0.2.7",
		"2001:db8:1:2:3::4":   "2001:db8:1:2::",
		"2001:db8:1:2:ffff::": "2001:db8:1:2::",
		"2001:db8:1:3::1":     "2001:db8:1:3::",
	} {
		if got := limitKey(netip.MustParseAddr(in)).String(); got != want {
			t.Errorf("limitKey(%s) = %s, want %s", in, got, want)
		}
	}
}

func TestAuthLimiter(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	a := newAuthLimiter(10 * time.Minute)
	a.now = func() time.Time { return now }

	// Attempts in flight count: with a limit of 2, a third parallel attempt waits its turn.
	f1, ok1 := a.begin("192.0.2.1", 2)
	f2, ok2 := a.begin("192.0.2.1", 2)
	if _, ok3 := a.begin("192.0.2.1", 2); !ok1 || !ok2 || ok3 {
		t.Fatalf("parallel attempts admitted: %v %v %v, want true true false", ok1, ok2, ok3)
	}
	f1(false) // a success frees its slot and leaves no mark
	f2(true)
	f3, ok := a.begin("192.0.2.1", 2)
	if !ok {
		t.Fatal("one failure of two must not block")
	}
	f3(true)
	if _, ok := a.begin("192.0.2.1", 2); ok {
		t.Error("two failures must block the address")
	}
	if _, ok := a.begin("192.0.2.2", 2); !ok {
		t.Error("another address must not be affected")
	}
	now = now.Add(10 * time.Minute)
	if _, ok := a.begin("192.0.2.1", 2); !ok {
		t.Error("the block must lift after the window")
	}
}

func TestLimitersKeepActiveBucketsWhenBounded(t *testing.T) {
	l := newLimiters(time.Hour)
	l.allow("busy", 1) // now empty: has history worth keeping
	for i := range 10001 {
		l.get(fmt.Sprintf("idle-%d", i), 1)
	}
	l.get("trigger", 1)
	if l.allow("busy", 1) {
		t.Error("bounding the map forgot a client that was at its limit")
	}
	if len(l.buckets) > 3 {
		t.Errorf("idle buckets were not dropped: %d left", len(l.buckets))
	}
}

func TestSenderAllowedAndMatchNetwork(t *testing.T) {
	for _, tc := range []struct {
		patterns []string
		addr     string
		want     bool
	}{
		{nil, "any@example.com", true},
		{[]string{"example.com"}, "Any@Example.com", true},
		{[]string{"example.com"}, "any@sub.example.com", false},
		{[]string{"example.com"}, "any@notexample.com", false},
		{[]string{"app@example.com"}, "APP@example.com", true},
		{[]string{"app@example.com"}, "other@example.com", false},
	} {
		if got := senderAllowed(tc.patterns, tc.addr); got != tc.want {
			t.Errorf("senderAllowed(%v, %q) = %v, want %v", tc.patterns, tc.addr, got, tc.want)
		}
	}
	nets := []store.Network{{CIDR: "192.0.2.0/24"}, {CIDR: "192.0.2.8/29"}, {CIDR: "2001:db8::/32"}}
	for ip, want := range map[string]string{
		"192.0.2.9":        "192.0.2.8/29", // most specific wins
		"192.0.2.200":      "192.0.2.0/24",
		"::ffff:192.0.2.1": "192.0.2.0/24", // IPv4-mapped
		"2001:db8::1":      "2001:db8::/32",
		"198.51.100.1":     "",
	} {
		got := ""
		if n := matchNetwork(nets, netip.MustParseAddr(ip)); n != nil {
			got = n.CIDR
		}
		if got != want {
			t.Errorf("matchNetwork(%s) = %q, want %q", ip, got, want)
		}
	}
	if matchNetwork(nets, netip.Addr{}) != nil {
		t.Error("an unknown client address must match no network")
	}
}
