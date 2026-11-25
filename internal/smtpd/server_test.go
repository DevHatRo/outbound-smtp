package smtpd

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
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
		MaxMessageSize: 1 << 20, MaxRecipients: 10, MaxConnectionsPerIP: 50,
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
		e.srv.authFail = newLimiters(10 * time.Minute) // lift the block for the next subtests
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
	t.Run("message rate", func(t *testing.T) {
		c := e.dial(Listener465, false)
		if err := c.Auth(sasl.NewPlainClient("", "app", goodPassword)); err != nil {
			t.Fatal(err)
		}
		// The oversized attempt above already used one of the two tokens.
		if err := send(c, "app@example.com", "rcpt@example.org", goodMessage); err != nil {
			t.Fatal(err)
		}
		wantCode(t, "over the rate", c.Mail("app@example.com", nil), 451)
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
			if _, err := c.Read(buf); err != nil || string(buf) != "220 " {
				t.Fatalf("greeting = %q, %v", buf, err)
			}
		}
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		open = append(open, c)
		buf := make([]byte, 4)
		if _, err := c.Read(buf); err != nil || string(buf) != "421 " {
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
	loop := bytes.Repeat([]byte("Received: x\r\n"), maxReceived+1)
	if _, _, _, err := prepare(append(loop, "From: a@example.com\r\n\r\n"...), "Q", "h", "ESMTP", now); !errors.Is(err, errBadMessage) {
		t.Errorf("mail loop: got %v", err)
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
