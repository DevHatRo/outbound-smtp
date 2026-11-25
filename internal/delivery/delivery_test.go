package delivery

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/DevHatRO/outbound-smtp/internal/config"
	"github.com/DevHatRO/outbound-smtp/internal/store"
	"github.com/DevHatRO/outbound-smtp/internal/testutil"
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
}

// newFixture starts a sink and a client whose every connection lands on it,
// whatever host DNS named. Hosts listed in down refuse the connection.
func newFixture(t *testing.T, sinkTLS bool, dns fakeDNS, down ...string) *fixture {
	t.Helper()
	var tlsCfg *tls.Config
	if sinkTLS {
		certFile, keyFile, err := testutil.WriteSelfSignedCert(t.TempDir(), time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			t.Fatal(err)
		}
		tlsCfg = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	}
	sink, err := testutil.StartSink(tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sink.Close)
	f := &fixture{sink: sink}
	f.client = New(&config.Config{Hostname: "relay.example.com", SmarthostPort: 587})
	f.client.Resolver = dns
	f.client.Dial = func(ctx context.Context, _, addr string) (net.Conn, error) {
		f.dialed = append(f.dialed, addr)
		for _, d := range down {
			if strings.HasPrefix(addr, d+":") {
				return nil, errors.New("connection refused")
			}
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", sink.Addr)
	}
	return f
}

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

// Smarthost credentials must never travel without verified TLS.
func TestSmarthostCredentialsNeedVerifiedTLS(t *testing.T) {
	for name, sinkTLS := range map[string]bool{"no STARTTLS offered": false, "certificate does not verify": true} {
		f := newFixture(t, sinkTLS, fakeDNS{})
		f.client.cfg.SmarthostHost, f.client.cfg.SmarthostUsername, f.client.cfg.SmarthostPassword = "smarthost.example.net", "user", "secret"
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
		if len(f.dialed) != 1 || f.dialed[0] != "smarthost.example.net:587" {
			t.Errorf("%s: dialed %v, want one attempt and no plaintext retry", name, f.dialed)
		}
	}
}

func TestSmarthostWithoutCredentialsSkipsMX(t *testing.T) {
	f := newFixture(t, true, fakeDNS{err: errors.New("DNS must not be used")})
	f.client.cfg.SmarthostHost = "smarthost.example.net"
	res := f.client.Deliver(context.Background(), testMsg, "example.org", rcpts("ok@example.org"))
	if res[0].Status != Delivered || !res[0].TLS {
		t.Errorf("result = %+v", res[0])
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

func TestOneLineIsRuneSafe(t *testing.T) {
	got := oneLine("550 " + strings.Repeat("é", 400) + "\r\nsecond line")
	if len(got) > 503 || !strings.HasSuffix(got, "...") || strings.ContainsAny(got, "\r\n") || strings.ContainsRune(got, '\uFFFD') {
		t.Errorf("oneLine = %q", got)
	}
}
