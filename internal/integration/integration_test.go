// Package integration sends a message through the whole relay: submission
// over STARTTLS, DKIM signing, the SQLite queue and delivery to a fake remote
// server, then checks the signature, the metrics and the trace.
package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	msgdkim "github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.uber.org/zap"

	"github.com/DevHatRo/outbound-smtp/internal/config"
	"github.com/DevHatRo/outbound-smtp/internal/delivery"
	"github.com/DevHatRo/outbound-smtp/internal/dkim"
	"github.com/DevHatRo/outbound-smtp/internal/metrics"
	"github.com/DevHatRo/outbound-smtp/internal/password"
	"github.com/DevHatRo/outbound-smtp/internal/queue"
	"github.com/DevHatRo/outbound-smtp/internal/smtpd"
	"github.com/DevHatRo/outbound-smtp/internal/store"
	"github.com/DevHatRo/outbound-smtp/internal/testutil"
)

type staticDNS struct{}

func (staticDNS) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	return []*net.MX{{Host: "mx." + name + ".", Pref: 10}}, nil
}
func (staticDNS) LookupHost(context.Context, string) ([]string, error) {
	return []string{"192.0.2.1"}, nil
}

const userPassword = "integration-test-password"

func TestEndToEnd(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, err := testutil.WriteSelfSignedCert(dir, time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}

	// Traces go to memory instead of a collector.
	spans := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(spans))
	otel.SetTracerProvider(tp)
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })

	// The "internet": one fake MX that every delivery lands on.
	sink, err := testutil.StartSink(&tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sink.Close)

	cfg := &config.Config{
		Hostname: "relay.example.com", Listen465: "127.0.0.1:0", Listen587: "127.0.0.1:0",
		TLSCertFile: certFile, TLSKeyFile: keyFile, DataDir: dir,
		MaxMessageSize: 1 << 20, MaxRecipients: 10, QueueMaxAge: 72 * time.Hour,
		DeliveryConcurrency: 4, DeliveryConcurrencyPerDomain: 2, MaxConnectionsPerIP: 10,
		RateLimitUserPerHour: 100, RateLimitNetworkPerHour: 100, AuthFailureLimit: 5,
	}
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	// What an admin does with the CLI.
	hash, err := password.Hash(userPassword)
	if err != nil {
		t.Fatal(err)
	}
	key, err := dkim.Generate(dkim.RSA)
	if err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(st.AddDomain("example.com"), st.AddDKIMKey("example.com", "sel1", dkim.RSA, key),
		st.AddUser("app", hash, nil, nil)); err != nil {
		t.Fatal(err)
	}
	active, err := st.ActiveDKIMKey("example.com")
	if err != nil {
		t.Fatal(err)
	}
	record, err := dkim.RecordFor(active)
	if err != nil {
		t.Fatal(err)
	}

	// The daemon, wired as in "serve".
	m := metrics.New("test")
	m.RegisterQueue(func() (int64, int64, int64, error) {
		s, err := st.QueueStats()
		return s.Pending, s.Deferred, s.Oldest, err
	})
	signer := dkim.Signer{Store: st}
	dl := delivery.New(cfg)
	dl.Resolver = staticDNS{}
	dl.Dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", sink.Addr)
	}
	q := queue.New(cfg, st, dl, signer, zap.NewNop(), m)
	srv, err := smtpd.New(cfg, st, signer, zap.NewNop(), m, q.Wake)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	metricsLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	queueDone := make(chan struct{})
	go func() { q.Run(ctx); close(queueDone) }()
	go func() { _ = m.Serve(ctx, metricsLn, st.Ping) }()
	t.Cleanup(func() {
		shutdownCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		_ = srv.Shutdown(shutdownCtx)
		cancel()
		<-queueDone
	})

	// An application submits one message to a good and a bad recipient.
	c, err := smtp.DialStartTLS(srv.Addr(smtpd.Listener587).String(), &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test cert
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Auth(sasl.NewPlainClient("", "app", userPassword)); err != nil {
		t.Fatal(err)
	}
	const submitted = "From: App <app@example.com>\r\nTo: ok@example.org, bounce@example.org\r\nSubject: integration\r\n\r\nHello.\r\n"
	if err := c.SendMail("app@example.com", []string{"ok@example.org", "bounce@example.org"}, strings.NewReader(submitted)); err != nil {
		t.Fatalf("submit: %v", err)
	}
	if err := c.Quit(); err != nil {
		t.Fatal(err)
	}

	// Expect the message at ok@ and, because bounce@ was refused, a DSN back
	// to the sender. Both travel through the fake MX.
	deadline := time.Now().Add(15 * time.Second)
	for len(sink.Messages()) < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("sink received %d message(s), want 2", len(sink.Messages()))
		}
		time.Sleep(20 * time.Millisecond)
	}
	var original, bounce testutil.Received
	for _, msg := range sink.Messages() {
		if msg.From == "" {
			bounce = msg
		} else {
			original = msg
		}
	}
	if original.From != "app@example.com" || len(original.To) != 1 || original.To[0] != "ok@example.org" || !original.TLS ||
		original.Helo != "relay.example.com" {
		t.Errorf("delivered message envelope = %+v", original)
	}
	if len(bounce.To) != 1 || bounce.To[0] != "app@example.com" || !bytes.Contains(bounce.Data, []byte("Final-Recipient: rfc822; bounce@example.org")) {
		t.Errorf("bounce = %+v\n%s", bounce, bounce.Data)
	}

	// Both must carry a DKIM signature that verifies against the record the
	// CLI prints for publication.
	for name, data := range map[string][]byte{"message": original.Data, "bounce": bounce.Data} {
		vs, err := msgdkim.VerifyWithOptions(bytes.NewReader(data), &msgdkim.VerifyOptions{
			LookupTXT: func(name string) ([]string, error) {
				if name != record.Name {
					return nil, fmt.Errorf("unexpected DKIM lookup %q", name)
				}
				return []string{record.Value}, nil
			},
		})
		if err != nil || len(vs) != 1 || vs[0].Err != nil || vs[0].Domain != "example.com" {
			t.Errorf("%s: DKIM verification failed: %v %+v\n%s", name, err, vs, data)
		}
	}
	if !bytes.HasSuffix(original.Data, []byte("\r\n\r\nHello.\r\n")) || !bytes.Contains(original.Data, []byte("Subject: integration\r\n")) {
		t.Errorf("delivered message was altered:\n%s", original.Data)
	}

	// The queue drains completely.
	for {
		stats, err := st.QueueStats()
		if err != nil {
			t.Fatal(err)
		}
		if stats.Pending+stats.Deferred == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("queue did not drain: %+v", stats)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Metrics as Prometheus would scrape them.
	base := "http://" + metricsLn.Addr().String()
	get := func(path string) (int, string) {
		t.Helper()
		resp, err := http.Get(base + path) //nolint:noctx // test
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, string(body)
	}
	if code, body := get("/healthz"); code != http.StatusOK || body != "ok\n" {
		t.Errorf("/healthz = %d %q", code, body)
	}
	// connections_total is counted when the client connection closes.
	var scrape string
	for {
		_, scrape = get("/metrics")
		if strings.Contains(scrape, `smtprelay_connections_total{listener="587",tls="true"} 1`) || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, want := range []string{
		`smtprelay_connections_total{listener="587",tls="true"} 1`,
		`smtprelay_connections_active{listener="587"} 0`,
		`smtprelay_auth_attempts_total{result="success"} 1`,
		`smtprelay_messages_accepted_total{domain="example.com",source="auth"} 1`,
		`smtprelay_dkim_sign_total{domain="example.com",result="ok"} 2`, // message + bounce
		`smtprelay_deliveries_total{result="delivered",tls="true"} 2`,   // ok@ + the bounce
		`smtprelay_deliveries_total{result="bounced",tls="true"} 1`,
		`smtprelay_delivery_duration_seconds_count 2`,
		`smtprelay_queue_depth{state="pending"} 0`,
		`smtprelay_queue_depth{state="deferred"} 0`,
		`smtprelay_queue_oldest_message_age_seconds 0`,
		`smtprelay_build_info{go_version="`,
		`smtprelay_tls_cert_expiry_timestamp_seconds `,
	} {
		if !strings.Contains(scrape, want) {
			t.Errorf("/metrics lacks %q", want)
		}
	}
	for _, leak := range []string{"example.org", "ok@", "bounce@"} {
		if strings.Contains(scrape, leak) {
			t.Errorf("/metrics exposes recipient data (%q)", leak)
		}
	}

	// One trace follows the message from submission to delivery and bounce.
	// A span ends just after its recipient row is removed, so wait for the last one.
	for time.Now().Before(deadline) {
		n := 0
		for _, s := range spans.GetSpans() {
			if s.Name == "smtp.deliver" {
				n++
			}
		}
		if n >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	names := map[string]int{}
	traces := map[string]bool{}
	for _, s := range spans.GetSpans() {
		names[s.Name]++
		traces[s.SpanContext.TraceID().String()] = true
		for _, kv := range s.Attributes {
			if v := kv.Value.String(); strings.Contains(v, "ok@") || strings.Contains(v, "bounce@") {
				t.Errorf("span %s attribute %s exposes a recipient address: %s", s.Name, kv.Key, v)
			}
		}
	}
	if names["smtp.receive"] != 1 || names["dkim.sign"] != 1 || names["smtp.deliver"] != 2 || names["dsn.generate"] != 1 {
		t.Errorf("spans = %v", names)
	}
	if len(traces) != 1 {
		t.Errorf("spans are spread over %d traces, want 1", len(traces))
	}
}
