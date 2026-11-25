package queue

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/zap"

	"github.com/DevHatRO/outbound-smtp/internal/config"
	"github.com/DevHatRO/outbound-smtp/internal/delivery"
	"github.com/DevHatRO/outbound-smtp/internal/metrics"
	"github.com/DevHatRO/outbound-smtp/internal/store"
)

// scripted answers every recipient with the status its local part names.
type scripted struct {
	mu    sync.Mutex
	calls int
}

func (s *scripted) Deliver(_ context.Context, _ store.Message, _ string, rcpts []store.Recipient) []delivery.Result {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	out := make([]delivery.Result, len(rcpts))
	for i, r := range rcpts {
		out[i] = delivery.Result{Recipient: r, Host: "mx.example.org", TLS: true}
		switch local, _, _ := strings.Cut(r.Address, "@"); local {
		case "bounce":
			out[i].Status, out[i].Response = delivery.Bounced, "550 5.1.1 User unknown"
		case "defer":
			out[i].Status, out[i].Response = delivery.Deferred, "451 4.2.0 Try again later"
		default:
			out[i].Status, out[i].Response = delivery.Delivered, "250 2.0.0 Ok"
		}
	}
	return out
}

type markSigner struct{ fail bool }

func (m markSigner) Sign(domain string, msg []byte) ([]byte, error) {
	if m.fail {
		return nil, errors.New("no key")
	}
	return append([]byte("X-Signed-For: "+domain+"\r\n"), msg...), nil
}

type env struct {
	t   *testing.T
	q   *Queue
	st  *store.Store
	dl  *scripted
	m   *metrics.Metrics
	now time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	e := &env{t: t, st: st, dl: &scripted{}, m: metrics.New("test"), now: time.Now()}
	cfg := &config.Config{Hostname: "relay.example.com", QueueMaxAge: 72 * time.Hour, DeliveryConcurrency: 4, DeliveryConcurrencyPerDomain: 2}
	e.q = New(cfg, st, e.dl, markSigner{}, zap.NewNop(), e.m)
	e.q.Now = func() time.Time { return e.now }
	e.q.Jitter = func(d time.Duration) time.Duration { return d }
	return e
}

func (e *env) enqueue(id, from string, rcpts ...string) {
	e.t.Helper()
	m := store.Message{ID: id, EnvelopeFrom: from, FromDomain: "example.com", Source: store.SourceAuth, SourceIdent: "app",
		Body: []byte("From: app@example.com\r\nSubject: s\r\n\r\nbody\r\n")}
	if err := e.st.Enqueue(m, rcpts); err != nil {
		e.t.Fatal(err)
	}
}

// pass runs one scheduler pass to completion.
func (e *env) pass() {
	e.q.dispatch()
	e.q.wg.Wait()
}

func (e *env) recipients(id string) []store.Recipient {
	e.t.Helper()
	r, err := e.st.ListRecipients(id)
	if err != nil {
		e.t.Fatal(err)
	}
	return r
}

func TestBackoffSchedule(t *testing.T) {
	want := []time.Duration{5 * time.Minute, 10 * time.Minute, 20 * time.Minute, 40 * time.Minute, 80 * time.Minute,
		160 * time.Minute, 4 * time.Hour, 4 * time.Hour}
	for i, w := range want {
		if got := Backoff(i + 1); got != w {
			t.Errorf("Backoff(%d) = %v, want %v", i+1, got, w)
		}
	}
	if Backoff(1000) != 4*time.Hour {
		t.Error("backoff must stay capped for any attempt count")
	}
}

func TestDeliveredMessageLeavesTheQueue(t *testing.T) {
	e := newEnv(t)
	e.enqueue("Q1", "app@example.com", "ok@example.org", "ok2@example.org", "ok@example.net")
	e.pass()
	if left := e.recipients(""); len(left) != 0 {
		t.Fatalf("queue not empty: %+v", left)
	}
	if e.dl.calls != 2 {
		t.Errorf("deliver calls = %d, want one per destination domain (2)", e.dl.calls)
	}
	if n := testutil.ToFloat64(e.m.Deliveries.WithLabelValues("delivered", "true")); n != 3 {
		t.Errorf("delivered metric = %v, want 3", n)
	}
}

func TestDeferredRecipientRetriesWithBackoff(t *testing.T) {
	e := newEnv(t)
	e.enqueue("Q1", "app@example.com", "defer@example.org", "ok@example.org")
	e.pass()
	left := e.recipients("Q1")
	if len(left) != 1 || left[0].Address != "defer@example.org" {
		t.Fatalf("after first pass: %+v", left)
	}
	r := left[0]
	if r.State != store.StateDeferred || r.Attempts != 1 || r.LastError != "451 4.2.0 Try again later" ||
		r.NextAttemptAt != e.now.Add(5*time.Minute).Unix() {
		t.Errorf("deferred recipient = %+v, want next attempt in 5m", r)
	}

	e.pass() // not due yet
	if e.dl.calls != 1 {
		t.Fatalf("retried before the backoff elapsed (%d calls)", e.dl.calls)
	}
	for i, wait := range []time.Duration{10 * time.Minute, 20 * time.Minute} {
		e.now = time.Unix(e.recipients("Q1")[0].NextAttemptAt, 0)
		e.pass()
		r = e.recipients("Q1")[0]
		if r.Attempts != i+2 || r.NextAttemptAt != e.now.Add(wait).Unix() {
			t.Errorf("after attempt %d: %+v, want next in %v", i+2, r, wait)
		}
	}
	if n := testutil.ToFloat64(e.m.Deliveries.WithLabelValues("deferred", "true")); n != 3 {
		t.Errorf("deferred metric = %v, want 3", n)
	}
}

func TestPermanentFailureBouncesToSender(t *testing.T) {
	e := newEnv(t)
	e.enqueue("Q1", "app@example.com", "bounce@example.org", "ok@example.org")
	e.pass()
	if len(e.recipients("Q1")) != 0 {
		t.Fatal("original message should be finished")
	}
	all := e.recipients("")
	if len(all) != 1 || all[0].Address != "app@example.com" {
		t.Fatalf("expected one bounce to the envelope sender, queue = %+v", all)
	}
	dsn, err := e.st.GetMessage(all[0].MessageID)
	if err != nil {
		t.Fatal(err)
	}
	body := string(dsn.Body)
	if dsn.EnvelopeFrom != "" || dsn.Source != store.SourceInternal || dsn.FromDomain != "example.com" {
		t.Errorf("bounce = %+v", dsn)
	}
	for _, want := range []string{"X-Signed-For: example.com\r\nReceived: by relay.example.com (DevHatRO SMTP) id " + dsn.ID + ";",
		"postmaster@example.com", "Final-Recipient: rfc822; bounce@example.org",
		"Status: 5.1.1", "550 5.1.1 User unknown"} {
		if !strings.Contains(body, want) {
			t.Errorf("bounce lacks %q", want)
		}
	}
	if strings.Contains(body, "ok@example.org") {
		t.Error("bounce mentions a recipient that was delivered")
	}

	// The bounce is delivered like any other message.
	e.pass()
	if left := e.recipients(""); len(left) != 0 {
		t.Errorf("bounce not delivered: %+v", left)
	}
}

func TestBounceOfABounceIsDropped(t *testing.T) {
	e := newEnv(t)
	e.enqueue("DSN1", "", "bounce@example.org") // null sender: this is itself a bounce
	e.pass()
	if left := e.recipients(""); len(left) != 0 {
		t.Fatalf("a failed bounce must not generate another message: %+v", left)
	}
}

func TestUnsignableBounceIsDroppedNotSentUnsigned(t *testing.T) {
	e := newEnv(t)
	e.q.signer = markSigner{fail: true}
	e.enqueue("Q1", "app@example.com", "bounce@example.org")
	e.pass()
	if left := e.recipients(""); len(left) != 0 {
		t.Fatalf("queue = %+v, want empty", left)
	}
}

func TestExpiredMessageBounces(t *testing.T) {
	e := newEnv(t)
	e.enqueue("Q1", "app@example.com", "defer@example.org")
	e.pass() // first failure

	// A retry due just before expiry is capped at the expiry time.
	e.now = e.now.Add(72*time.Hour - time.Minute)
	if err := e.st.RetryNow("Q1"); err != nil {
		t.Fatal(err)
	}
	// RetryNow stamps wall-clock time; move the row to the fake clock.
	if err := e.st.RecipientDefer(e.recipients("Q1")[0].ID, e.now, "451 4.2.0 Try again later"); err != nil {
		t.Fatal(err)
	}
	e.pass()
	r := e.recipients("Q1")[0]
	msg, _ := e.st.GetMessage("Q1")
	expiry := time.Unix(msg.CreatedAt, 0).Add(72 * time.Hour).Unix()
	if r.NextAttemptAt != expiry {
		t.Fatalf("next attempt = %d, want capped at expiry %d", r.NextAttemptAt, expiry)
	}

	calls := e.dl.calls
	e.now = time.Unix(expiry, 0)
	e.pass()
	if e.dl.calls != calls {
		t.Error("an expired recipient must bounce without another delivery attempt")
	}
	all := e.recipients("")
	if len(all) != 1 || all[0].Address != "app@example.com" {
		t.Fatalf("expected the expiry bounce, queue = %+v", all)
	}
	dsn, _ := e.st.GetMessage(all[0].MessageID)
	if !strings.Contains(string(dsn.Body), "Status: 4.4.7") || !strings.Contains(string(dsn.Body), "message expired after 72h0m0s") {
		t.Errorf("expiry bounce body:\n%s", dsn.Body)
	}
	if n := testutil.ToFloat64(e.m.Deliveries.WithLabelValues("bounced", "false")); n != 1 {
		t.Errorf("bounced metric = %v, want 1", n)
	}
}

func TestNeverTriedMessageGetsOneAttemptEvenIfOld(t *testing.T) {
	e := newEnv(t)
	e.enqueue("Q1", "app@example.com", "ok@example.org")
	e.now = e.now.Add(100 * time.Hour) // the daemon was down for days
	e.pass()
	if e.dl.calls != 1 || len(e.recipients("")) != 0 {
		t.Errorf("calls = %d, queue = %+v; want one attempt and delivery", e.dl.calls, e.recipients(""))
	}
}

func TestRunStopsAndLeavesQueueIntact(t *testing.T) {
	e := newEnv(t)
	e.enqueue("Q1", "app@example.com", "defer@example.org")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.q.Run(ctx); close(done) }()
	deadline := time.Now().Add(3 * time.Second)
	for len(e.recipients("Q1")) == 0 || e.recipients("Q1")[0].Attempts == 0 {
		if time.Now().After(deadline) {
			t.Fatal("scheduler did not attempt delivery")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	if len(e.recipients("Q1")) != 1 {
		t.Error("a deferred message must survive shutdown")
	}
}
