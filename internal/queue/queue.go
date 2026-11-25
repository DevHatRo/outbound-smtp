// Package queue schedules delivery attempts for the persistent SQLite queue:
// retries with exponential backoff, expiry, and bounces.
package queue

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"regexp"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"

	"github.com/DevHatRo/outbound-smtp/internal/config"
	"github.com/DevHatRo/outbound-smtp/internal/delivery"
	"github.com/DevHatRo/outbound-smtp/internal/metrics"
	"github.com/DevHatRo/outbound-smtp/internal/store"
	"github.com/DevHatRo/outbound-smtp/internal/tracing"
)

// Deliverer makes one delivery attempt for recipients sharing a domain.
type Deliverer interface {
	Deliver(ctx context.Context, msg store.Message, domain string, rcpts []store.Recipient) []delivery.Result
}

// Signer DKIM-signs bounce messages.
type Signer interface {
	Sign(domain string, msg []byte) ([]byte, error)
}

// Retry schedule: 5 minutes, doubling, capped at 4 hours.
const (
	backoffBase = 5 * time.Minute
	backoffMax  = 4 * time.Hour
)

// Backoff returns the wait before the next attempt after `failures` failed
// attempts (1 for the first failure), without jitter.
func Backoff(failures int) time.Duration {
	d := backoffBase
	for i := 1; i < failures && d < backoffMax; i++ {
		d *= 2
	}
	return min(d, backoffMax)
}

// Queue is the delivery scheduler.
type Queue struct {
	cfg    *config.Config
	st     *store.Store
	dl     Deliverer
	signer Signer
	log    *zap.Logger
	m      *metrics.Metrics

	// Now and Jitter are replaceable for tests.
	Now    func() time.Time
	Jitter func(d time.Duration) time.Duration
	// AttemptTimeout bounds one delivery attempt, including after shutdown began.
	AttemptTimeout time.Duration

	wake chan struct{}
	sem  chan struct{} // global delivery concurrency
	wg   sync.WaitGroup

	mu        sync.Mutex
	inFlight  map[string]bool // message ID + destination domain
	perDomain map[string]int
}

// New creates the scheduler.
func New(cfg *config.Config, st *store.Store, dl Deliverer, signer Signer, log *zap.Logger, m *metrics.Metrics) *Queue {
	return &Queue{
		cfg: cfg, st: st, dl: dl, signer: signer, log: log, m: m,
		Now: time.Now,
		Jitter: func(d time.Duration) time.Duration { // +/-10% so retries do not synchronise
			return d + time.Duration((rand.Float64()*0.2-0.1)*float64(d)) //nolint:gosec // jitter, not a secret
		},
		AttemptTimeout: 15 * time.Minute,
		wake:           make(chan struct{}, 1),
		sem:            make(chan struct{}, cfg.DeliveryConcurrency),
		inFlight:       map[string]bool{},
		perDomain:      map[string]int{},
	}
}

// Wake asks the scheduler to look at the queue now.
func (q *Queue) Wake() {
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

// Run schedules deliveries until ctx is cancelled, then waits for the
// attempts in flight. Anything unfinished stays in SQLite for the next start.
func (q *Queue) Run(ctx context.Context) {
	// Polling also picks up what the CLI writes (send-test, queue retry).
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		// Checked before every pass: select picks at random among ready cases,
		// so a wake-up from a finishing attempt could otherwise start new
		// deliveries after shutdown began.
		if ctx.Err() != nil {
			q.wg.Wait()
			return
		}
		q.dispatch()
		select {
		case <-ctx.Done():
			q.wg.Wait()
			return
		case <-tick.C:
		case <-q.wake:
		}
	}
}

type group struct {
	messageID string
	domain    string
	rcpts     []store.Recipient
}

// dispatch starts an attempt for every due group that fits the limits.
func (q *Queue) dispatch() {
	// ponytail: one page of 1000 due rows; a single huge blocked destination can
	// delay others until its rows are deferred. Page per domain if that shows up.
	due, err := q.st.DueRecipients(q.Now(), 1000)
	if err != nil {
		q.log.Error("read queue", zap.Error(err))
		return
	}
	var groups []*group
	index := map[string]*group{}
	for _, r := range due {
		key := r.MessageID + "\x00" + r.Domain
		g, ok := index[key]
		if !ok {
			g = &group{messageID: r.MessageID, domain: r.Domain}
			index[key] = g
			groups = append(groups, g)
		}
		g.rcpts = append(g.rcpts, r)
	}
	for _, g := range groups {
		key := g.messageID + "\x00" + g.domain
		q.mu.Lock()
		busy := q.inFlight[key] || q.perDomain[g.domain] >= q.cfg.DeliveryConcurrencyPerDomain
		q.mu.Unlock()
		if busy {
			continue
		}
		select {
		case q.sem <- struct{}{}:
		default:
			return // global limit reached; finishing attempts wake us
		}
		q.mu.Lock()
		q.inFlight[key] = true
		q.perDomain[g.domain]++
		q.mu.Unlock()
		q.wg.Add(1)
		go func() {
			defer func() {
				q.mu.Lock()
				delete(q.inFlight, key)
				if q.perDomain[g.domain]--; q.perDomain[g.domain] <= 0 {
					delete(q.perDomain, g.domain)
				}
				q.mu.Unlock()
				<-q.sem
				q.wg.Done()
				q.Wake()
			}()
			q.attempt(g)
		}()
	}
}

// bouncePending prefixes last_error of a recipient whose delivery failed
// for good but whose bounce could not be queued yet. Such a recipient is
// never offered to the remote server again; only the bounce is retried.
const bouncePending = "bounce pending: "

// redact removes the recipient's address from a remote reply before it is
// logged or traced: servers often echo it ("550 <user@example.org>: unknown").
func redact(reply, address string) string {
	if address == "" {
		return reply
	}
	return regexp.MustCompile("(?i)"+regexp.QuoteMeta(address)).ReplaceAllLiteralString(reply, "[recipient]")
}

// attempt handles one message for one destination domain.
func (q *Queue) attempt(g *group) {
	msg, err := q.st.GetMessage(g.messageID)
	if err != nil { // deleted through the CLI meanwhile
		q.log.Info("queued message is gone, skipping", zap.String("queue_id", g.messageID), zap.Error(err))
		return
	}
	now := q.Now()
	expiry := time.Unix(msg.CreatedAt, 0).Add(q.cfg.QueueMaxAge)

	// The group was read before it was admitted; an attempt that finished in
	// between has already removed or rescheduled some of its rows. Work only
	// on what the store says is still due, or mail would be delivered twice.
	current, err := q.st.ListRecipients(g.messageID)
	if err != nil {
		q.log.Error("reload recipients", zap.String("queue_id", g.messageID), zap.Error(err))
		return
	}
	var rcpts []store.Recipient
	for _, r := range current {
		if r.Domain == g.domain && r.NextAttemptAt <= now.Unix() {
			rcpts = append(rcpts, r)
		}
	}
	if len(rcpts) == 0 {
		return
	}

	// Detached from the scheduler's context on purpose: shutdown lets attempts finish.
	ctx, cancel := context.WithTimeout(tracing.Extract(context.Background(), msg.Traceparent), q.AttemptTimeout)
	defer cancel()
	ctx, span := tracing.Tracer().Start(ctx, "smtp.deliver", trace.WithSpanKind(trace.SpanKindClient), trace.WithAttributes(
		attribute.String("smtprelay.queue_id", msg.ID),
		attribute.String("smtprelay.sender", msg.EnvelopeFrom),
		attribute.String("smtprelay.recipient_domain", g.domain),
		attribute.Int("smtprelay.recipients", len(rcpts)),
	))
	defer span.End()

	var try []store.Recipient
	var results []delivery.Result
	for _, r := range rcpts {
		switch {
		case strings.HasPrefix(r.LastError, bouncePending):
			// Already failed permanently; only its bounce is outstanding.
			results = append(results, delivery.Result{Recipient: r, Status: delivery.Bounced,
				Response: strings.TrimPrefix(r.LastError, bouncePending)})
		case r.Attempts > 0 && !now.Before(expiry):
			// Expired recipients bounce without another attempt, but only once
			// they were tried at least once (the daemon may have been down for days).
			results = append(results, delivery.Result{Recipient: r, Status: delivery.Bounced,
				Response: fmt.Sprintf("4.4.7 message expired after %s in the queue; last error: %s", q.cfg.QueueMaxAge, r.LastError)})
		default:
			try = append(try, r)
		}
	}
	if len(try) > 0 {
		start := time.Now()
		results = append(results, q.dl.Deliver(ctx, msg, g.domain, try)...)
		q.m.DeliveryDuration.Observe(time.Since(start).Seconds())
	}
	// Backoff counts from the end of the attempt: a delivery that fails after
	// several minutes must not be due again the moment it returns.
	done := q.Now()

	var failures []delivery.Failure
	var bounced []store.Recipient
	delivered := 0
	for _, res := range results {
		r := res.Recipient
		safe := redact(res.Response, r.Address)
		q.m.Deliveries.WithLabelValues(res.Status.String(), metrics.TLSLabel(res.TLS)).Inc()
		span.AddEvent("recipient", trace.WithAttributes(attribute.String("smtprelay.result", res.Status.String()),
			attribute.String("smtprelay.response", safe), attribute.String("server.address", res.Host),
			attribute.Bool("smtprelay.tls", res.TLS)))
		// With LOG_RECIPIENTS the operator asked for addresses in the log, so
		// the reply is kept as received too. Traces stay redacted either way.
		logged := safe
		if q.cfg.LogRecipients {
			logged = res.Response
		}
		fields := []zap.Field{
			zap.String("queue_id", msg.ID), zap.String("sender", msg.EnvelopeFrom), zap.String("recipient_domain", g.domain),
			zap.String("result", res.Status.String()), zap.String("response", logged), zap.String("remote_host", res.Host),
			zap.Bool("tls", res.TLS), zap.Int("attempt", r.Attempts+1), zap.String("trace_id", tracing.TraceID(ctx)),
		}
		if q.cfg.LogRecipients {
			fields = append(fields, zap.String("recipient", r.Address))
		}
		q.log.Info("delivery attempt", fields...)
		switch res.Status {
		case delivery.Delivered:
			delivered++
			if err := q.st.RecipientDone(r); err != nil {
				// The remote has the message; a duplicate is the cost of not losing it.
				q.log.Error("mark delivered", zap.String("queue_id", msg.ID), zap.Error(err))
			}
		case delivery.Deferred:
			next := done.Add(q.Jitter(Backoff(r.Attempts + 1)))
			if next.After(expiry) {
				next = expiry // the next look at this recipient bounces it
			}
			if err := q.st.RecipientDefer(r, next, res.Response); err != nil {
				q.log.Error("defer recipient", zap.String("queue_id", msg.ID), zap.Error(err))
			}
		case delivery.Bounced:
			failures = append(failures, delivery.Failure{Address: r.Address, Response: res.Response, Host: res.Host})
			bounced = append(bounced, r)
		}
	}
	if delivered == 0 {
		span.SetStatus(codes.Error, "no recipient accepted")
	}
	if len(failures) == 0 {
		return
	}
	// Queue the bounce before dropping the recipients: a crash in between
	// sends the bounce twice instead of never.
	if err := q.bounce(ctx, msg, failures); err != nil {
		for i, r := range bounced {
			if !done.Before(expiry) {
				// Past the queue lifetime there is nothing left to wait for.
				q.log.Error("bounce could not be queued before the message expired, dropped",
					zap.String("queue_id", msg.ID), zap.Error(err))
				if err := q.st.RecipientDone(r); err != nil {
					q.log.Error("remove bounced recipient", zap.String("queue_id", msg.ID), zap.Error(err))
				}
				continue
			}
			// Keep the verdict with the recipient so the retry sends the
			// bounce, not the rejected message, again.
			q.log.Error("bounce not queued, will retry", zap.String("queue_id", msg.ID), zap.Error(err))
			if err := q.st.RecipientDefer(r, done.Add(backoffBase), bouncePending+failures[i].Response); err != nil {
				q.log.Error("defer recipient", zap.String("queue_id", msg.ID), zap.Error(err))
			}
		}
		return
	}
	for _, r := range bounced {
		if err := q.st.RecipientDone(r); err != nil {
			q.log.Error("remove bounced recipient", zap.String("queue_id", msg.ID), zap.Error(err))
		}
	}
}

// bounce queues a signed DSN to the envelope sender. A nil return means the
// failure has been dealt with, including the cases where no DSN is possible.
func (q *Queue) bounce(ctx context.Context, msg store.Message, failures []delivery.Failure) error {
	ctx, span := tracing.Tracer().Start(ctx, "dsn.generate", trace.WithAttributes(
		attribute.String("smtprelay.queue_id", msg.ID), attribute.Int("smtprelay.recipients", len(failures))))
	defer span.End()
	if msg.EnvelopeFrom == "" {
		// A bounce that bounced: never answer it (RFC 5321 section 6.1).
		q.log.Warn("bounce message undeliverable, dropped", zap.String("queue_id", msg.ID))
		return nil
	}
	id := store.NewID()
	dsn := append([]byte(config.ReceivedHeader(q.cfg.Hostname, "", id, q.Now())),
		delivery.BuildDSN(q.cfg.Hostname, msg, failures, q.Now())...)
	signed, err := q.signer.Sign(msg.FromDomain, dsn)
	if err != nil {
		q.m.DKIMSign.WithLabelValues(msg.FromDomain, "error").Inc()
		span.SetStatus(codes.Error, err.Error())
		if !errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("sign bounce: %w", err) // may be transient: keep the bounce
		}
		// The sending domain or its key was removed; an unsigned bounce would
		// only hurt the reputation of the relay.
		q.log.Error("bounce cannot be signed, dropped", zap.String("queue_id", msg.ID), zap.String("from_domain", msg.FromDomain), zap.Error(err))
		return nil
	}
	q.m.DKIMSign.WithLabelValues(msg.FromDomain, "ok").Inc()
	if err := q.st.Enqueue(store.Message{ID: id, EnvelopeFrom: "", FromDomain: msg.FromDomain, Source: store.SourceInternal,
		SourceIdent: "dsn", Body: signed, Traceparent: tracing.Inject(ctx)}, []string{msg.EnvelopeFrom}); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	q.log.Info("bounce queued", zap.String("queue_id", id), zap.String("original_queue_id", msg.ID),
		zap.String("sender", msg.EnvelopeFrom), zap.Int("failed_recipients", len(failures)))
	return nil
}
