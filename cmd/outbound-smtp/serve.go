package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/mail"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/DevHatRO/outbound-smtp/internal/delivery"
	"github.com/DevHatRO/outbound-smtp/internal/dkim"
	"github.com/DevHatRO/outbound-smtp/internal/metrics"
	"github.com/DevHatRO/outbound-smtp/internal/queue"
	"github.com/DevHatRO/outbound-smtp/internal/smtpd"
	"github.com/DevHatRO/outbound-smtp/internal/store"
	"github.com/DevHatRO/outbound-smtp/internal/tracing"
)

// shutdownGrace is how long open SMTP sessions and in-flight deliveries get
// after SIGTERM. Give the container at least this long (stop_grace_period).
const shutdownGrace = 30 * time.Second

func newLogger(level zapcore.Level) (*zap.Logger, error) {
	cfg := zap.NewProductionConfig() // JSON
	cfg.Level = zap.NewAtomicLevelAt(level)
	cfg.Sampling = nil // every message and delivery attempt must be logged
	cfg.OutputPaths = []string{"stdout"}
	cfg.ErrorOutputPaths = []string{"stderr"}
	cfg.EncoderConfig.TimeKey = "time"
	cfg.EncoderConfig.EncodeTime = zapcore.RFC3339NanoTimeEncoder
	cfg.DisableStacktrace = true
	cfg.DisableCaller = true
	return cfg.Build()
}

func (a *app) serve() error {
	cfg := a.cfg
	if err := cfg.ValidateServe(); err != nil {
		return err
	}
	log, err := newLogger(cfg.LogLevel)
	if err != nil {
		return err
	}
	defer func() { _ = log.Sync() }() // stdout sync fails on some platforms; nothing to do about it

	st, err := store.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer func() {
		if err := st.Close(); err != nil {
			log.Error("close database", zap.Error(err))
		}
	}()

	ctx, stop := context.WithCancel(context.Background())
	defer stop()

	stopTracing, err := tracing.Setup(ctx, version)
	if err != nil {
		return fmt.Errorf("OpenTelemetry setup: %w", err)
	}

	m := metrics.New(version)
	m.RegisterQueue(func() (int64, int64, int64, error) {
		s, err := st.QueueStats()
		return s.Pending, s.Deferred, s.Oldest, err
	})
	signer := dkim.Signer{Store: st}
	q := queue.New(cfg, st, delivery.New(cfg), signer, log, m)

	srv, err := smtpd.New(cfg, st, signer, log, m, q.Wake)
	if err != nil {
		return err
	}
	metricsLn, err := net.Listen("tcp", cfg.MetricsListen)
	if err != nil {
		return fmt.Errorf("listen METRICS_LISTEN %s: %w", cfg.MetricsListen, err)
	}
	if err := srv.Start(); err != nil {
		return errors.Join(err, metricsLn.Close())
	}

	log.Info("outbound-smtp started", zap.String("version", version), zap.String("commit", commit),
		zap.String("hostname", cfg.Hostname), zap.Bool("port25", cfg.EnablePort25), zap.Bool("smarthost", cfg.SmarthostHost != ""),
		zap.Bool("tracing", tracing.Enabled()), zap.String("metrics", cfg.MetricsListen))

	go func() {
		if err := m.Serve(ctx, metricsLn, st.Ping); err != nil {
			log.Error("metrics listener stopped", zap.Error(err))
		}
	}()
	go srv.WatchCert(ctx)
	queueDone := make(chan struct{})
	go func() { q.Run(ctx); close(queueDone) }()

	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	for s := range sig {
		if s != syscall.SIGHUP {
			log.Info("shutting down", zap.Stringer("signal", s))
			break
		}
		if err := srv.ReloadCert(); err != nil {
			log.Error("TLS certificate reload failed, keeping the previous one", zap.Error(err))
		}
	}

	// Stop accepting, let open sessions and in-flight deliveries finish.
	// Whatever is left stays in SQLite for the next start.
	graceCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	if err := srv.Shutdown(graceCtx); err != nil {
		log.Warn("SMTP sessions cut off at shutdown", zap.Error(err))
	}
	stop()
	select {
	case <-queueDone:
	case <-graceCtx.Done():
		log.Warn("deliveries still running at shutdown; they will be retried after restart")
	}
	if err := stopTracing(graceCtx); err != nil {
		log.Warn("flush traces", zap.Error(err))
	}
	log.Info("stopped")
	return nil
}

// healthcheck asks the running daemon's /healthz; it is the container
// HEALTHCHECK, so the image needs no curl or wget.
func (a *app) healthcheck() error {
	host, port, err := net.SplitHostPort(a.cfg.MetricsListen)
	if err != nil {
		return fmt.Errorf("METRICS_LISTEN: %w", err)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + net.JoinHostPort(host, port) + "/healthz") //nolint:noctx // bounded by the client timeout
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck // nothing was read
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unhealthy: HTTP %d", resp.StatusCode)
	}
	return nil
}

// sendTest queues a signed test message through the same queue the daemon
// reads, so it also proves DKIM and delivery work.
func (a *app) sendTest(st *store.Store, args []string) error {
	fs := flag.NewFlagSet("send-test", flag.ContinueOnError)
	from := fs.String("from", "", "sender address in a configured domain")
	to := fs.String("to", "", "recipient address")
	if pos, err := a.parse(fs, args); err != nil {
		return err
	} else if len(pos) != 0 || *from == "" || *to == "" {
		return errors.New("usage: outbound-smtp send-test --from sender@example.com --to rcpt@example.org")
	}
	for _, addr := range []string{*from, *to} {
		if a, err := mail.ParseAddress(addr); err != nil || a.Address != addr {
			return fmt.Errorf("invalid address %q (give a bare address)", addr)
		}
	}
	_, domain, err := store.SplitAddress(*from)
	if err != nil {
		return err
	}
	if _, _, err := store.SplitAddress(*to); err != nil {
		return err
	}
	if ok, err := st.DomainExists(domain); err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("%s is not a configured domain; run 'domain add %s' first", domain, domain)
	}
	id := store.NewID()
	host := a.cfg.Hostname
	if host == "" {
		host = domain
	}
	now := time.Now()
	msg := fmt.Sprintf("From: <%s>\r\nTo: <%s>\r\nSubject: outbound-smtp test message %s\r\nDate: %s\r\nMessage-ID: <%s@%s>\r\n"+
		"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"+
		"This is a test message from outbound-smtp, queued at %s with queue ID %s.\r\n"+
		"If it arrived, check that the receiving server reports dkim=pass for %s.\r\n",
		*from, *to, id, now.Format("Mon, 02 Jan 2006 15:04:05 -0700"), strings.ToLower(id), host, now.UTC().Format(time.RFC3339), id, domain)
	signed, err := dkim.Signer{Store: st}.Sign(domain, []byte(msg))
	if err != nil {
		return fmt.Errorf("%w (run 'dkim generate %s' first)", err, domain)
	}
	if err := st.Enqueue(store.Message{ID: id, EnvelopeFrom: *from, FromDomain: domain, Source: store.SourceInternal,
		SourceIdent: "send-test", Body: signed}, []string{*to}); err != nil {
		return err
	}
	fmt.Fprintf(a.out, "queued test message %s\nThe running daemon picks it up within a few seconds; follow it with 'outbound-smtp queue list' or the logs.\n", id)
	return nil
}
