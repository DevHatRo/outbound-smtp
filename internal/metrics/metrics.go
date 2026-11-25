// Package metrics defines the Prometheus metrics and serves /metrics and /healthz.
//
// Label cardinality is bounded on purpose: labels use our own sending domains
// only, never a recipient address or recipient domain.
package metrics

import (
	"context"
	"errors"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds every collector on its own registry.
type Metrics struct {
	Registry *prometheus.Registry

	Connections       *prometheus.CounterVec // listener, tls
	ConnectionsActive *prometheus.GaugeVec   // listener
	AuthAttempts      *prometheus.CounterVec // result
	Accepted          *prometheus.CounterVec // source, domain
	Rejected          *prometheus.CounterVec // reason
	Deliveries        *prometheus.CounterVec // result, tls
	DeliveryDuration  prometheus.Histogram
	DKIMSign          *prometheus.CounterVec // domain, result
	CertExpiry        prometheus.Gauge
}

// Rejection reasons for smtprelay_messages_rejected_total.
const (
	ReasonRelayDenied      = "relay_denied"
	ReasonSenderNotAllowed = "sender_not_allowed"
	ReasonSize             = "size"
	ReasonRateLimit        = "rate_limit"
	ReasonInvalid          = "invalid_message"
)

// New creates the metrics. version is reported by smtprelay_build_info.
func New(version string) *Metrics {
	const ns = "smtprelay"
	m := &Metrics{
		Registry: prometheus.NewRegistry(),
		Connections: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "connections_total",
			Help: "Client connections closed, by listener and whether TLS was established."}, []string{"listener", "tls"}),
		ConnectionsActive: prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "connections_active",
			Help: "Open client connections."}, []string{"listener"}),
		AuthAttempts: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "auth_attempts_total",
			Help: "SMTP AUTH attempts by result (success, failure, blocked)."}, []string{"result"}),
		Accepted: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "messages_accepted_total",
			Help: "Messages accepted into the queue, by source (auth, network) and sending domain."}, []string{"source", "domain"}),
		Rejected: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "messages_rejected_total",
			Help: "Messages or transactions rejected, by reason."}, []string{"reason"}),
		Deliveries: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "deliveries_total",
			Help: "Per-recipient delivery outcomes (delivered, deferred, bounced) and whether TLS was used."}, []string{"result", "tls"}),
		DeliveryDuration: prometheus.NewHistogram(prometheus.HistogramOpts{Namespace: ns, Name: "delivery_duration_seconds",
			Help: "Duration of one delivery attempt to a remote server.", Buckets: []float64{.05, .1, .25, .5, 1, 2.5, 5, 10, 30, 60, 120}}),
		DKIMSign: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "dkim_sign_total",
			Help: "DKIM signing operations by sending domain and result (ok, error)."}, []string{"domain", "result"}),
		CertExpiry: prometheus.NewGauge(prometheus.GaugeOpts{Namespace: ns, Name: "tls_cert_expiry_timestamp_seconds",
			Help: "NotAfter of the loaded TLS certificate as a unix timestamp."}),
	}
	build := prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "build_info",
		Help: "Build information; the value is always 1."}, []string{"version", "go_version"})
	build.WithLabelValues(version, runtime.Version()).Set(1)
	m.Registry.MustRegister(m.Connections, m.ConnectionsActive, m.AuthAttempts, m.Accepted, m.Rejected,
		m.Deliveries, m.DeliveryDuration, m.DKIMSign, m.CertExpiry, build)
	return m
}

// QueueStats is what the queue gauges read at scrape time.
type QueueStats func() (pending, deferred, oldestUnix int64, err error)

var (
	queueDepthDesc = prometheus.NewDesc("smtprelay_queue_depth", "Queued recipients by state; -1 when the queue cannot be read.", []string{"state"}, nil)
	queueAgeDesc   = prometheus.NewDesc("smtprelay_queue_oldest_message_age_seconds", "Age of the oldest queued message; 0 when the queue is empty.", nil, nil)
)

// queueCollector reads the queue once per scrape for all three series.
type queueCollector struct{ stats QueueStats }

func (c queueCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- queueDepthDesc
	ch <- queueAgeDesc
}

func (c queueCollector) Collect(ch chan<- prometheus.Metric) {
	pending, deferred, oldest, err := c.stats()
	age := 0.0
	if err != nil {
		pending, deferred = -1, -1
	} else if oldest != 0 {
		age = time.Since(time.Unix(oldest, 0)).Seconds()
	}
	ch <- prometheus.MustNewConstMetric(queueDepthDesc, prometheus.GaugeValue, float64(pending), "pending")
	ch <- prometheus.MustNewConstMetric(queueDepthDesc, prometheus.GaugeValue, float64(deferred), "deferred")
	ch <- prometheus.MustNewConstMetric(queueAgeDesc, prometheus.GaugeValue, age)
}

// RegisterQueue adds smtprelay_queue_depth and smtprelay_queue_oldest_message_age_seconds.
func (m *Metrics) RegisterQueue(stats QueueStats) {
	m.Registry.MustRegister(queueCollector{stats})
}

// TLSLabel renders a bool as the "tls" label value.
func TLSLabel(tls bool) string { return strconv.FormatBool(tls) }

// Serve runs the unauthenticated HTTP listener with /metrics and /healthz
// until ctx is cancelled. healthy reports whether the daemon can do its job.
func (m *Metrics) Serve(ctx context.Context, ln net.Listener, healthy func() error) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		if err := healthy(); err != nil {
			http.Error(w, "unhealthy", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok\n")) // the client going away is not our problem
	})
	// ReadTimeout also bounds a request body that never arrives.
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 2 * time.Minute}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}
