// Package config reads boot-time configuration from the environment.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap/zapcore"
)

// Config is the boot-time configuration. Domains, keys, users and networks
// live in SQLite and are managed by the CLI.
type Config struct {
	Hostname     string // SMTP_HOSTNAME
	EnablePort25 bool   // SMTP_ENABLE_PORT25
	Listen465    string // SMTP_LISTEN_465
	Listen587    string // SMTP_LISTEN_587
	Listen25     string // SMTP_LISTEN_25
	TLSCertFile  string // TLS_CERT_FILE
	TLSKeyFile   string // TLS_KEY_FILE
	DataDir      string // DATA_DIR

	MaxMessageSize int64         // MAX_MESSAGE_SIZE
	MaxRecipients  int           // MAX_RECIPIENTS
	QueueMaxAge    time.Duration // QUEUE_MAX_AGE

	SmarthostHost     string // SMARTHOST_HOST
	SmarthostPort     int    // SMARTHOST_PORT
	SmarthostUsername string // SMARTHOST_USERNAME
	SmarthostPassword string // SMARTHOST_PASSWORD

	DeliveryConcurrency          int  // DELIVERY_CONCURRENCY
	DeliveryConcurrencyPerDomain int  // DELIVERY_CONCURRENCY_PER_DOMAIN
	DeliveryIPv6                 bool // DELIVERY_IPV6

	MaxConnectionsPerIP     int // MAX_CONNECTIONS_PER_IP
	RateLimitUserPerHour    int // RATE_LIMIT_USER_PER_HOUR
	RateLimitNetworkPerHour int // RATE_LIMIT_NETWORK_PER_HOUR
	AuthFailureLimit        int // AUTH_FAILURE_LIMIT (per IP per 10 minutes)

	MetricsListen string        // METRICS_LISTEN
	LogLevel      zapcore.Level // LOG_LEVEL
}

// Load reads the environment, applying defaults. It does not check the
// settings only the daemon needs; see ValidateServe.
func Load() (*Config, error) {
	l := loader{}
	c := &Config{
		Hostname:     l.str("SMTP_HOSTNAME", ""),
		EnablePort25: l.boolean("SMTP_ENABLE_PORT25", false),
		Listen465:    l.str("SMTP_LISTEN_465", ":465"),
		Listen587:    l.str("SMTP_LISTEN_587", ":587"),
		Listen25:     l.str("SMTP_LISTEN_25", ":25"),
		TLSCertFile:  l.str("TLS_CERT_FILE", ""),
		TLSKeyFile:   l.str("TLS_KEY_FILE", ""),
		DataDir:      l.str("DATA_DIR", "/data"),

		MaxMessageSize: l.size("MAX_MESSAGE_SIZE", 25<<20),
		MaxRecipients:  l.positive("MAX_RECIPIENTS", 100),
		QueueMaxAge:    l.duration("QUEUE_MAX_AGE", 72*time.Hour),

		SmarthostHost:     l.str("SMARTHOST_HOST", ""),
		SmarthostPort:     l.positive("SMARTHOST_PORT", 587),
		SmarthostUsername: l.str("SMARTHOST_USERNAME", ""),
		SmarthostPassword: l.str("SMARTHOST_PASSWORD", ""),

		DeliveryConcurrency:          l.positive("DELIVERY_CONCURRENCY", 20),
		DeliveryConcurrencyPerDomain: l.positive("DELIVERY_CONCURRENCY_PER_DOMAIN", 2),
		DeliveryIPv6:                 l.boolean("DELIVERY_IPV6", false),

		MaxConnectionsPerIP:     l.positive("MAX_CONNECTIONS_PER_IP", 10),
		RateLimitUserPerHour:    l.positive("RATE_LIMIT_USER_PER_HOUR", 1000),
		RateLimitNetworkPerHour: l.positive("RATE_LIMIT_NETWORK_PER_HOUR", 1000),
		AuthFailureLimit:        l.positive("AUTH_FAILURE_LIMIT", 5),

		MetricsListen: l.str("METRICS_LISTEN", ":9090"),
	}
	if err := c.LogLevel.UnmarshalText([]byte(l.str("LOG_LEVEL", "info"))); err != nil {
		l.fail("LOG_LEVEL", err)
	}
	if (c.SmarthostUsername == "") != (c.SmarthostPassword == "") {
		l.fail("SMARTHOST_USERNAME", fmt.Errorf("set both SMARTHOST_USERNAME and SMARTHOST_PASSWORD, or neither"))
	}
	if c.SmarthostUsername != "" && c.SmarthostHost == "" {
		l.fail("SMARTHOST_HOST", fmt.Errorf("required when smarthost credentials are set"))
	}
	return c, l.err
}

// ValidateServe checks the settings the daemon cannot run without.
func (c *Config) ValidateServe() error {
	if c.Hostname == "" {
		return fmt.Errorf("SMTP_HOSTNAME is required (the name this server announces in EHLO; it should match the PTR record of the sending IP)")
	}
	if c.TLSCertFile == "" || c.TLSKeyFile == "" {
		return fmt.Errorf("TLS_CERT_FILE and TLS_KEY_FILE are required: ports 465 and 587 do not run without a certificate")
	}
	return nil
}

type loader struct{ err error }

func (l *loader) fail(name string, err error) {
	if l.err == nil {
		l.err = fmt.Errorf("%s: %w", name, err)
	}
}

func (l *loader) str(name, def string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return def
}

func (l *loader) boolean(name string, def bool) bool {
	v := l.str(name, "")
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		l.fail(name, err)
	}
	return b
}

func (l *loader) positive(name string, def int) int {
	v := l.str(name, "")
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		l.fail(name, fmt.Errorf("want a positive integer, got %q", v))
	}
	return n
}

func (l *loader) duration(name string, def time.Duration) time.Duration {
	v := l.str(name, "")
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		l.fail(name, fmt.Errorf("want a duration such as 72h, got %q", v))
	}
	return d
}

// size parses a byte count with an optional KB, MB or GB suffix (powers of 1024).
func (l *loader) size(name string, def int64) int64 {
	v := strings.ToUpper(l.str(name, ""))
	if v == "" {
		return def
	}
	mult := int64(1)
	for suffix, m := range map[string]int64{"KB": 1 << 10, "MB": 1 << 20, "GB": 1 << 30} {
		if strings.HasSuffix(v, suffix) {
			v, mult = strings.TrimSpace(strings.TrimSuffix(v, suffix)), m
			break
		}
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 {
		l.fail(name, fmt.Errorf("want bytes or a value such as 25MB"))
	}
	return n * mult
}
