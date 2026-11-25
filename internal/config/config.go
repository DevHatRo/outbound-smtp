// Package config reads boot-time configuration from the environment.
package config

import (
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap/zapcore"
)

// Identifier names the software in the Received header of every message.
const Identifier = "DevHatRO SMTP"

// ReceivedHeader returns the Received field (with CRLF) that marks a message
// as handled by this relay. with is the protocol keyword (ESMTPSA, ...), or ""
// for messages the relay generated itself. It carries no client address:
// that would leak internal IPs to recipients.
func ReceivedHeader(hostname, with, queueID string, now time.Time) string {
	if with != "" {
		with = " with " + with
	}
	return fmt.Sprintf("Received: by %s (%s)%s id %s;\r\n\t%s\r\n", hostname, Identifier, with, queueID,
		now.Format("Mon, 02 Jan 2006 15:04:05 -0700"))
}

// Config is the boot-time configuration. Domains, keys, users and networks
// live in SQLite and are managed by the CLI.
type Config struct {
	Hostname     string // SMTP_HOSTNAME
	EnablePort25 bool   // SMTP_ENABLE_PORT25
	// Port25StartTLS offers STARTTLS on port 25. Turn it off for clients
	// that upgrade opportunistically and then reject the certificate.
	Port25StartTLS bool   // SMTP_PORT25_STARTTLS
	Listen465      string // SMTP_LISTEN_465
	Listen587      string // SMTP_LISTEN_587
	Listen25       string // SMTP_LISTEN_25
	TLSCertFile    string // TLS_CERT_FILE
	TLSKeyFile     string // TLS_KEY_FILE
	DataDir        string // DATA_DIR

	// Let's Encrypt (or another ACME CA) instead of TLS_CERT_FILE/TLS_KEY_FILE.
	ACMEEnabled      bool     // ACME_ENABLED
	ACMEAgreeTOS     bool     // ACME_AGREE_TOS
	ACMEEmail        string   // ACME_EMAIL (optional contact address)
	ACMEDomains      []string // ACME_DOMAINS (default: SMTP_HOSTNAME)
	ACMEChallenge    string   // ACME_CHALLENGE: "http" or "dns"
	ACMEHTTPListen   string   // ACME_HTTP_LISTEN
	ACMEDNSProvider  string   // ACME_DNS_PROVIDER: cloudflare, hetzner or cpanel
	ACMEDirectoryURL string   // ACME_DIRECTORY_URL
	// ACMEDNSPropagationWait, when positive, replaces the DNS-01 propagation
	// checks with a fixed wait. For networks that only allow DNS through the
	// local resolver, where the authoritative servers cannot be queried.
	ACMEDNSPropagationWait time.Duration // ACME_DNS_PROPAGATION_WAIT

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

	// LogRecipients adds full recipient addresses to the logs. Off by default:
	// logs then carry the recipient domain only.
	LogRecipients bool // LOG_RECIPIENTS

	MetricsListen string        // METRICS_LISTEN
	LogLevel      zapcore.Level // LOG_LEVEL
}

// Load reads the environment, applying defaults. It does not check the
// settings only the daemon needs; see ValidateServe.
func Load() (*Config, error) {
	l := loader{}
	c := &Config{
		Hostname:       l.str("SMTP_HOSTNAME", ""),
		EnablePort25:   l.boolean("SMTP_ENABLE_PORT25", false),
		Port25StartTLS: l.boolean("SMTP_PORT25_STARTTLS", true),
		Listen465:      l.str("SMTP_LISTEN_465", ":465"),
		Listen587:      l.str("SMTP_LISTEN_587", ":587"),
		Listen25:       l.str("SMTP_LISTEN_25", ":25"),
		TLSCertFile:    l.str("TLS_CERT_FILE", ""),
		TLSKeyFile:     l.str("TLS_KEY_FILE", ""),
		DataDir:        l.str("DATA_DIR", "/data"),

		ACMEEnabled:      l.boolean("ACME_ENABLED", false),
		ACMEAgreeTOS:     l.boolean("ACME_AGREE_TOS", false),
		ACMEEmail:        l.str("ACME_EMAIL", ""),
		ACMEChallenge:    strings.ToLower(l.str("ACME_CHALLENGE", "http")),
		ACMEHTTPListen:   l.str("ACME_HTTP_LISTEN", ":80"),
		ACMEDNSProvider:  strings.ToLower(l.str("ACME_DNS_PROVIDER", "")),
		ACMEDirectoryURL: l.str("ACME_DIRECTORY_URL", "https://acme-v02.api.letsencrypt.org/directory"),

		MaxMessageSize: l.size("MAX_MESSAGE_SIZE", 25<<20),
		MaxRecipients:  l.positive("MAX_RECIPIENTS", 100),
		QueueMaxAge:    l.duration("QUEUE_MAX_AGE", 72*time.Hour),

		SmarthostHost:     l.str("SMARTHOST_HOST", ""),
		SmarthostPort:     l.positive("SMARTHOST_PORT", 587),
		SmarthostUsername: l.str("SMARTHOST_USERNAME", ""),
		SmarthostPassword: os.Getenv("SMARTHOST_PASSWORD"), // not trimmed: spaces can be part of it

		DeliveryConcurrency:          l.positive("DELIVERY_CONCURRENCY", 20),
		DeliveryConcurrencyPerDomain: l.positive("DELIVERY_CONCURRENCY_PER_DOMAIN", 2),
		DeliveryIPv6:                 l.boolean("DELIVERY_IPV6", false),

		MaxConnectionsPerIP:     l.positive("MAX_CONNECTIONS_PER_IP", 10),
		RateLimitUserPerHour:    l.positive("RATE_LIMIT_USER_PER_HOUR", 1000),
		RateLimitNetworkPerHour: l.positive("RATE_LIMIT_NETWORK_PER_HOUR", 1000),
		AuthFailureLimit:        l.positive("AUTH_FAILURE_LIMIT", 5),

		LogRecipients: l.boolean("LOG_RECIPIENTS", false),
		MetricsListen: l.str("METRICS_LISTEN", ":9090"),
	}
	for _, d := range strings.Split(l.str("ACME_DOMAINS", c.Hostname), ",") {
		if d = strings.ToLower(strings.TrimSpace(d)); d != "" {
			c.ACMEDomains = append(c.ACMEDomains, d)
		}
	}
	if os.Getenv("ACME_DNS_PROPAGATION_WAIT") != "" {
		c.ACMEDNSPropagationWait = l.duration("ACME_DNS_PROPAGATION_WAIT", 0)
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
	ownCert := c.TLSCertFile != "" || c.TLSKeyFile != ""
	switch {
	case c.ACMEEnabled && ownCert:
		return fmt.Errorf("choose one certificate source: either TLS_CERT_FILE and TLS_KEY_FILE, or ACME_ENABLED=true")
	case c.ACMEEnabled:
		return c.validateACME()
	case c.TLSCertFile == "" || c.TLSKeyFile == "":
		return fmt.Errorf("a certificate is required, ports 465 and 587 do not run without one: " +
			"set TLS_CERT_FILE and TLS_KEY_FILE, or ACME_ENABLED=true for Let's Encrypt")
	}
	return nil
}

// DNSProviders are the DNS-01 providers built into the binary.
var DNSProviders = []string{"cloudflare", "hetzner", "cpanel"}

func (c *Config) validateACME() error {
	if !c.ACMEAgreeTOS {
		return fmt.Errorf("ACME_AGREE_TOS=true is required: it states that you accept the terms of service of the certificate authority")
	}
	if len(c.ACMEDomains) == 0 {
		return fmt.Errorf("ACME_DOMAINS is empty")
	}
	for _, d := range c.ACMEDomains {
		if strings.ContainsAny(d, "*/: ") || !strings.Contains(d, ".") {
			return fmt.Errorf("ACME_DOMAINS: %q is not a host name (wildcards are not supported)", d)
		}
	}
	switch c.ACMEChallenge {
	case "http":
	case "dns":
		ok := false
		for _, p := range DNSProviders {
			ok = ok || p == c.ACMEDNSProvider
		}
		if !ok {
			return fmt.Errorf("ACME_DNS_PROVIDER must be one of %s, got %q", strings.Join(DNSProviders, ", "), c.ACMEDNSProvider)
		}
	default:
		return fmt.Errorf("ACME_CHALLENGE must be http or dns, got %q", c.ACMEChallenge)
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
	if err != nil || n <= 0 || n > math.MaxInt64/mult {
		// The overflow check matters: a wrapped value of 0 would mean "no limit".
		l.fail(name, fmt.Errorf("want bytes or a value such as 25MB"))
		return def
	}
	return n * mult
}
