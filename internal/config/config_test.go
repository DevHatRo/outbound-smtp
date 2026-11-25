package config

import (
	"strings"
	"testing"
	"time"
)

func TestDefaultsAreSafe(t *testing.T) {
	for _, name := range []string{"SMTP_HOSTNAME", "SMTP_ENABLE_PORT25", "TLS_CERT_FILE", "TLS_KEY_FILE", "DATA_DIR", "MAX_MESSAGE_SIZE",
		"QUEUE_MAX_AGE", "SMARTHOST_HOST", "SMARTHOST_USERNAME", "SMARTHOST_PASSWORD", "METRICS_LISTEN", "LOG_LEVEL", "DELIVERY_IPV6"} {
		t.Setenv(name, "")
	}
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.EnablePort25 || c.DeliveryIPv6 || c.SmarthostHost != "" {
		t.Errorf("port 25, IPv6 delivery and smarthost must be off by default: %+v", c)
	}
	if c.MaxMessageSize != 25<<20 || c.QueueMaxAge != 72*time.Hour || c.DataDir != "/data" || c.MetricsListen != ":9090" ||
		c.Listen465 != ":465" || c.Listen587 != ":587" || c.MaxRecipients != 100 {
		t.Errorf("defaults = %+v", c)
	}
	if err := c.ValidateServe(); err == nil || !strings.Contains(err.Error(), "SMTP_HOSTNAME") {
		t.Errorf("serve without hostname: %v", err)
	}
	c.Hostname = "relay.example.com"
	if err := c.ValidateServe(); err == nil || !strings.Contains(err.Error(), "TLS_CERT_FILE") {
		t.Errorf("serve without certificate: %v", err)
	}
	if c.ACMEEnabled {
		t.Error("ACME must be off by default")
	}
}

func TestCertificateSource(t *testing.T) {
	base := func() *Config {
		return &Config{Hostname: "relay.example.com", ACMEEnabled: true, ACMEAgreeTOS: true, ACMEChallenge: "http",
			ACMEDomains: []string{"relay.example.com"}}
	}
	for name, tc := range map[string]struct {
		tweak func(*Config)
		want  string // substring of the error, "" = valid
	}{
		"http challenge":       {func(*Config) {}, ""},
		"dns with cloudflare":  {func(c *Config) { c.ACMEChallenge, c.ACMEDNSProvider = "dns", "cloudflare" }, ""},
		"dns with hetzner":     {func(c *Config) { c.ACMEChallenge, c.ACMEDNSProvider = "dns", "hetzner" }, ""},
		"dns with cpanel":      {func(c *Config) { c.ACMEChallenge, c.ACMEDNSProvider = "dns", "cpanel" }, ""},
		"own certificate":      {func(c *Config) { c.ACMEEnabled, c.TLSCertFile, c.TLSKeyFile = false, "a.crt", "a.key" }, ""},
		"both sources":         {func(c *Config) { c.TLSCertFile, c.TLSKeyFile = "a.crt", "a.key" }, "choose one"},
		"terms not accepted":   {func(c *Config) { c.ACMEAgreeTOS = false }, "ACME_AGREE_TOS"},
		"dns without provider": {func(c *Config) { c.ACMEChallenge = "dns" }, "ACME_DNS_PROVIDER"},
		"unknown provider":     {func(c *Config) { c.ACMEChallenge, c.ACMEDNSProvider = "dns", "route53" }, "ACME_DNS_PROVIDER"},
		"unknown challenge":    {func(c *Config) { c.ACMEChallenge = "tls-alpn" }, "ACME_CHALLENGE"},
		"wildcard":             {func(c *Config) { c.ACMEDomains = []string{"*.example.com"} }, "not a host name"},
		"no domains":           {func(c *Config) { c.ACMEDomains = nil }, "ACME_DOMAINS"},
		"neither source":       {func(c *Config) { c.ACMEEnabled = false }, "ACME_ENABLED=true"},
	} {
		c := base()
		tc.tweak(c)
		err := c.ValidateServe()
		if (tc.want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%s: got %v, want %q", name, err, tc.want)
		}
	}
}

func TestACMEDomainsDefaultToHostname(t *testing.T) {
	t.Setenv("SMTP_HOSTNAME", "relay.example.com")
	t.Setenv("ACME_DOMAINS", "")
	c, err := Load()
	if err != nil || len(c.ACMEDomains) != 1 || c.ACMEDomains[0] != "relay.example.com" {
		t.Fatalf("domains = %v, %v", c.ACMEDomains, err)
	}
	t.Setenv("ACME_DOMAINS", "Relay.Example.com, smtp.example.com")
	if c, _ = Load(); len(c.ACMEDomains) != 2 || c.ACMEDomains[0] != "relay.example.com" || c.ACMEDomains[1] != "smtp.example.com" {
		t.Errorf("domains = %v", c.ACMEDomains)
	}
}

func TestParsing(t *testing.T) {
	t.Setenv("MAX_MESSAGE_SIZE", "10mb")
	t.Setenv("QUEUE_MAX_AGE", "36h")
	t.Setenv("SMTP_ENABLE_PORT25", "true")
	t.Setenv("LOG_LEVEL", "debug")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.MaxMessageSize != 10<<20 || c.QueueMaxAge != 36*time.Hour || !c.EnablePort25 || c.LogLevel.String() != "debug" {
		t.Errorf("parsed = %+v", c)
	}
	for name, bad := range map[string]string{"ACME_DNS_PROPAGATION_WAIT": "soon", "MAX_MESSAGE_SIZE": "lots", "QUEUE_MAX_AGE": "3 days", "SMTP_ENABLE_PORT25": "maybe",
		"LOG_LEVEL": "chatty", "MAX_RECIPIENTS": "0", "SMARTHOST_USERNAME": "user-without-password"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, bad)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), name) {
				t.Errorf("%s=%q: got %v, want an error naming the variable", name, bad, err)
			}
		})
	}
}
