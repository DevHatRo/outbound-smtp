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
	for name, bad := range map[string]string{"MAX_MESSAGE_SIZE": "lots", "QUEUE_MAX_AGE": "3 days", "SMTP_ENABLE_PORT25": "maybe",
		"LOG_LEVEL": "chatty", "MAX_RECIPIENTS": "0", "SMARTHOST_USERNAME": "user-without-password"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, bad)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), name) {
				t.Errorf("%s=%q: got %v, want an error naming the variable", name, bad, err)
			}
		})
	}
}
