package acmecert

import (
	"context"
	"crypto/tls"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/DevHatRO/outbound-smtp/internal/config"
	"github.com/DevHatRO/outbound-smtp/internal/testutil"
)

type fakeCA struct {
	t      *testing.T
	orders int
	fail   error
	names  []string
	from   time.Time
	until  time.Time
}

// obtain plays the certificate authority: it issues a self-signed pair.
func (f *fakeCA) obtain(context.Context) ([]byte, []byte, error) {
	f.orders++
	if f.fail != nil {
		return nil, nil, f.fail
	}
	certFile, keyFile, err := testutil.WriteCert(f.t.TempDir(), f.from, f.until, f.names...)
	if err != nil {
		f.t.Fatal(err)
	}
	cert, err1 := os.ReadFile(certFile)
	key, err2 := os.ReadFile(keyFile)
	if err := errors.Join(err1, err2); err != nil {
		f.t.Fatal(err)
	}
	return cert, key, nil
}

func setup(t *testing.T) (*Manager, *fakeCA, *time.Time) {
	t.Helper()
	now := time.Now()
	cfg := &config.Config{DataDir: t.TempDir(), ACMEDomains: []string{"relay.example.com"}, ACMEChallenge: "http",
		ACMEDirectoryURL: "https://acme.example.com/directory"}
	m, err := New(cfg, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	ca := &fakeCA{t: t, names: []string{"relay.example.com"}, from: now.Add(-time.Minute), until: now.Add(90 * 24 * time.Hour)}
	m.Obtain = ca.obtain
	m.Now = func() time.Time { return now }
	return m, ca, &now
}

func ensure(t *testing.T, m *Manager) bool {
	t.Helper()
	renewed, err := m.Ensure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return renewed
}

func TestIssueThenRenewInLastThirdOfLifetime(t *testing.T) {
	m, ca, now := setup(t)
	if m.Usable() {
		t.Fatal("no certificate should exist yet")
	}
	if !ensure(t, m) || ca.orders != 1 || !m.Usable() {
		t.Fatalf("first start must issue a certificate (orders=%d)", ca.orders)
	}
	// What was written must be a pair the TLS stack accepts, readable only by us.
	if _, err := tls.LoadX509KeyPair(m.CertFile(), m.KeyFile()); err != nil {
		t.Fatalf("written pair does not load: %v", err)
	}
	for _, f := range []string{m.CertFile(), m.KeyFile()} {
		if fi, err := os.Stat(f); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: mode %v, %v; want 0600", f, fi.Mode().Perm(), err)
		}
	}

	if ensure(t, m) || ca.orders != 1 {
		t.Error("a fresh certificate must not be renewed")
	}
	*now = now.Add(59 * 24 * time.Hour) // 31 days left of 90
	if ensure(t, m) {
		t.Error("renewed with more than a third of the lifetime left")
	}
	*now = now.Add(2 * 24 * time.Hour) // 29 days left
	ca.until = now.Add(90 * 24 * time.Hour)
	if !ensure(t, m) || ca.orders != 2 {
		t.Errorf("not renewed in the last third of the lifetime (orders=%d)", ca.orders)
	}
}

func TestReissueWhenDomainsChange(t *testing.T) {
	m, ca, _ := setup(t)
	ensure(t, m)
	m.cfg.ACMEDomains = []string{"relay.example.com", "smtp.example.com"}
	ca.names = m.cfg.ACMEDomains
	if !ensure(t, m) || ca.orders != 2 {
		t.Error("a certificate missing a configured name must be replaced")
	}
	if ensure(t, m) {
		t.Error("certificate covering every name was requested again")
	}
}

func TestFailedRenewalKeepsTheOldCertificate(t *testing.T) {
	m, ca, now := setup(t)
	ensure(t, m)
	before, _ := os.ReadFile(m.CertFile())

	*now = now.Add(70 * 24 * time.Hour)
	ca.fail = errors.New("rate limited")
	if _, err := m.Ensure(context.Background()); err == nil || !strings.Contains(err.Error(), "rate limited") {
		t.Fatalf("Ensure = %v, want the CA error", err)
	}
	after, _ := os.ReadFile(m.CertFile())
	if string(before) != string(after) || !m.Usable() {
		t.Error("a failed renewal must leave the working certificate in place")
	}

	*now = now.Add(30 * 24 * time.Hour) // past expiry
	if m.Usable() {
		t.Error("an expired certificate is not usable")
	}
}

func TestAccountIsReusedPerCAAndContact(t *testing.T) {
	m, _, _ := setup(t)
	a, err := m.loadAccount()
	if err != nil {
		t.Fatal(err)
	}
	if err := m.saveAccount(a); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(m.accountFile()); fi.Mode().Perm() != 0o600 {
		t.Errorf("account file mode = %v, want 0600 (it holds the account key)", fi.Mode().Perm())
	}
	b, _ := m.loadAccount()
	if b.KeyPEM != a.KeyPEM || b.GetPrivateKey() == nil {
		t.Error("stored account was not reused")
	}
	m.cfg.ACMEDirectoryURL = "https://staging.example.com/directory"
	if c, _ := m.loadAccount(); c.KeyPEM == a.KeyPEM || c.Registration != nil {
		t.Error("an account must not be reused with a different CA")
	}
}

func TestDNSProvidersNeedTheirCredentials(t *testing.T) {
	for _, name := range config.DNSProviders {
		for _, env := range []string{"CLOUDFLARE_DNS_API_TOKEN", "CLOUDFLARE_API_KEY", "CLOUDFLARE_EMAIL", "CLOUDFLARE_ZONE_API_TOKEN",
			"HETZNER_API_TOKEN", "HETZNER_API_KEY", "CPANEL_USERNAME", "CPANEL_TOKEN", "CPANEL_BASE_URL"} {
			t.Setenv(env, "")
		}
		if _, err := dnsProvider(name); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("%s without credentials: got %v, want an error naming the provider", name, err)
		}
	}
	t.Setenv("CLOUDFLARE_DNS_API_TOKEN", "not-a-real-token")
	t.Setenv("HETZNER_API_TOKEN", "not-a-real-token")
	t.Setenv("CPANEL_USERNAME", "user")
	t.Setenv("CPANEL_TOKEN", "not-a-real-token")
	t.Setenv("CPANEL_BASE_URL", "https://cpanel.example.com:2083")
	for _, name := range config.DNSProviders {
		if _, err := dnsProvider(name); err != nil {
			t.Errorf("%s with credentials: %v", name, err)
		}
	}
	if _, err := dnsProvider("route53"); err == nil {
		t.Error("unknown provider must fail")
	}
}
