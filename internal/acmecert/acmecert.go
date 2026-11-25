// Package acmecert obtains and renews the relay's TLS certificate from
// Let's Encrypt or another ACME certificate authority.
//
// It only writes the certificate and key files; the SMTP server loads them
// exactly like a certificate the operator brings.
package acmecert

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/challenge/dns01"
	"github.com/go-acme/lego/v5/challenge/http01"
	"github.com/go-acme/lego/v5/lego"
	"github.com/go-acme/lego/v5/providers/dns/cloudflare"
	"github.com/go-acme/lego/v5/providers/dns/cpanel"
	"github.com/go-acme/lego/v5/providers/dns/hetzner"
	"github.com/go-acme/lego/v5/registration"
	"go.uber.org/zap"

	"github.com/DevHatRo/outbound-smtp/internal/config"
)

// Manager keeps the certificate in DATA_DIR/acme valid.
type Manager struct {
	cfg *config.Config
	log *zap.Logger
	dir string

	// Obtain requests a new certificate and returns the PEM chain and key.
	// Tests replace it; the default talks to the ACME server.
	Obtain func(ctx context.Context) (certPEM, keyPEM []byte, err error)
	// Now is replaceable for tests.
	Now func() time.Time
}

// New creates the manager and its directory.
func New(cfg *config.Config, log *zap.Logger) (*Manager, error) {
	m := &Manager{cfg: cfg, log: log, dir: filepath.Join(cfg.DataDir, "acme"), Now: time.Now}
	m.Obtain = m.obtain
	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		return nil, fmt.Errorf("create ACME directory: %w", err)
	}
	return m, nil
}

// CertFile is where the certificate chain is written.
func (m *Manager) CertFile() string { return filepath.Join(m.dir, "fullchain.pem") }

// KeyFile is where the private key is written.
func (m *Manager) KeyFile() string { return filepath.Join(m.dir, "privkey.pem") }

// current returns the leaf certificate on disk, or nil when the certificate
// and key do not load as a matching pair (missing, damaged, or mixed up).
func (m *Manager) current() *x509.Certificate {
	pair, err := tls.LoadX509KeyPair(m.CertFile(), m.KeyFile())
	if err != nil {
		return nil
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil
	}
	return cert
}

// Usable reports whether the pair on disk can serve TLS right now.
func (m *Manager) Usable() bool {
	c := m.current()
	return c != nil && !m.Now().Before(c.NotBefore) && m.Now().Before(c.NotAfter)
}

// due reports whether a new certificate is needed, and why.
func (m *Manager) due() (bool, string) {
	c := m.current()
	if c == nil {
		return true, "no usable certificate and key on disk"
	}
	for _, d := range m.cfg.ACMEDomains {
		if c.VerifyHostname(d) != nil {
			return true, "certificate does not cover " + d
		}
	}
	// Renew in the last third of the lifetime: 30 days for a 90-day
	// certificate, and proportionally for shorter-lived ones.
	lifetime := c.NotAfter.Sub(c.NotBefore)
	if m.Now().After(c.NotAfter.Add(-lifetime / 3)) {
		return true, "certificate expires " + c.NotAfter.Format(time.RFC3339)
	}
	return false, ""
}

// Ensure obtains a certificate if none is valid or renewal is due. It
// reports whether the files changed.
func (m *Manager) Ensure(ctx context.Context) (renewed bool, err error) {
	need, why := m.due()
	if !need {
		return false, nil
	}
	m.log.Info("requesting certificate", zap.String("reason", why), zap.Strings("domains", m.cfg.ACMEDomains),
		zap.String("challenge", m.cfg.ACMEChallenge), zap.String("directory", m.cfg.ACMEDirectoryURL))
	certPEM, keyPEM, err := m.Obtain(ctx)
	if err != nil {
		return false, fmt.Errorf("obtain certificate for %v: %w", m.cfg.ACMEDomains, err)
	}
	// Never publish a pair that does not load.
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return false, fmt.Errorf("certificate authority returned an unusable pair: %w", err)
	}
	// Key first, and the certificate only if the key was written. A reader or
	// a restart that catches a mixed pair fails to load it; the server keeps
	// its loaded certificate and this manager requests a fresh pair.
	if err := writeFile(m.KeyFile(), keyPEM); err != nil {
		return false, err
	}
	if err := writeFile(m.CertFile(), certPEM); err != nil {
		return false, err
	}
	if c := m.current(); c != nil {
		m.log.Info("certificate issued", zap.Strings("dns_names", c.DNSNames), zap.Time("not_after", c.NotAfter))
	}
	return true, nil
}

// Run checks twice a day until ctx is done and calls onRenew after each new
// certificate. A failed renewal is logged and retried; the old certificate
// keeps serving until it expires.
func (m *Manager) Run(ctx context.Context, onRenew func()) {
	t := time.NewTicker(12 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			renewed, err := m.Ensure(ctx)
			if err != nil {
				m.log.Error("certificate renewal failed, will retry", zap.Error(err))
			} else if renewed {
				onRenew()
			}
		}
	}
}

// writeFile replaces path atomically with mode 0600.
func writeFile(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ---- ACME account ----

// account is the ACME account, persisted so renewals reuse it.
type account struct {
	Email        string                `json:"email"`
	DirectoryURL string                `json:"directory_url"`
	KeyPEM       string                `json:"key"`
	Registration *acme.ExtendedAccount `json:"registration"`

	key crypto.Signer
}

func (a *account) GetEmail() string                       { return a.Email }
func (a *account) GetRegistration() *acme.ExtendedAccount { return a.Registration }
func (a *account) GetPrivateKey() crypto.Signer           { return a.key }

func (m *Manager) accountFile() string { return filepath.Join(m.dir, "account.json") }

// loadAccount returns the stored account, or a fresh unregistered one when
// there is none or it belongs to another CA or contact address.
func (m *Manager) loadAccount() (*account, error) {
	var a account
	if data, err := os.ReadFile(m.accountFile()); err == nil {
		if json.Unmarshal(data, &a) == nil && a.Email == m.cfg.ACMEEmail && a.DirectoryURL == m.cfg.ACMEDirectoryURL {
			if a.key, err = certcrypto.ParsePEMPrivateKey([]byte(a.KeyPEM)); err == nil {
				return &a, nil
			}
		}
	}
	key, err := certcrypto.GeneratePrivateKey(certcrypto.EC256)
	if err != nil {
		return nil, err
	}
	return &account{Email: m.cfg.ACMEEmail, DirectoryURL: m.cfg.ACMEDirectoryURL,
		KeyPEM: string(certcrypto.PEMEncode(key)), key: key}, nil
}

func (m *Manager) saveAccount(a *account) error {
	data, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(m.accountFile(), data)
}

// dnsProvider builds the DNS-01 provider. Each reads its credentials from
// its own environment variables (see README).
func dnsProvider(name string) (challenge.Provider, error) {
	switch name {
	case "cloudflare":
		return cloudflare.NewDNSProvider()
	case "hetzner":
		return hetzner.NewDNSProvider()
	case "cpanel":
		return cpanel.NewDNSProvider()
	}
	return nil, fmt.Errorf("unknown DNS provider %q", name)
}

// obtain runs one ACME order.
func (m *Manager) obtain(ctx context.Context) (certPEM, keyPEM []byte, err error) {
	acct, err := m.loadAccount()
	if err != nil {
		return nil, nil, err
	}
	lc := lego.NewConfig(acct)
	lc.CADirURL = m.cfg.ACMEDirectoryURL
	client, err := lego.NewClient(lc)
	if err != nil {
		return nil, nil, err
	}
	switch m.cfg.ACMEChallenge {
	case "http":
		host, port, err := net.SplitHostPort(m.cfg.ACMEHTTPListen)
		if err != nil {
			return nil, nil, fmt.Errorf("ACME_HTTP_LISTEN: %w", err)
		}
		// Listens only while a challenge is being answered.
		err = client.Challenge.SetHTTP01Provider(http01.NewProviderServer(host, port))
		if err != nil {
			return nil, nil, err
		}
	case "dns":
		p, err := dnsProvider(m.cfg.ACMEDNSProvider)
		if err != nil {
			return nil, nil, err
		}
		var opts []dns01.ChallengeOption
		if wait := m.cfg.ACMEDNSPropagationWait; wait > 0 {
			// The default checks query the zone's authoritative servers
			// directly, which networks that force a local resolver block.
			opts = append(opts, dns01.PropagationWait(wait, true))
		}
		if err := client.Challenge.SetDNS01Provider(p, opts...); err != nil {
			return nil, nil, err
		}
	}
	if acct.Registration == nil {
		reg, err := client.Registration.Register(ctx, registration.RegisterOptions{TermsOfServiceAgreed: m.cfg.ACMEAgreeTOS})
		if err != nil {
			return nil, nil, fmt.Errorf("register ACME account: %w", err)
		}
		acct.Registration = reg
		if err := m.saveAccount(acct); err != nil {
			return nil, nil, err
		}
	}
	// RSA: some older submission clients and devices cannot verify ECDSA certificates.
	res, err := client.Certificate.Obtain(ctx, certificate.ObtainRequest{Domains: m.cfg.ACMEDomains, Bundle: true, KeyType: certcrypto.RSA2048})
	if err != nil {
		return nil, nil, err
	}
	return res.Certificate, res.PrivateKey, nil
}
