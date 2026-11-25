package smtpd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"
)

// certReloader serves the TLS certificate and reloads it when the files
// change or on SIGHUP, without a restart.
type certReloader struct {
	certFile, keyFile string
	onLoad            func(notAfter time.Time)
	log               *zap.Logger

	mu    sync.RWMutex
	cert  *tls.Certificate
	stamp string // modification times of both files at the last successful load
}

func newCertReloader(certFile, keyFile string, log *zap.Logger, onLoad func(time.Time)) (*certReloader, error) {
	r := &certReloader{certFile: certFile, keyFile: keyFile, log: log, onLoad: onLoad}
	if err := r.load(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *certReloader) fileStamp() string {
	var s string
	for _, f := range []string{r.certFile, r.keyFile} {
		if fi, err := os.Stat(f); err == nil { // Stat follows symlinks, so swapped links are seen
			s += fi.ModTime().String() + fmt.Sprint(fi.Size()) + ";"
		}
	}
	return s
}

// load reads the key pair. On failure the previous certificate stays in use.
func (r *certReloader) load() error {
	stamp := r.fileStamp()
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return fmt.Errorf("load TLS certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse TLS certificate: %w", err)
	}
	if time.Now().After(leaf.NotAfter) {
		return fmt.Errorf("TLS certificate %s expired on %s", r.certFile, leaf.NotAfter.Format(time.RFC3339))
	}
	cert.Leaf = leaf
	r.mu.Lock()
	r.cert, r.stamp = &cert, stamp
	r.mu.Unlock()
	r.onLoad(leaf.NotAfter)
	r.log.Info("TLS certificate loaded", zap.Time("not_after", leaf.NotAfter), zap.Strings("dns_names", leaf.DNSNames))
	return nil
}

func (r *certReloader) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cert, nil
}

// watch polls the files every interval until ctx is done. Polling instead of
// inotify also works on bind mounts and symlink-swapped secrets.
func (r *certReloader) watch(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.mu.RLock()
			changed := r.fileStamp() != r.stamp
			r.mu.RUnlock()
			if changed {
				if err := r.load(); err != nil {
					r.log.Error("TLS certificate reload failed, keeping the previous one", zap.Error(err))
				}
			}
		}
	}
}

func (r *certReloader) tlsConfig() *tls.Config {
	return &tls.Config{GetCertificate: r.getCertificate, MinVersion: tls.VersionTLS12}
}
