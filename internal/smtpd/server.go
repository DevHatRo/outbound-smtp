// Package smtpd is the submission side of the relay: listeners, TLS,
// authentication and the rules deciding who may send what.
package smtpd

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/emersion/go-smtp"
	"go.uber.org/zap"

	"github.com/DevHatRO/outbound-smtp/internal/config"
	"github.com/DevHatRO/outbound-smtp/internal/metrics"
	"github.com/DevHatRO/outbound-smtp/internal/password"
	"github.com/DevHatRO/outbound-smtp/internal/store"
)

// Listener names, also used as the "listener" metric label.
const (
	Listener465 = "465" // implicit TLS
	Listener587 = "587" // submission, STARTTLS required
	Listener25  = "25"  // plain SMTP for trusted networks, optional STARTTLS
)

// Signer DKIM-signs a message for a sending domain.
type Signer interface {
	Sign(domain string, msg []byte) ([]byte, error)
}

// Server runs the SMTP listeners.
type Server struct {
	cfg    *config.Config
	st     *store.Store
	signer Signer
	log    *zap.Logger
	m      *metrics.Metrics
	wake   func() // tells the queue a message was committed

	certs   *certReloader
	servers []*smtp.Server
	addrs   map[string]net.Addr

	connMu sync.Mutex
	conns  map[netip.Addr]int

	authFail  *limiters
	msgRate   *limiters
	hashSem   chan struct{} // bounds concurrent argon2 runs (19 MiB each)
	dummyHash string        // verified for unknown users so timing does not reveal them
}

// New loads the TLS certificate and prepares the server. It fails when the
// certificate is missing or invalid: 465 and 587 never run without TLS.
func New(cfg *config.Config, st *store.Store, signer Signer, log *zap.Logger, m *metrics.Metrics, wake func()) (*Server, error) {
	dummy, err := password.Hash(store.NewID())
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg: cfg, st: st, signer: signer, log: log, m: m, wake: wake,
		addrs:     map[string]net.Addr{},
		conns:     map[netip.Addr]int{},
		authFail:  newLimiters(10 * time.Minute),
		msgRate:   newLimiters(time.Hour),
		hashSem:   make(chan struct{}, 4),
		dummyHash: dummy,
	}
	s.certs, err = newCertReloader(cfg.TLSCertFile, cfg.TLSKeyFile, log, func(notAfter time.Time) {
		m.CertExpiry.Set(float64(notAfter.Unix()))
	})
	if err != nil {
		return nil, err
	}
	return s, nil
}

// Start binds the listeners and serves in the background.
func (s *Server) Start() error {
	type spec struct{ name, addr string }
	specs := []spec{{Listener465, s.cfg.Listen465}, {Listener587, s.cfg.Listen587}}
	if s.cfg.EnablePort25 {
		specs = append(specs, spec{Listener25, s.cfg.Listen25})
	}
	for _, sp := range specs {
		tcp, err := net.Listen("tcp", sp.addr)
		if err != nil {
			return errors.Join(fmt.Errorf("listen %s (%s): %w", sp.name, sp.addr, err), s.Shutdown(context.Background()))
		}
		s.addrs[sp.name] = tcp.Addr()
		implicit := sp.name == Listener465
		var ln net.Listener = &limitListener{Listener: tcp, s: s, name: sp.name, implicitTLS: implicit}

		srv := smtp.NewServer(&backend{s: s, listener: sp.name})
		srv.Domain = s.cfg.Hostname
		srv.MaxMessageBytes = s.cfg.MaxMessageSize
		srv.MaxRecipients = s.cfg.MaxRecipients
		srv.ReadTimeout = 5 * time.Minute
		srv.WriteTimeout = time.Minute
		srv.AllowInsecureAuth = false
		srv.ErrorLog = zapPrintf{s.log.With(zap.String("listener", sp.name))}
		if implicit {
			ln = tls.NewListener(ln, s.certs.tlsConfig())
		} else {
			srv.TLSConfig = s.certs.tlsConfig() // offered through STARTTLS
		}
		s.servers = append(s.servers, srv)
		s.log.Info("listening", zap.String("listener", sp.name), zap.Stringer("addr", tcp.Addr()))
		go func() {
			if err := srv.Serve(ln); err != nil && !errors.Is(err, smtp.ErrServerClosed) {
				s.log.Error("SMTP listener stopped", zap.String("listener", sp.name), zap.Error(err))
			}
		}()
	}
	return nil
}

// Addr returns the bound address of a listener, or nil.
func (s *Server) Addr(listener string) net.Addr { return s.addrs[listener] }

// ReloadCert re-reads the certificate files (SIGHUP).
func (s *Server) ReloadCert() error { return s.certs.load() }

// WatchCert reloads the certificate when its files change, until ctx is done.
func (s *Server) WatchCert(ctx context.Context) { s.certs.watch(ctx, 30*time.Second) }

// Shutdown stops accepting and waits for open sessions until ctx expires.
func (s *Server) Shutdown(ctx context.Context) error {
	var errs []error
	for _, srv := range s.servers {
		if err := srv.Shutdown(ctx); err != nil && !errors.Is(err, smtp.ErrServerClosed) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// zapPrintf adapts zap to go-smtp's logger interface.
type zapPrintf struct{ log *zap.Logger }

func (z zapPrintf) Printf(format string, v ...any) { z.log.Warn(fmt.Sprintf(format, v...)) }
func (z zapPrintf) Println(v ...any)               { z.log.Warn(fmt.Sprint(v...)) }

func remoteIP(addr net.Addr) netip.Addr {
	if tcp, ok := addr.(*net.TCPAddr); ok {
		return tcp.AddrPort().Addr().Unmap()
	}
	ap, _ := netip.ParseAddrPort(addr.String()) // zero Addr matches no trusted network
	return ap.Addr().Unmap()
}

// limitListener enforces the per-IP connection limit and counts connections.
type limitListener struct {
	net.Listener
	s           *Server
	name        string
	implicitTLS bool
}

func (l *limitListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ip := remoteIP(c.RemoteAddr())
		l.s.connMu.Lock()
		over := l.s.conns[ip] >= l.s.cfg.MaxConnectionsPerIP
		if !over {
			l.s.conns[ip]++
		}
		l.s.connMu.Unlock()
		if over {
			if !l.implicitTLS { // a plaintext reply would be garbage inside a TLS handshake
				_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
				_, _ = c.Write([]byte("421 4.7.0 Too many connections from your address\r\n"))
			}
			_ = c.Close() // best effort: the client is being turned away
			l.s.log.Info("connection refused", zap.String("reason", "per-IP connection limit"),
				zap.String("listener", l.name), zap.Stringer("client_ip", ip))
			continue
		}
		active := l.s.m.ConnectionsActive.WithLabelValues(l.name)
		active.Inc()
		tc := &trackedConn{Conn: c}
		tc.tls.Store(l.implicitTLS)
		tc.onClose = func() {
			l.s.connMu.Lock()
			if l.s.conns[ip]--; l.s.conns[ip] <= 0 {
				delete(l.s.conns, ip)
			}
			l.s.connMu.Unlock()
			active.Dec()
			l.s.m.Connections.WithLabelValues(l.name, metrics.TLSLabel(tc.tls.Load())).Inc()
		}
		return tc, nil
	}
}

// trackedConn runs onClose exactly once and remembers whether TLS was used.
type trackedConn struct {
	net.Conn
	tls     atomic.Bool
	once    sync.Once
	onClose func()
}

func (c *trackedConn) Close() error {
	c.once.Do(c.onClose)
	return c.Conn.Close()
}

// markTLS records on the underlying tracked connection that TLS is in use.
func markTLS(c net.Conn) {
	if t, ok := c.(*tls.Conn); ok {
		c = t.NetConn()
	}
	if tc, ok := c.(*trackedConn); ok {
		tc.tls.Store(true)
	}
}
