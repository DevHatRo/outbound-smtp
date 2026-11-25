package testutil

import (
	"crypto/tls"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/emersion/go-smtp"
)

// Received is one message accepted by a Sink.
type Received struct {
	Helo string
	From string
	To   []string
	Data []byte
	TLS  bool
}

// Sink is a fake remote mail server. Recipients whose local part is "bounce"
// are refused with 550, "defer" with 451 and "full" with the legacy 552;
// everything else is accepted.
type Sink struct {
	Addr string
	// Busy makes the next n MAIL commands fail with 421, as an overloaded
	// server does before it closes the session.
	Busy atomic.Int32

	srv  *smtp.Server
	ln   net.Listener
	mu   sync.Mutex
	msgs []Received
}

// StartSink listens on loopback. A nil tlsCfg means STARTTLS is not offered.
func StartSink(tlsCfg *tls.Config) (*Sink, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &Sink{Addr: ln.Addr().String(), ln: ln}
	s.srv = smtp.NewServer(sinkBackend{s})
	s.srv.Domain = "mx.example.org"
	s.srv.TLSConfig = tlsCfg
	go func() { _ = s.srv.Serve(ln) }() // ends with Close
	return s, nil
}

// Close stops the server.
func (s *Sink) Close() {
	_ = s.ln.Close() // also when Serve has not registered it yet
	_ = s.srv.Close()
}

// Messages returns what was accepted so far.
func (s *Sink) Messages() []Received {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Received(nil), s.msgs...)
}

type sinkBackend struct{ s *Sink }

func (b sinkBackend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	_, isTLS := c.TLSConnectionState()
	return &sinkSession{s: b.s, cur: Received{Helo: c.Hostname(), TLS: isTLS}}, nil
}

type sinkSession struct {
	s   *Sink
	cur Received
}

func (s *sinkSession) Reset()        { s.cur.From, s.cur.To = "", nil }
func (s *sinkSession) Logout() error { return nil }

func (s *sinkSession) Mail(from string, _ *smtp.MailOptions) error {
	if s.s.Busy.Add(-1) >= 0 {
		return &smtp.SMTPError{Code: 421, EnhancedCode: smtp.EnhancedCode{4, 3, 2}, Message: "Too busy, closing"}
	}
	s.cur.From = from
	return nil
}

func (s *sinkSession) Rcpt(to string, _ *smtp.RcptOptions) error {
	switch local, _, _ := strings.Cut(to, "@"); local {
	case "bounce":
		return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 1, 1}, Message: "User unknown"}
	case "full":
		return &smtp.SMTPError{Code: 552, Message: "Too many recipients"}
	case "defer":
		return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 2, 0}, Message: "Try again later"}
	}
	s.cur.To = append(s.cur.To, to)
	return nil
}

func (s *sinkSession) Data(r io.Reader) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	msg := s.cur
	msg.Data = data
	s.s.mu.Lock()
	s.s.msgs = append(s.s.msgs, msg)
	s.s.mu.Unlock()
	return nil
}
