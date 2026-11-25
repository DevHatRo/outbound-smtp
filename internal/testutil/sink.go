package testutil

import (
	"crypto/tls"
	"io"
	"net"
	"strings"
	"sync"

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
// are refused with 550 and "defer" with 451; everything else is accepted.
type Sink struct {
	Addr string

	srv  *smtp.Server
	mu   sync.Mutex
	msgs []Received
}

// StartSink listens on loopback. A nil tlsCfg means STARTTLS is not offered.
func StartSink(tlsCfg *tls.Config) (*Sink, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &Sink{Addr: ln.Addr().String()}
	s.srv = smtp.NewServer(sinkBackend{s})
	s.srv.Domain = "mx.example.org"
	s.srv.TLSConfig = tlsCfg
	go func() { _ = s.srv.Serve(ln) }() // ends with Close
	return s, nil
}

// Close stops the server.
func (s *Sink) Close() { _ = s.srv.Close() }

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
	s.cur.From = from
	return nil
}

func (s *sinkSession) Rcpt(to string, _ *smtp.RcptOptions) error {
	switch local, _, _ := strings.Cut(to, "@"); local {
	case "bounce":
		return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 1, 1}, Message: "User unknown"}
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
