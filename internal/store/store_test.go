package store

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s
}

func TestOpenIsIdempotentAndPrivate(t *testing.T) {
	dir := t.TempDir()
	for range 2 { // second Open must not re-run migrations
		s, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}
	fi, err := os.Stat(filepath.Join(dir, "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("database mode = %v, want 0600", fi.Mode().Perm())
	}
}

func TestFreshInstallIsEmpty(t *testing.T) {
	s := open(t)
	d, _ := s.ListDomains()
	u, _ := s.ListUsers()
	n, _ := s.ListNetworks()
	if len(d)+len(u)+len(n) != 0 {
		t.Fatalf("fresh database is not empty: %v %v %v", d, u, n)
	}
}

func TestDomains(t *testing.T) {
	s := open(t)
	if err := s.AddDomain("example.com"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddDomain("example.com"); !errors.Is(err, ErrExists) {
		t.Errorf("duplicate add = %v, want ErrExists", err)
	}
	if ok, _ := s.DomainExists("example.com"); !ok {
		t.Error("domain should exist")
	}
	if ok, _ := s.DomainExists("mail.example.com"); ok {
		t.Error("subdomain must not match implicitly")
	}
	if err := s.RemoveDomain("example.org"); !errors.Is(err, ErrNotFound) {
		t.Errorf("remove missing = %v, want ErrNotFound", err)
	}
}

func TestUsers(t *testing.T) {
	s := open(t)
	rate := 5
	if err := s.AddUser("app", "hash", &rate, []string{"example.com", "a@example.org", "example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddUser("app", "hash", nil, nil); !errors.Is(err, ErrExists) {
		t.Errorf("duplicate add = %v, want ErrExists", err)
	}
	u, err := s.GetUser("app")
	if err != nil {
		t.Fatal(err)
	}
	if got := u.SenderPatterns(); len(got) != 2 || got[0] != "a@example.org" || got[1] != "example.com" {
		t.Errorf("senders = %v", got)
	}
	if u.RatePerHour == nil || *u.RatePerHour != 5 {
		t.Errorf("rate = %v", u.RatePerHour)
	}
	if err := s.SetPassword("app", "new"); err != nil {
		t.Fatal(err)
	}
	if u, _ = s.GetUser("app"); u.PasswordHash != "new" {
		t.Errorf("hash = %q", u.PasswordHash)
	}
	if err := s.RemoveUser("app"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetUser("app"); !errors.Is(err, ErrNotFound) {
		t.Errorf("get removed = %v, want ErrNotFound", err)
	}
}

func TestNetworks(t *testing.T) {
	s := open(t)
	if err := s.AddDomain("example.com"); err != nil {
		t.Fatal(err)
	}
	p := netip.MustParsePrefix("192.0.2.77/24") // host bits are masked off
	if err := s.AddNetwork(p, nil, []string{"example.org"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown domain = %v, want ErrNotFound", err)
	}
	if err := s.AddNetwork(p, nil, []string{"example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddNetwork(p, nil, nil); !errors.Is(err, ErrExists) {
		t.Errorf("duplicate add = %v, want ErrExists", err)
	}
	nets, err := s.ListNetworks()
	if err != nil || len(nets) != 1 {
		t.Fatalf("list = %v, %v", nets, err)
	}
	if nets[0].CIDR != "192.0.2.0/24" || len(nets[0].DomainNames()) != 1 {
		t.Errorf("network = %+v", nets[0])
	}
	// Removing the domain must not leave the network unrestricted by accident:
	// the link row goes, which the relay rules treat separately (see smtpd).
	if doms, _ := s.ListDomains(); len(doms) != 1 {
		t.Errorf("AddNetwork must not duplicate domains: %v", doms)
	}
	if err := s.RemoveNetwork(p); err != nil {
		t.Fatal(err)
	}
}

func TestDKIMKeys(t *testing.T) {
	s := open(t)
	if err := s.AddDKIMKey("example.com", "s1", "rsa", []byte("k1")); !errors.Is(err, ErrNotFound) {
		t.Errorf("key for unknown domain = %v, want ErrNotFound", err)
	}
	if err := s.AddDomain("example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ActiveDKIMKey("example.com"); !errors.Is(err, ErrNotFound) {
		t.Errorf("no key = %v, want ErrNotFound", err)
	}
	for _, sel := range []string{"s1", "s2"} {
		if err := s.AddDKIMKey("example.com", sel, "rsa", []byte(sel)); err != nil {
			t.Fatal(err)
		}
	}
	if k, _ := s.ActiveDKIMKey("example.com"); k.Selector != "s1" {
		t.Errorf("first key should be active, got %q", k.Selector)
	}
	if err := s.ActivateDKIMKey("example.com", "s2"); err != nil {
		t.Fatal(err)
	}
	if k, _ := s.ActiveDKIMKey("example.com"); k.Selector != "s2" || k.Domain != "example.com" {
		t.Errorf("active = %+v", k)
	}
	if err := s.ActivateDKIMKey("example.com", "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("activate missing = %v, want ErrNotFound", err)
	}
	if k, _ := s.ActiveDKIMKey("example.com"); k.Selector != "s2" {
		t.Error("failed activation must roll back and keep the old key active")
	}
	if err := s.RemoveDomain("example.com"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddDomain("example.com"); err != nil {
		t.Fatal(err)
	}
	if keys, _ := s.ListDKIMKeys("example.com"); len(keys) != 0 {
		t.Errorf("keys must cascade with the domain, got %d", len(keys))
	}
}

func TestQueue(t *testing.T) {
	s := open(t)
	m := Message{ID: "Q1", EnvelopeFrom: "a@example.com", FromDomain: "example.com", Source: SourceAuth, SourceIdent: "app", Body: []byte("body")}
	if err := s.Enqueue(m, nil); err == nil {
		t.Error("enqueue without recipients must fail")
	}
	if err := s.Enqueue(m, []string{"x@example.org", "y@Example.NET"}); err != nil {
		t.Fatal(err)
	}
	st, _ := s.QueueStats()
	if st.Pending != 2 || st.Deferred != 0 || st.Oldest == 0 {
		t.Errorf("stats = %+v", st)
	}
	due, err := s.DueRecipients(time.Now(), 10)
	if err != nil || len(due) != 2 {
		t.Fatalf("due = %v, %v", due, err)
	}
	if due[1].Domain != "example.net" || due[0].Message == nil || due[0].Message.EnvelopeFrom != "a@example.com" {
		t.Errorf("due[1] = %+v", due[1])
	}
	if len(due[0].Message.Body) != 0 {
		t.Error("DueRecipients must not load message bodies")
	}

	if err := s.RecipientDefer(due[0].ID, time.Now().Add(time.Hour), "451 try later"); err != nil {
		t.Fatal(err)
	}
	if due, _ = s.DueRecipients(time.Now(), 10); len(due) != 1 {
		t.Fatalf("after defer, due = %d, want 1", len(due))
	}
	if st, _ = s.QueueStats(); st.Pending != 1 || st.Deferred != 1 {
		t.Errorf("stats = %+v", st)
	}
	if err := s.RetryNow("Q1"); err != nil {
		t.Fatal(err)
	}
	if due, _ = s.DueRecipients(time.Now(), 10); len(due) != 2 || due[0].Attempts+due[1].Attempts != 1 {
		t.Fatalf("after retry, due = %+v", due)
	}

	if err := s.RecipientDone(due[0]); err != nil {
		t.Fatal(err)
	}
	if got, err := s.GetMessage("Q1"); err != nil || string(got.Body) != "body" || got.Size != 4 {
		t.Fatalf("message must stay while recipients remain: %+v, %v", got, err)
	}
	if err := s.RecipientDone(due[1]); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetMessage("Q1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("message must go with its last recipient, got %v", err)
	}
	if err := s.DeleteMessage("Q1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("delete missing = %v, want ErrNotFound", err)
	}
}

func TestNormalizeDomain(t *testing.T) {
	for in, want := range map[string]string{
		"Example.COM.": "example.com",
		"localhost":    "",
		"-bad.example": "",
		"exa mple.com": "",
		"münchen.de":   "",
		"":             "",
	} {
		got, err := NormalizeDomain(in)
		if got != want || (want == "") != (err != nil) {
			t.Errorf("NormalizeDomain(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}
