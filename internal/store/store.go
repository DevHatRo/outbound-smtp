// Package store holds all configuration and queue state in one SQLite file.
//
// The schema is owned by the embedded SQL migrations; GORM is used for
// queries only (no AutoMigrate).
package store

import (
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/base32"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	_ "modernc.org/sqlite" // pure-Go driver, keeps the binary static
)

//go:embed migrations/*.sql
var migrations embed.FS

// ErrNotFound is returned when a named row does not exist.
var ErrNotFound = errors.New("not found")

// ErrExists is returned when a row with the same unique name already exists.
var ErrExists = errors.New("already exists")

// ErrInUse is returned when a row cannot be removed because another depends on it.
var ErrInUse = errors.New("in use")

// NewID returns a random 16-character queue ID.
func NewID() string {
	b := make([]byte, 10)
	_, _ = rand.Read(b) // crypto/rand.Read never fails (Go 1.24+)
	return base32.StdEncoding.EncodeToString(b)
}

// Store wraps the SQLite database.
type Store struct {
	db  *gorm.DB
	sql *sql.DB
}

// Open opens (creating if needed) the database in dataDir and applies migrations.
func Open(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	path := filepath.Join(dataDir, "relay.db")
	// Create with 0600 up front: the file holds DKIM private keys, and SQLite
	// gives the -wal and -shm files the same mode as the main file.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // DATA_DIR is the operator's choice
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	q := url.Values{}
	q.Add("_pragma", "busy_timeout(10000)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(FULL)") // a 250 reply must survive power loss
	q.Add("_pragma", "foreign_keys(1)")
	q.Set("_txlock", "immediate")
	sqlDB, err := sql.Open("sqlite", "file:"+path+"?"+q.Encode())
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if err := migrate(sqlDB); err != nil {
		return nil, errors.Join(fmt.Errorf("migrate: %w", err), sqlDB.Close())
	}
	db, err := gorm.Open(sqlite.Dialector{Conn: sqlDB}, &gorm.Config{Logger: logger.Discard})
	if err != nil {
		return nil, errors.Join(fmt.Errorf("open gorm: %w", err), sqlDB.Close())
	}
	return &Store{db: db, sql: sqlDB}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.sql.Close() }

// Ping reports whether the database is usable.
func (s *Store) Ping() error { return s.sql.Ping() }

func migrate(db *sql.DB) error {
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, name := range names {
		base := filepath.Base(name)
		prefix, _, _ := strings.Cut(base, "_")
		version, err := strconv.Atoi(prefix)
		if err != nil {
			return fmt.Errorf("migration %s: bad version prefix", base)
		}
		body, err := migrations.ReadFile(name)
		if err != nil {
			return err
		}
		if err := applyMigration(db, version, string(body)); err != nil {
			return fmt.Errorf("%s: %w", base, err)
		}
	}
	return nil
}

func applyMigration(db *sql.DB, version int, body string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }() // no-op after Commit
	var current int
	if err := tx.QueryRow("PRAGMA user_version").Scan(&current); err != nil {
		return err
	}
	if current >= version {
		return nil
	}
	if _, err := tx.Exec(body); err != nil {
		return err
	}
	if _, err := tx.Exec("PRAGMA user_version = " + strconv.Itoa(version)); err != nil {
		return err
	}
	return tx.Commit()
}

func isUnique(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// affected maps "no rows changed" to ErrNotFound.
func affected(res *gorm.DB) error {
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

func notFound(err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrNotFound
	}
	return err
}

// NormalizeDomain lowercases and validates an ASCII domain name.
// Internationalised names must be given in punycode form.
func NormalizeDomain(name string) (string, error) {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if name == "" || len(name) > 253 || !strings.Contains(name, ".") {
		return "", fmt.Errorf("invalid domain %q", name)
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid domain %q", name)
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return "", fmt.Errorf("invalid domain %q (use the punycode form for non-ASCII names)", name)
			}
		}
	}
	return name, nil
}

// SplitAddress splits "local@domain" and lowercases the domain.
func SplitAddress(addr string) (local, domain string, err error) {
	i := strings.LastIndexByte(addr, '@')
	if i <= 0 || i == len(addr)-1 {
		return "", "", fmt.Errorf("invalid address %q", addr)
	}
	domain, err = NormalizeDomain(addr[i+1:])
	return addr[:i], domain, err
}

// ---- domains ----

// Domain is a sending domain. Timestamps are unix seconds.
type Domain struct {
	ID        int64
	Name      string
	CreatedAt int64 `gorm:"autoCreateTime"`
}

// AddDomain registers a sending domain.
func (s *Store) AddDomain(name string) error {
	err := s.db.Create(&Domain{Name: name}).Error
	if isUnique(err) {
		return ErrExists
	}
	return err
}

// RemoveDomain deletes a domain and its DKIM keys. It returns ErrInUse while
// a trusted network is restricted to the domain.
func (s *Store) RemoveDomain(name string) error {
	err := affected(s.db.Where("name = ?", name).Delete(&Domain{}))
	if err != nil && strings.Contains(err.Error(), "FOREIGN KEY constraint failed") {
		return fmt.Errorf("a trusted network is restricted to it, remove that network first: %w", ErrInUse)
	}
	return err
}

// ListDomains returns all sending domains.
func (s *Store) ListDomains() ([]Domain, error) {
	var out []Domain
	return out, s.db.Order("name").Find(&out).Error
}

// DomainExists reports whether name is a configured sending domain.
func (s *Store) DomainExists(name string) (bool, error) {
	var n int64
	err := s.db.Model(&Domain{}).Where("name = ?", name).Count(&n).Error
	return n > 0, err
}

func domainByName(db *gorm.DB, name string) (Domain, error) {
	var d Domain
	err := db.Where("name = ?", name).Take(&d).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return d, fmt.Errorf("domain %s: %w", name, ErrNotFound)
	}
	return d, err
}

// ---- users ----

// User is an SMTP AUTH account.
type User struct {
	ID           int64
	Username     string
	PasswordHash string
	RatePerHour  *int         // nil = global default
	Senders      []UserSender `gorm:"foreignKey:UserID"`
	CreatedAt    int64        `gorm:"autoCreateTime"`
}

// UserSender is one allowed sender of a user: a domain or a full address.
type UserSender struct {
	UserID  int64  `gorm:"primaryKey"`
	Pattern string `gorm:"primaryKey"`
}

// SenderPatterns returns the allowed domains and addresses; empty means any
// configured domain.
func (u User) SenderPatterns() []string {
	out := make([]string, len(u.Senders))
	for i, s := range u.Senders {
		out[i] = s.Pattern
	}
	sort.Strings(out)
	return out
}

// AddUser creates a user, optionally restricted to sender patterns.
func (s *Store) AddUser(username, hash string, rate *int, senders []string) error {
	u := User{Username: username, PasswordHash: hash, RatePerHour: rate}
	seen := map[string]bool{}
	for _, p := range senders {
		if !seen[p] {
			seen[p] = true
			u.Senders = append(u.Senders, UserSender{Pattern: p})
		}
	}
	err := s.db.Create(&u).Error
	if isUnique(err) {
		return ErrExists
	}
	return err
}

// RemoveUser deletes a user.
func (s *Store) RemoveUser(username string) error {
	return affected(s.db.Where("username = ?", username).Delete(&User{}))
}

// SetPassword replaces a user's password hash.
func (s *Store) SetPassword(username, hash string) error {
	return affected(s.db.Model(&User{}).Where("username = ?", username).Update("password_hash", hash))
}

// GetUser returns one user, or ErrNotFound.
func (s *Store) GetUser(username string) (User, error) {
	var u User
	err := s.db.Preload("Senders").Where("username = ?", username).Take(&u).Error
	return u, notFound(err)
}

// ListUsers returns all users.
func (s *Store) ListUsers() ([]User, error) {
	var out []User
	return out, s.db.Preload("Senders").Order("username").Find(&out).Error
}

// ---- networks ----

// Network is a trusted CIDR that may relay without authentication.
type Network struct {
	ID          int64
	CIDR        string   `gorm:"column:cidr"` // canonical netip.Prefix form
	RatePerHour *int     // nil = global default
	Domains     []Domain `gorm:"many2many:network_domains"` // empty = any configured domain
	CreatedAt   int64    `gorm:"autoCreateTime"`
}

// Prefix returns the parsed CIDR.
func (n Network) Prefix() netip.Prefix {
	p, _ := netip.ParsePrefix(n.CIDR) // stored canonical; an invalid value yields a prefix that contains nothing
	return p
}

// DomainNames returns the allowed sending domains; empty means any.
func (n Network) DomainNames() []string {
	out := make([]string, len(n.Domains))
	for i, d := range n.Domains {
		out[i] = d.Name
	}
	sort.Strings(out)
	return out
}

// AddNetwork trusts a CIDR. Every name in domains must be a configured domain.
func (s *Store) AddNetwork(cidr netip.Prefix, rate *int, domains []string) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		n := Network{CIDR: cidr.Masked().String(), RatePerHour: rate}
		seen := map[string]bool{}
		for _, name := range domains {
			if seen[name] {
				continue
			}
			seen[name] = true
			d, err := domainByName(tx, name)
			if err != nil {
				return err
			}
			n.Domains = append(n.Domains, d)
		}
		// Omit("Domains.*") links the existing domains without upserting them.
		err := tx.Omit("Domains.*").Create(&n).Error
		if isUnique(err) {
			return ErrExists
		}
		return err
	})
}

// RemoveNetwork removes a trusted CIDR.
func (s *Store) RemoveNetwork(cidr netip.Prefix) error {
	return affected(s.db.Where("cidr = ?", cidr.Masked().String()).Delete(&Network{}))
}

// ListNetworks returns all trusted networks.
func (s *Store) ListNetworks() ([]Network, error) {
	var out []Network
	return out, s.db.Preload("Domains").Order("cidr").Find(&out).Error
}

// ---- DKIM keys ----

// DKIMKey is one selector of a domain.
type DKIMKey struct {
	ID         int64
	DomainID   int64
	Domain     string `gorm:"-"` // domain name, filled by the store
	Selector   string
	Algorithm  string // "rsa" or "ed25519"
	PrivateKey []byte // PKCS#8 DER
	Active     bool
	CreatedAt  int64 `gorm:"autoCreateTime"`
}

// TableName pins the table name.
func (DKIMKey) TableName() string { return "dkim_keys" }

// AddDKIMKey stores a key. The first key of a domain becomes active.
func (s *Store) AddDKIMKey(domain, selector, algorithm string, privateKey []byte) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		d, err := domainByName(tx, domain)
		if err != nil {
			return err
		}
		var n int64
		if err := tx.Model(&DKIMKey{}).Where("domain_id = ?", d.ID).Count(&n).Error; err != nil {
			return err
		}
		err = tx.Create(&DKIMKey{DomainID: d.ID, Selector: selector, Algorithm: algorithm, PrivateKey: privateKey, Active: n == 0}).Error
		if isUnique(err) {
			return ErrExists
		}
		return err
	})
}

// ActivateDKIMKey makes selector the only active key of domain.
func (s *Store) ActivateDKIMKey(domain, selector string) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		d, err := domainByName(tx, domain)
		if err != nil {
			return err
		}
		if err := tx.Model(&DKIMKey{}).Where("domain_id = ?", d.ID).Update("active", false).Error; err != nil {
			return err
		}
		return affected(tx.Model(&DKIMKey{}).Where("domain_id = ? AND selector = ?", d.ID, selector).Update("active", true))
	})
}

// ListDKIMKeys returns the keys of a domain, newest first.
func (s *Store) ListDKIMKeys(domain string) ([]DKIMKey, error) {
	d, err := domainByName(s.db, domain)
	if err != nil {
		return nil, err
	}
	var out []DKIMKey
	if err := s.db.Where("domain_id = ?", d.ID).Order("id DESC").Find(&out).Error; err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Domain = domain
	}
	return out, nil
}

// ActiveDKIMKey returns the signing key of a domain, or ErrNotFound.
func (s *Store) ActiveDKIMKey(domain string) (DKIMKey, error) {
	keys, err := s.ListDKIMKeys(domain)
	if err != nil {
		return DKIMKey{}, err
	}
	for _, k := range keys {
		if k.Active {
			return k, nil
		}
	}
	return DKIMKey{}, fmt.Errorf("active DKIM key for %s: %w", domain, ErrNotFound)
}

// ---- queue ----

// Message sources.
const (
	SourceAuth     = "auth"
	SourceNetwork  = "network"
	SourceInternal = "internal"
)

// Recipient states.
const (
	StatePending  = "pending"
	StateDeferred = "deferred"
)

// Message is a queued, already signed message.
type Message struct {
	ID           string `gorm:"primaryKey"`
	EnvelopeFrom string // "" for DSNs
	FromDomain   string
	Source       string
	SourceIdent  string
	Size         int64
	Body         []byte
	Traceparent  string // W3C trace context of the accepting span, "" if tracing is off
	CreatedAt    int64  `gorm:"autoCreateTime"`
}

// Recipient is one pending delivery of a message.
type Recipient struct {
	ID            int64
	MessageID     string
	Address       string
	Domain        string
	State         string
	Attempts      int
	NextAttemptAt int64
	LastAttemptAt int64 // 0 if never tried
	LastError     string
	// Message is the parent without its body; set by DueRecipients and ListRecipients.
	Message *Message `gorm:"foreignKey:MessageID"`
}

// Enqueue durably stores a message with its recipients in one transaction.
func (s *Store) Enqueue(m Message, rcpts []string) error {
	if len(rcpts) == 0 {
		return errors.New("no recipients")
	}
	now := time.Now().Unix()
	m.Size = int64(len(m.Body))
	rows := make([]Recipient, 0, len(rcpts))
	for _, r := range rcpts {
		_, domain, err := SplitAddress(r)
		if err != nil {
			return err
		}
		rows = append(rows, Recipient{MessageID: m.ID, Address: r, Domain: domain, State: StatePending, NextAttemptAt: now})
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&m).Error; err != nil {
			return err
		}
		return tx.Create(&rows).Error
	})
}

// withMessage preloads the parent message without its body.
func withMessage(db *gorm.DB) *gorm.DB {
	return db.Preload("Message", func(db *gorm.DB) *gorm.DB {
		return db.Select("id", "envelope_from", "from_domain", "source", "source_ident", "size", "traceparent", "created_at")
	})
}

// DueRecipients returns recipients whose next attempt is due, oldest first.
func (s *Store) DueRecipients(now time.Time, limit int) ([]Recipient, error) {
	var out []Recipient
	err := withMessage(s.db).Where("next_attempt_at <= ?", now.Unix()).Order("next_attempt_at, id").Limit(limit).Find(&out).Error
	return out, err
}

// ListRecipients returns the queue; messageID "" means everything.
func (s *Store) ListRecipients(messageID string) ([]Recipient, error) {
	var out []Recipient
	q := withMessage(s.db).Order("id")
	if messageID != "" {
		q = q.Where("message_id = ?", messageID)
	}
	return out, q.Find(&out).Error
}

// GetMessage loads a queued message including its body.
func (s *Store) GetMessage(id string) (Message, error) {
	var m Message
	err := s.db.Where("id = ?", id).Take(&m).Error
	return m, notFound(err)
}

// RecipientDone removes a finished recipient (delivered or bounced) and the
// message itself once no recipients remain.
func (s *Store) RecipientDone(r Recipient) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Delete(&Recipient{}, r.ID).Error; err != nil {
			return err
		}
		return tx.Where("id = ? AND NOT EXISTS (SELECT 1 FROM recipients WHERE message_id = ?)", r.MessageID, r.MessageID).
			Delete(&Message{}).Error
	})
}

// RecipientDefer records a failed attempt and schedules the next one.
func (s *Store) RecipientDefer(id int64, next time.Time, lastErr string) error {
	return s.db.Model(&Recipient{}).Where("id = ?", id).Updates(map[string]any{
		"state":           StateDeferred,
		"attempts":        gorm.Expr("attempts + 1"),
		"next_attempt_at": next.Unix(),
		"last_attempt_at": time.Now().Unix(),
		"last_error":      lastErr,
	}).Error
}

// RetryNow makes a message (or, with id "", the whole queue) due immediately.
func (s *Store) RetryNow(id string) error {
	q := s.db.Model(&Recipient{})
	if id == "" {
		return q.Where("1 = 1").Update("next_attempt_at", time.Now().Unix()).Error
	}
	return affected(q.Where("message_id = ?", id).Update("next_attempt_at", time.Now().Unix()))
}

// DeleteMessage removes a message and its recipients from the queue.
func (s *Store) DeleteMessage(id string) error {
	return affected(s.db.Where("id = ?", id).Delete(&Message{}))
}

// QueueStats summarises the queue for metrics.
type QueueStats struct {
	Pending  int64
	Deferred int64
	Oldest   int64 // unix seconds of the oldest message, 0 when the queue is empty
}

// QueueStats returns recipient counts by state and the oldest message time.
func (s *Store) QueueStats() (QueueStats, error) {
	var st QueueStats
	err := s.db.Raw(`SELECT
		(SELECT COUNT(*) FROM recipients WHERE state = 'pending') AS pending,
		(SELECT COUNT(*) FROM recipients WHERE state = 'deferred') AS deferred,
		(SELECT COALESCE(MIN(created_at), 0) FROM messages) AS oldest`).Scan(&st).Error
	return st, err
}
