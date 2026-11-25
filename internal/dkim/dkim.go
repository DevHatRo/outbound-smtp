// Package dkim generates DKIM keys, renders and checks their DNS records, and
// signs outgoing messages.
package dkim

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	msgdkim "github.com/emersion/go-msgauth/dkim"

	"github.com/DevHatRo/outbound-smtp/internal/store"
)

// Key algorithms.
const (
	RSA     = "rsa"     // RSA-2048, the default: verified by every receiver
	Ed25519 = "ed25519" // smaller and faster, but not verified everywhere yet
)

// signedHeaders follows RFC 6376 section 5.4.1. Fields that are absent are
// still listed, which stops anyone adding them to a signed message later.
var signedHeaders = []string{
	"From", "Sender", "Reply-To", "To", "Cc", "Subject", "Date", "Message-ID",
	"In-Reply-To", "References", "MIME-Version", "Content-Type", "Content-Transfer-Encoding",
	"List-Id", "List-Unsubscribe", "List-Unsubscribe-Post",
}

// Generate creates a private key and returns it as PKCS#8 DER.
func Generate(algorithm string) ([]byte, error) {
	var key any
	var err error
	switch algorithm {
	case RSA:
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	case Ed25519:
		_, key, err = ed25519.GenerateKey(rand.Reader)
	default:
		return nil, fmt.Errorf("unknown DKIM algorithm %q (want %s or %s)", algorithm, RSA, Ed25519)
	}
	if err != nil {
		return nil, err
	}
	return x509.MarshalPKCS8PrivateKey(key)
}

func parseKey(der []byte) (crypto.Signer, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse DKIM private key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("DKIM private key cannot sign")
	}
	return signer, nil
}

// Record is the DNS TXT record to publish for a key.
type Record struct {
	Name  string // selector._domainkey.domain
	Value string // v=DKIM1; k=...; p=...
}

// Zone renders the record for a zone file, with the value split into the
// 255-byte strings that DNS requires.
func (r Record) Zone() string {
	var parts []string
	for v := r.Value; len(v) > 0; {
		n := min(len(v), 255)
		parts = append(parts, `"`+v[:n]+`"`)
		v = v[n:]
	}
	return fmt.Sprintf("%s. IN TXT ( %s )", r.Name, strings.Join(parts, " "))
}

// RecordFor returns the DNS record matching a stored key.
func RecordFor(k store.DKIMKey) (Record, error) {
	signer, err := parseKey(k.PrivateKey)
	if err != nil {
		return Record{}, err
	}
	var p []byte
	switch pub := signer.Public().(type) {
	case *rsa.PublicKey:
		if p, err = x509.MarshalPKIXPublicKey(pub); err != nil {
			return Record{}, err
		}
	case ed25519.PublicKey:
		p = pub // RFC 8463: the raw 32-byte key
	default:
		return Record{}, fmt.Errorf("unsupported DKIM key type %T", pub)
	}
	return Record{
		Name:  k.Selector + "._domainkey." + k.Domain,
		Value: fmt.Sprintf("v=DKIM1; k=%s; p=%s", k.Algorithm, base64.StdEncoding.EncodeToString(p)),
	}, nil
}

// LookupTXT resolves TXT records; net.DefaultResolver.LookupTXT fits.
type LookupTXT func(ctx context.Context, name string) ([]string, error)

// tags parses "a=b; c=d" and drops whitespace inside values, which DNS
// tooling is free to insert into the base64 key.
func tags(record string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(record, ";") {
		if k, v, ok := strings.Cut(part, "="); ok {
			out[strings.TrimSpace(k)] = strings.Join(strings.Fields(v), "")
		}
	}
	return out
}

// VerifyDNS checks that the published TXT record matches the stored key.
func VerifyDNS(ctx context.Context, lookup LookupTXT, k store.DKIMKey) error {
	want, err := RecordFor(k)
	if err != nil {
		return err
	}
	txts, err := lookup(ctx, want.Name)
	if err != nil {
		return fmt.Errorf("look up TXT %s: %w", want.Name, err)
	}
	// RFC 6376 allows one TXT record per selector; verifiers fail or behave
	// unpredictably with more, even if one of them is right.
	if len(txts) > 1 {
		return fmt.Errorf("TXT %s has %d records; a DKIM selector must have exactly one", want.Name, len(txts))
	}
	if len(txts) == 0 {
		return fmt.Errorf("TXT %s has no DKIM record", want.Name)
	}
	wantTags, got := tags(want.Value), tags(txts[0])
	if got["p"] == "" {
		return fmt.Errorf("TXT %s has no DKIM record", want.Name)
	}
	if v, ok := got["v"]; ok && v != "DKIM1" {
		return fmt.Errorf("TXT %s has version %q; receivers only accept v=DKIM1", want.Name, v)
	}
	algo := got["k"]
	if algo == "" {
		algo = RSA // RFC 6376: k defaults to rsa
	}
	if got["p"] != wantTags["p"] || algo != wantTags["k"] {
		return fmt.Errorf("TXT %s is published but holds a different key", want.Name)
	}
	return nil
}

// Signer signs messages with the active key of the From domain.
type Signer struct {
	Store *store.Store
}

// Sign returns msg with a DKIM-Signature header prepended (relaxed/relaxed).
func (s Signer) Sign(domain string, msg []byte) ([]byte, error) {
	k, err := s.Store.ActiveDKIMKey(domain)
	if err != nil {
		return nil, err
	}
	signer, err := parseKey(k.PrivateKey)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	out.Grow(len(msg) + 1024)
	err = msgdkim.Sign(&out, bytes.NewReader(msg), &msgdkim.SignOptions{
		Domain:                 domain,
		Selector:               k.Selector,
		Signer:                 signer,
		Hash:                   crypto.SHA256,
		HeaderCanonicalization: msgdkim.CanonicalizationRelaxed,
		BodyCanonicalization:   msgdkim.CanonicalizationRelaxed,
		HeaderKeys:             signedHeaders,
	})
	if err != nil {
		return nil, fmt.Errorf("DKIM sign: %w", err)
	}
	return out.Bytes(), nil
}
