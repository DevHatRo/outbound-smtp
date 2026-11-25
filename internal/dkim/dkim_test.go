package dkim

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	msgdkim "github.com/emersion/go-msgauth/dkim"

	"github.com/DevHatRO/outbound-smtp/internal/store"
)

const message = "From: App <app@example.com>\r\nTo: rcpt@example.org\r\nSubject: hello\r\n" +
	"Date: Thu, 01 Jan 2026 00:00:00 +0000\r\nMessage-ID: <1@example.com>\r\n\r\nHello,  world.\r\n\r\n"

func setup(t *testing.T, algorithm string) (*store.Store, store.DKIMKey) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	der, err := Generate(algorithm)
	if err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(st.AddDomain("example.com"), st.AddDKIMKey("example.com", "sel1", algorithm, der)); err != nil {
		t.Fatal(err)
	}
	k, err := st.ActiveDKIMKey("example.com")
	if err != nil {
		t.Fatal(err)
	}
	return st, k
}

// The signature must verify against the DNS record the CLI tells the admin
// to publish, for both key types.
func TestSignVerifiesAgainstPublishedRecord(t *testing.T) {
	for _, algorithm := range []string{RSA, Ed25519} {
		t.Run(algorithm, func(t *testing.T) {
			st, k := setup(t, algorithm)
			rec, err := RecordFor(k)
			if err != nil {
				t.Fatal(err)
			}
			if rec.Name != "sel1._domainkey.example.com" || !strings.HasPrefix(rec.Value, "v=DKIM1; k="+algorithm+"; p=") {
				t.Fatalf("record = %+v", rec)
			}
			signed, err := Signer{Store: st}.Sign("example.com", []byte(message))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.HasSuffix(signed, []byte(message)) || !bytes.HasPrefix(signed, []byte("DKIM-Signature:")) {
				t.Fatalf("signature must be prepended to the unchanged message:\n%s", signed)
			}
			lookup := func(name string) ([]string, error) {
				if name != rec.Name {
					t.Errorf("verifier looked up %q, want %q", name, rec.Name)
				}
				return []string{rec.Value}, nil
			}
			verify := func(msg []byte) error {
				vs, err := msgdkim.VerifyWithOptions(bytes.NewReader(msg), &msgdkim.VerifyOptions{LookupTXT: lookup})
				if err != nil {
					return err
				}
				if len(vs) != 1 {
					t.Fatalf("signatures = %d, want 1", len(vs))
				}
				if vs[0].Domain != "example.com" {
					t.Errorf("d= %q", vs[0].Domain)
				}
				return vs[0].Err
			}
			if err := verify(signed); err != nil {
				t.Fatalf("signature does not verify: %v", err)
			}
			// relaxed/relaxed survives whitespace changes in transit...
			relaxed := bytes.Replace(signed, []byte("Hello,  world."), []byte("Hello, world.  "), 1)
			if err := verify(relaxed); err != nil {
				t.Errorf("relaxed canonicalization should tolerate whitespace: %v", err)
			}
			// ...but not a changed subject, body, or an added signed header.
			for name, tampered := range map[string][]byte{
				"subject":      bytes.Replace(signed, []byte("Subject: hello"), []byte("Subject: PAY NOW"), 1),
				"body":         bytes.Replace(signed, []byte("world"), []byte("WORLD"), 1),
				"added header": bytes.Replace(signed, []byte("\r\nFrom:"), []byte("\r\nReply-To: evil@example.org\r\nFrom:"), 1),
			} {
				if err := verify(tampered); err == nil {
					t.Errorf("tampered %s still verifies", name)
				}
			}
		})
	}
}

func TestSignNeedsActiveKey(t *testing.T) {
	st, _ := setup(t, Ed25519)
	if _, err := (Signer{Store: st}).Sign("example.org", []byte(message)); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown domain: got %v, want ErrNotFound", err)
	}
	if _, err := Generate("dsa"); err == nil {
		t.Error("unknown algorithm must fail")
	}
}

func TestVerifyDNS(t *testing.T) {
	_, k := setup(t, RSA)
	rec, _ := RecordFor(k)
	other, _ := Generate(RSA)
	otherRec, _ := RecordFor(store.DKIMKey{Domain: "example.com", Selector: "sel1", Algorithm: RSA, PrivateKey: other})
	p := strings.TrimPrefix(rec.Value, "v=DKIM1; k=rsa; p=")

	for name, tc := range map[string]struct {
		txt  []string
		err  error
		want string // substring of the error, "" = success
	}{
		"exact":                {txt: []string{rec.Value}},
		"split and reordered":  {txt: []string{"p=" + p[:100] + " " + p[100:] + " ; v=DKIM1"}}, // k defaults to rsa
		"among other records":  {txt: []string{"v=spf1 -all", rec.Value}},
		"different key":        {txt: []string{otherRec.Value}, want: "different key"},
		"wrong algorithm":      {txt: []string{strings.Replace(rec.Value, "k=rsa", "k=ed25519", 1)}, want: "different key"},
		"no dkim record":       {txt: []string{"v=spf1 -all"}, want: "no DKIM record"},
		"lookup failure":       {err: errors.New("NXDOMAIN"), want: "NXDOMAIN"},
		"revoked (empty p)":    {txt: []string{"v=DKIM1; p="}, want: "no DKIM record"},
		"nothing published":    {want: "no DKIM record"},
		"zone-file whitespace": {txt: []string{strings.ReplaceAll(rec.Value, ";", " ;\t")}},
	} {
		err := VerifyDNS(context.Background(), func(_ context.Context, name string) ([]string, error) {
			if name != "sel1._domainkey.example.com" {
				t.Errorf("looked up %q", name)
			}
			return tc.txt, tc.err
		}, k)
		if (tc.want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%s: got %v, want %q", name, err, tc.want)
		}
	}
}

func TestZoneSplitsLongValues(t *testing.T) {
	_, k := setup(t, RSA)
	rec, _ := RecordFor(k)
	zone := rec.Zone()
	if !strings.HasPrefix(zone, "sel1._domainkey.example.com. IN TXT ( \"v=DKIM1;") {
		t.Errorf("zone = %s", zone)
	}
	var joined string
	for i, part := range strings.Split(zone, `"`) {
		if i%2 == 1 {
			if len(part) > 255 {
				t.Errorf("TXT string of %d bytes exceeds 255", len(part))
			}
			joined += part
		}
	}
	if joined != rec.Value {
		t.Error("split strings do not reassemble into the record value")
	}
}
