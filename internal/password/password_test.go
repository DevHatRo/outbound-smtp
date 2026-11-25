package password

import (
	"strings"
	"testing"
)

func TestHashVerify(t *testing.T) {
	h, err := Hash("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Errorf("unexpected hash format: %s", h)
	}
	if ok, err := Verify(h, "correct horse battery"); err != nil || !ok {
		t.Errorf("correct password rejected: %v", err)
	}
	if ok, _ := Verify(h, "wrong"); ok {
		t.Error("wrong password accepted")
	}
	h2, _ := Hash("correct horse battery")
	if h == h2 {
		t.Error("salt is not random")
	}
	for _, bad := range []string{"", "plaintext", "$argon2i$v=19$m=1,t=1,p=1$AAAA$AAAA", "$argon2id$v=19$m=x$AAAA$AAAA"} {
		if ok, err := Verify(bad, "x"); ok || err == nil {
			t.Errorf("Verify(%q) = %v, %v; want an error", bad, ok, err)
		}
	}
}

func TestGenerate(t *testing.T) {
	a, _ := Generate()
	b, _ := Generate()
	if len(a) != 24 || a == b {
		t.Errorf("Generate() = %q, %q", a, b)
	}
}
