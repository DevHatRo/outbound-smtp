package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

// cli runs one command against the DATA_DIR set by the test.
func cli(t *testing.T, stdin string, args ...string) (out, errOut string, code int) {
	t.Helper()
	var o, e bytes.Buffer
	code = run(args, strings.NewReader(stdin), &o, &e)
	return o.String(), e.String(), code
}

func mustCLI(t *testing.T, stdin string, args ...string) string {
	t.Helper()
	out, errOut, code := cli(t, stdin, args...)
	if code != 0 {
		t.Fatalf("%v: exit %d: %s", args, code, errOut)
	}
	return out
}

func TestAdminCLI(t *testing.T) {
	t.Setenv("DATA_DIR", t.TempDir())

	for _, args := range [][]string{{"domain", "list"}, {"user", "list"}, {"network", "list"}, {"queue", "list"}} {
		if out := mustCLI(t, "", args...); strings.Count(out, "\n") != 1 {
			t.Errorf("fresh install: %v should print only a header, got %q", args, out)
		}
	}

	mustCLI(t, "", "domain", "add", "Example.COM")
	if out := mustCLI(t, "", "domain", "list"); !strings.Contains(out, "example.com") || !strings.Contains(out, "NO ACTIVE KEY") {
		t.Errorf("domain list = %q", out)
	}
	if _, _, code := cli(t, "", "domain", "add", "example.com"); code == 0 {
		t.Error("duplicate domain must fail")
	}

	// Flags may come before or after the username.
	mustCLI(t, "a-long-enough-password\n", "user", "add", "app", "--allow", "example.com", "--allow", "Other@Example.ORG", "--password-stdin")
	if out := mustCLI(t, "", "user", "list"); !strings.Contains(out, "example.com,other@example.org") {
		t.Errorf("user list = %q", out)
	}
	if _, errOut, code := cli(t, "short\n", "user", "add", "weak", "--password-stdin"); code == 0 || !strings.Contains(errOut, "at least") {
		t.Errorf("short password accepted: %q", errOut)
	}
	if _, errOut, code := cli(t, "", "user", "add", "nopw"); code == 0 || !strings.Contains(errOut, "--password-stdin") {
		t.Errorf("non-terminal without --password-stdin should explain itself: %q", errOut)
	}
	out := mustCLI(t, "", "user", "passwd", "--generate", "app")
	if !strings.Contains(out, "shown once") {
		t.Errorf("passwd --generate = %q", out)
	}
	if out := mustCLI(t, "", "user", "list"); strings.Contains(out, "argon2") {
		t.Error("user list must not print password hashes")
	}
	if _, _, code := cli(t, "", "user", "passwd", "--generate", "ghost"); code == 0 {
		t.Error("passwd for a missing user must fail")
	}

	mustCLI(t, "", "network", "add", "192.0.2.10", "--domain", "example.com")
	if out := mustCLI(t, "", "network", "list"); !strings.Contains(out, "192.0.2.10/32") {
		t.Errorf("network list = %q", out)
	}
	for _, broad := range []string{"0.0.0.0/0", "::/0", "128.0.0.0/1", "2000::/8", "2001::/16", "2001:db8::/31"} {
		if _, errOut, code := cli(t, "", "network", "add", broad); code == 0 || !strings.Contains(errOut, "too broad") {
			t.Errorf("network add %s must be refused: %q", broad, errOut)
		}
	}
	if _, errOut, _ := cli(t, "", "network", "add", "172.17.0.0/16"); !strings.Contains(errOut, "Docker") {
		t.Errorf("Docker pool should warn: %q", errOut)
	}
	mustCLI(t, "", "network", "remove", "192.0.2.10/32")
	mustCLI(t, "", "network", "add", "2001:db8::/32") // the narrowest IPv6 prefix refused is /31
	mustCLI(t, "", "network", "remove", "2001:db8::/32")

	mustCLI(t, "", "queue", "retry", "--all")
	if _, _, code := cli(t, "", "queue", "retry"); code == 0 {
		t.Error("queue retry without ID or --all must fail")
	}
	if _, _, code := cli(t, "", "queue", "show", "nope"); code == 0 {
		t.Error("queue show for a missing ID must fail")
	}
	if _, _, code := cli(t, "", "bogus"); code == 0 {
		t.Error("unknown command must fail")
	}
	if out := mustCLI(t, "", "version"); !strings.Contains(out, "outbound-smtp dev") {
		t.Errorf("version = %q", out)
	}
}

func TestDKIMCLI(t *testing.T) {
	t.Setenv("DATA_DIR", t.TempDir())
	published := map[string]string{} // fake DNS
	orig := lookupTXT
	lookupTXT = func(_ context.Context, name string) ([]string, error) {
		if v, ok := published[name]; ok {
			return []string{v}, nil
		}
		return nil, errors.New("NXDOMAIN")
	}
	t.Cleanup(func() { lookupTXT = orig })
	// publish copies the "Value:" line of a command's output into the fake DNS.
	publish := func(out, name string) {
		t.Helper()
		_, rest, ok := strings.Cut(out, "Value: ")
		if !ok {
			t.Fatalf("no record in output: %s", out)
		}
		published[name], _, _ = strings.Cut(rest, "\n")
	}

	if _, _, code := cli(t, "", "dkim", "generate", "example.com"); code == 0 {
		t.Fatal("generate for an unconfigured domain must fail")
	}
	mustCLI(t, "", "domain", "add", "example.com")
	out := mustCLI(t, "", "dkim", "generate", "example.com", "--selector", "one")
	if !strings.Contains(out, "one._domainkey.example.com") || !strings.Contains(out, "v=DKIM1; k=rsa; p=") || strings.Contains(out, "PRIVATE") {
		t.Fatalf("generate output: %s", out)
	}
	if _, _, code := cli(t, "", "dkim", "verify", "example.com"); code == 0 {
		t.Error("verify must fail before the record is published")
	}
	publish(out, "one._domainkey.example.com")
	mustCLI(t, "", "dkim", "verify", "example.com")

	// Rotation: step 1 generates an inactive key, step 2 refuses until DNS matches.
	out = mustCLI(t, "", "dkim", "rotate", "example.com", "--algorithm", "ed25519", "--selector", "two")
	if _, _, code := cli(t, "", "dkim", "rotate", "example.com", "--selector", "two"); code == 0 {
		t.Fatal("switching to an unpublished selector must fail")
	}
	if !strings.Contains(out, "Step 1 of 2") || !strings.Contains(out, "k=ed25519") {
		t.Fatalf("rotate step 1 output: %s", out)
	}
	if list := mustCLI(t, "", "domain", "list"); !strings.Contains(list, "one (rsa)") {
		t.Fatalf("the old key must keep signing until DNS is ready: %s", list)
	}
	if _, errOut, code := cli(t, "", "dkim", "rotate", "example.com"); code == 0 || !strings.Contains(errOut, "not switching") {
		t.Fatalf("rotate must refuse an unpublished selector: %s", errOut)
	}
	publish(out, "two._domainkey.example.com")
	mustCLI(t, "", "dkim", "rotate", "example.com")
	if list := mustCLI(t, "", "domain", "list"); !strings.Contains(list, "two (ed25519)") {
		t.Fatalf("rotation did not switch the active key: %s", list)
	}
	if show := mustCLI(t, "", "dkim", "show", "example.com"); strings.Count(show, "selector ") != 2 || strings.Count(show, "ACTIVE") != 1 {
		t.Errorf("show should list both selectors with one active: %s", show)
	}
	// Switching back to a named selector works the same way.
	mustCLI(t, "", "dkim", "rotate", "example.com", "--selector", "one")

	// send-test queues a signed message that the queue commands can inspect.
	if _, _, code := cli(t, "", "send-test", "--from", "app@example.org", "--to", "rcpt@example.org"); code == 0 {
		t.Error("send-test from an unconfigured domain must fail")
	}
	out = mustCLI(t, "", "send-test", "--from", "app@example.com", "--to", "rcpt@example.org")
	id := strings.Fields(strings.TrimPrefix(out, "queued test message "))[0]
	if list := mustCLI(t, "", "queue", "list"); !strings.Contains(list, id) || !strings.Contains(list, "rcpt@example.org") {
		t.Errorf("queue list = %s", list)
	}
	if raw := mustCLI(t, "", "queue", "show", id, "--raw"); !strings.HasPrefix(raw, "DKIM-Signature:") || !strings.Contains(raw, "s=one;") ||
		!strings.Contains(raw, "(DevHatRO SMTP) id "+id+";") {
		t.Errorf("test message lacks the signature of the active selector or the relay identifier:\n%s", raw)
	}
	mustCLI(t, "", "queue", "show", id)
	mustCLI(t, "", "queue", "retry", id)
	mustCLI(t, "", "queue", "delete", id)
	if list := mustCLI(t, "", "queue", "list"); strings.Contains(list, id) {
		t.Error("deleted message still listed")
	}
}

func TestServeRefusesToStartUnconfigured(t *testing.T) {
	t.Setenv("DATA_DIR", t.TempDir())
	t.Setenv("SMTP_HOSTNAME", "")
	if _, errOut, code := cli(t, "", "serve"); code == 0 || !strings.Contains(errOut, "SMTP_HOSTNAME") {
		t.Errorf("serve without hostname: %q", errOut)
	}
	t.Setenv("SMTP_HOSTNAME", "relay.example.com")
	t.Setenv("TLS_CERT_FILE", "")
	if _, errOut, code := cli(t, "", "serve"); code == 0 || !strings.Contains(errOut, "TLS_CERT_FILE") {
		t.Errorf("serve without certificate: %q", errOut)
	}
	t.Setenv("TLS_CERT_FILE", "/nonexistent/tls.crt")
	t.Setenv("TLS_KEY_FILE", "/nonexistent/tls.key")
	if _, errOut, code := cli(t, "", "serve"); code == 0 || !strings.Contains(errOut, "certificate") {
		t.Errorf("serve with a missing certificate file: %q", errOut)
	}
}
