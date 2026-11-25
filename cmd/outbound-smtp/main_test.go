package main

import (
	"bytes"
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
	for _, broad := range []string{"0.0.0.0/0", "::/0", "128.0.0.0/1"} {
		if _, errOut, code := cli(t, "", "network", "add", broad); code == 0 || !strings.Contains(errOut, "too broad") {
			t.Errorf("network add %s must be refused: %q", broad, errOut)
		}
	}
	if _, errOut, _ := cli(t, "", "network", "add", "172.17.0.0/16"); !strings.Contains(errOut, "Docker") {
		t.Errorf("Docker pool should warn: %q", errOut)
	}
	mustCLI(t, "", "network", "remove", "192.0.2.10/32")

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
