// Command outbound-smtp is an outbound-only SMTP relay with DKIM signing.
// The same binary is the daemon ("serve") and the admin CLI.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"text/tabwriter"

	"github.com/DevHatRo/outbound-smtp/internal/config"
	"github.com/DevHatRo/outbound-smtp/internal/store"
)

// Set at build time with -ldflags "-X main.version=... -X main.commit=...".
var (
	version = "dev"
	commit  = "none"
)

const usage = `outbound-smtp - outbound-only SMTP relay with DKIM signing

Usage:
  outbound-smtp serve
  outbound-smtp version
  outbound-smtp healthcheck          (exit 0 if the running daemon answers /healthz)
  outbound-smtp domain  add|list|remove <domain>
  outbound-smtp dkim    generate|show|verify|rotate <domain> [--selector s] [--algorithm rsa|ed25519] [--force]
  outbound-smtp user    add|passwd <username> [--allow domain-or-address]... [--rate N] [--password-stdin|--generate]
  outbound-smtp user    list|remove <username>
  outbound-smtp network add <cidr> [--domain d]... [--rate N]
  outbound-smtp network list|remove <cidr>
  outbound-smtp queue   list|show <id> [--raw]|retry <id>|retry --all|delete <id>
  outbound-smtp send-test --from sender@example.com --to rcpt@example.org

Configuration comes from the environment (see README). Admin commands only
need DATA_DIR and work while the daemon is running.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// app carries what every command needs.
type app struct {
	in   io.Reader
	out  io.Writer
	errw io.Writer
	cfg  *config.Config
}

func run(args []string, in io.Reader, out, errw io.Writer) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(out, usage)
		return 0
	}
	if args[0] == "version" {
		fmt.Fprintf(out, "outbound-smtp %s (commit %s, %s)\n", version, commit, runtime.Version())
		return 0
	}
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(errw, "configuration error:", err)
		return 2
	}
	a := &app{in: in, out: out, errw: errw, cfg: cfg}
	if err := a.dispatch(args[0], args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(errw, "error:", err)
		return 1
	}
	return 0
}

func (a *app) dispatch(cmd string, args []string) error {
	switch cmd {
	case "serve":
		return a.serve()
	case "healthcheck":
		return a.healthcheck()
	}
	st, err := store.Open(a.cfg.DataDir)
	if err != nil {
		return err
	}
	err = func() error {
		switch cmd {
		case "domain":
			return a.domain(st, args)
		case "user":
			return a.user(st, args)
		case "network":
			return a.network(st, args)
		case "dkim":
			return a.dkim(st, args)
		case "queue":
			return a.queue(st, args)
		case "send-test":
			return a.sendTest(st, args)
		}
		return fmt.Errorf("unknown command %q (run 'outbound-smtp help')", cmd)
	}()
	return errors.Join(err, st.Close())
}

// list is a repeatable string flag.
type list []string

func (l *list) String() string     { return strings.Join(*l, ",") }
func (l *list) Set(v string) error { *l = append(*l, v); return nil }

// parse accepts flags before, between and after positional arguments, which
// the flag package alone does not.
func (a *app) parse(fs *flag.FlagSet, args []string) ([]string, error) {
	fs.SetOutput(a.errw)
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

// sub splits "<verb> [args]" and checks the positional count after flags.
// A wanted count of -1 means "zero or one".
func (a *app) sub(name string, fs *flag.FlagSet, args []string, wantPos map[string]int) (verb string, pos []string, err error) {
	if len(args) == 0 {
		return "", nil, fmt.Errorf("%s: missing subcommand (run 'outbound-smtp help')", name)
	}
	verb = args[0]
	want, ok := wantPos[verb]
	if !ok {
		return "", nil, fmt.Errorf("%s: unknown subcommand %q (run 'outbound-smtp help')", name, verb)
	}
	if pos, err = a.parse(fs, args[1:]); err != nil {
		return "", nil, err
	}
	if want == -1 && len(pos) <= 1 {
		return verb, pos, nil
	}
	if len(pos) != want {
		return "", nil, fmt.Errorf("%s %s: want %d argument(s), got %d", name, verb, want, len(pos))
	}
	return verb, pos, nil
}

func (a *app) table(header string, rows func(w io.Writer)) error {
	w := tabwriter.NewWriter(a.out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, header)
	rows(w)
	return w.Flush()
}
