package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/DevHatRo/outbound-smtp/internal/password"
	"github.com/DevHatRo/outbound-smtp/internal/store"
)

func when(unix int64) string {
	if unix == 0 {
		return "-"
	}
	return time.Unix(unix, 0).UTC().Format(time.RFC3339)
}

func orAny(items []string) string {
	if len(items) == 0 {
		return "(any configured domain)"
	}
	return strings.Join(items, ",")
}

func rateText(r *int) string {
	if r == nil {
		return "default"
	}
	return fmt.Sprintf("%d/h", *r)
}

// rateFlag turns --rate into the stored override; 0 means the global default.
func rateFlag(n int) (*int, error) {
	if n < 0 {
		return nil, fmt.Errorf("--rate %d: want a positive number, or 0 for the global default", n)
	}
	if n == 0 {
		return nil, nil
	}
	return &n, nil
}

// ---- domain ----

func (a *app) domain(st *store.Store, args []string) error {
	fs := flag.NewFlagSet("domain", flag.ContinueOnError)
	verb, pos, err := a.sub("domain", fs, args, map[string]int{"add": 1, "list": 0, "remove": 1})
	if err != nil {
		return err
	}
	if verb == "list" {
		domains, err := st.ListDomains()
		if err != nil {
			return err
		}
		return a.table("DOMAIN\tDKIM\tCREATED", func(w io.Writer) {
			for _, d := range domains {
				dkim := "NO ACTIVE KEY"
				if k, err := st.ActiveDKIMKey(d.Name); err == nil {
					dkim = k.Selector + " (" + k.Algorithm + ")"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\n", d.Name, dkim, when(d.CreatedAt))
			}
		})
	}
	name, err := store.NormalizeDomain(pos[0])
	if err != nil {
		return err
	}
	if verb == "remove" {
		if err := st.RemoveDomain(name); err != nil {
			return fmt.Errorf("domain %s: %w", name, err)
		}
		fmt.Fprintf(a.out, "removed domain %s and its DKIM keys\n", name)
		return nil
	}
	if err := st.AddDomain(name); err != nil {
		return fmt.Errorf("domain %s: %w", name, err)
	}
	fmt.Fprintf(a.out, "added domain %s\nnext: outbound-smtp dkim generate %s\n", name, name)
	return nil
}

// ---- user ----

// senderPattern normalises "example.com" or "app@example.com".
func senderPattern(p string) (string, error) {
	if strings.Contains(p, "@") {
		local, domain, err := store.SplitAddress(p)
		if err != nil {
			return "", err
		}
		return strings.ToLower(local) + "@" + domain, nil
	}
	return store.NormalizeDomain(p)
}

func (a *app) user(st *store.Store, args []string) error {
	fs := flag.NewFlagSet("user", flag.ContinueOnError)
	var allow list
	fs.Var(&allow, "allow", "restrict the user to this sender domain or address (repeatable)")
	rate := fs.Int("rate", 0, "recipients per hour (0 = global default)")
	fromStdin := fs.Bool("password-stdin", false, "read the password from the first line of stdin")
	generate := fs.Bool("generate", false, "generate a random password and print it once")
	verb, pos, err := a.sub("user", fs, args, map[string]int{"add": 1, "list": 0, "remove": 1, "passwd": 1})
	if err != nil {
		return err
	}
	switch verb {
	case "list":
		users, err := st.ListUsers()
		if err != nil {
			return err
		}
		return a.table("USERNAME\tALLOWED SENDERS\tRATE\tCREATED", func(w io.Writer) {
			for _, u := range users {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", u.Username, orAny(u.SenderPatterns()), rateText(u.RatePerHour), when(u.CreatedAt))
			}
		})
	case "remove":
		if err := st.RemoveUser(pos[0]); err != nil {
			return fmt.Errorf("user %s: %w", pos[0], err)
		}
		fmt.Fprintf(a.out, "removed user %s\n", pos[0])
		return nil
	}

	username := pos[0]
	if username == "" || strings.ContainsAny(username, " \t\r\n\x00") {
		return fmt.Errorf("invalid username %q", username)
	}
	// Accepting these and changing only the password would leave the operator
	// believing the user is now restricted.
	rateGiven := false // "--rate 0" is a request too, and passwd cannot honour it
	fs.Visit(func(f *flag.Flag) { rateGiven = rateGiven || f.Name == "rate" })
	if verb == "passwd" && (len(allow) > 0 || rateGiven) {
		return errors.New("user passwd only changes the password: --allow and --rate are set by 'user add' (remove and add the user to change them)")
	}
	userRate, err := rateFlag(*rate)
	if err != nil {
		return err
	}
	var senders []string
	for _, p := range allow {
		norm, err := senderPattern(p)
		if err != nil {
			return fmt.Errorf("--allow %s: %w", p, err)
		}
		senders = append(senders, norm)
		domain := norm[strings.LastIndexByte(norm, '@')+1:]
		if ok, err := st.DomainExists(domain); err == nil && !ok {
			fmt.Fprintf(a.errw, "warning: %s is not a configured domain yet; mail from it is rejected until you run 'domain add %s'\n", domain, domain)
		}
	}
	if verb == "passwd" {
		if _, err := st.GetUser(username); err != nil {
			return fmt.Errorf("user %s: %w", username, err)
		}
	}
	pw, err := a.readPassword(*fromStdin, *generate)
	if err != nil {
		return err
	}
	hash, err := password.Hash(pw)
	if err != nil {
		return err
	}
	if verb == "passwd" {
		err = st.SetPassword(username, hash)
	} else {
		err = st.AddUser(username, hash, userRate, senders)
	}
	if err != nil {
		return fmt.Errorf("user %s: %w", username, err)
	}
	if *generate {
		fmt.Fprintf(a.out, "password for %s (shown once): %s\n", username, pw)
	} else {
		fmt.Fprintf(a.out, "saved user %s\n", username)
	}
	return nil
}

// readPassword never takes the password from argv, where it would leak into
// shell history and the process list.
func (a *app) readPassword(fromStdin, generate bool) (string, error) {
	if generate {
		return password.Generate()
	}
	var pw string
	if fromStdin {
		line, err := bufio.NewReader(a.in).ReadString('\n')
		if err != nil && line == "" {
			return "", fmt.Errorf("read password from stdin: %w", err)
		}
		pw = strings.TrimRight(line, "\r\n")
	} else {
		f, ok := a.in.(*os.File)
		if !ok || !term.IsTerminal(int(f.Fd())) {
			return "", errors.New("no terminal to prompt on: use --password-stdin or --generate")
		}
		fmt.Fprint(a.errw, "Password: ")
		first, err := term.ReadPassword(int(f.Fd()))
		fmt.Fprint(a.errw, "\nRepeat password: ")
		second, err2 := term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(a.errw)
		if err := errors.Join(err, err2); err != nil {
			return "", err
		}
		if string(first) != string(second) {
			return "", errors.New("passwords do not match")
		}
		pw = string(first)
	}
	if len(pw) < password.MinLength {
		return "", fmt.Errorf("password must be at least %d characters", password.MinLength)
	}
	return pw, nil
}

// ---- network ----

// Docker's default address pools. When the daemon runs behind Docker's
// userland proxy or Docker Desktop, every outside client can appear to come
// from the bridge gateway inside these ranges.
var dockerPools = []netip.Prefix{netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16")}

func parseCIDR(s string) (netip.Prefix, error) {
	if !strings.Contains(s, "/") {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid CIDR or IP %q", s)
		}
		addr = addr.Unmap()
		return netip.PrefixFrom(addr, addr.BitLen()), nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid CIDR %q", s)
	}
	// Clients are matched by their IPv4 address, so store "::ffff:a.b.c.d/n" as IPv4.
	if p.Addr().Is4In6() {
		if p.Bits() < 96 {
			return netip.Prefix{}, fmt.Errorf("invalid CIDR %q", s)
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96).Masked()
	}
	// A /8 is already a large slice of IPv4; the same number of bits in IPv6
	// would cover a 256th of the whole address space.
	minBits, family := 8, "IPv4"
	if p.Addr().Is6() {
		minBits, family = 32, "IPv6"
	}
	if p.Bits() < minBits {
		return netip.Prefix{}, fmt.Errorf("%s is too broad to trust: trusted networks relay without authentication (minimum prefix length is /%d for %s)",
			s, minBits, family)
	}
	return p.Masked(), nil
}

func (a *app) network(st *store.Store, args []string) error {
	fs := flag.NewFlagSet("network", flag.ContinueOnError)
	var domains list
	fs.Var(&domains, "domain", "restrict the network to this sending domain (repeatable)")
	rate := fs.Int("rate", 0, "recipients per hour (0 = global default)")
	verb, pos, err := a.sub("network", fs, args, map[string]int{"add": 1, "list": 0, "remove": 1})
	if err != nil {
		return err
	}
	if verb == "list" {
		nets, err := st.ListNetworks()
		if err != nil {
			return err
		}
		return a.table("CIDR\tALLOWED DOMAINS\tRATE\tCREATED", func(w io.Writer) {
			for _, n := range nets {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", n.CIDR, orAny(n.DomainNames()), rateText(n.RatePerHour), when(n.CreatedAt))
			}
		})
	}
	cidr, err := parseCIDR(pos[0])
	if err != nil {
		return err
	}
	if verb == "remove" {
		if err := st.RemoveNetwork(cidr); err != nil {
			return fmt.Errorf("network %s: %w", cidr, err)
		}
		fmt.Fprintf(a.out, "removed network %s\n", cidr)
		return nil
	}
	var names []string
	for _, d := range domains {
		name, err := store.NormalizeDomain(d)
		if err != nil {
			return err
		}
		names = append(names, name)
	}
	netRate, err := rateFlag(*rate)
	if err != nil {
		return err
	}
	if err := st.AddNetwork(cidr, netRate, names); err != nil {
		return fmt.Errorf("network %s: %w", cidr, err)
	}
	fmt.Fprintf(a.out, "trusted network %s: clients in it relay WITHOUT authentication\n", cidr)
	for _, pool := range dockerPools {
		if pool.Overlaps(cidr) {
			fmt.Fprintf(a.errw, "warning: %s overlaps a default Docker address pool (%s). If it includes the Docker bridge gateway and "+
				"Docker hides client addresses (userland proxy, Docker Desktop), every host on the internet is trusted. See the README.\n", cidr, pool)
			break
		}
	}
	return nil
}

// ---- queue ----

func (a *app) queue(st *store.Store, args []string) error {
	fs := flag.NewFlagSet("queue", flag.ContinueOnError)
	all := fs.Bool("all", false, "retry: every queued message")
	raw := fs.Bool("raw", false, "show: print the raw message instead of the summary")
	verb, pos, err := a.sub("queue", fs, args, map[string]int{"list": 0, "show": 1, "retry": -1, "delete": 1})
	if err != nil {
		return err
	}
	switch verb {
	case "list":
		rcpts, err := st.ListRecipients("")
		if err != nil {
			return err
		}
		return a.table("ID\tQUEUED\tFROM\tRECIPIENT\tSTATE\tTRIES\tNEXT ATTEMPT\tLAST ERROR", func(w io.Writer) {
			for _, r := range rcpts {
				from, queued := "?", int64(0)
				if r.Message != nil {
					from, queued = r.Message.EnvelopeFrom, r.Message.CreatedAt
				}
				if from == "" {
					from = "<>"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\n", r.MessageID, when(queued), from, r.Address, r.State,
					r.Attempts, when(r.NextAttemptAt), r.LastError)
			}
		})
	case "show":
		m, err := st.GetMessage(pos[0])
		if err != nil {
			return fmt.Errorf("message %s: %w", pos[0], err)
		}
		if *raw {
			_, err := a.out.Write(m.Body)
			return err
		}
		rcpts, err := st.ListRecipients(m.ID)
		if err != nil {
			return err
		}
		fmt.Fprintf(a.out, "ID:        %s\nQueued:    %s\nFrom:      <%s>\nDomain:    %s\nSource:    %s (%s)\nSize:      %d bytes\n\n",
			m.ID, when(m.CreatedAt), m.EnvelopeFrom, m.FromDomain, m.Source, m.SourceIdent, m.Size)
		return a.table("RECIPIENT\tSTATE\tTRIES\tNEXT ATTEMPT\tLAST ERROR", func(w io.Writer) {
			for _, r := range rcpts {
				fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\n", r.Address, r.State, r.Attempts, when(r.NextAttemptAt), r.LastError)
			}
		})
	case "retry":
		if *all && len(pos) == 0 {
			if err := st.RetryNow(""); err != nil {
				return err
			}
			fmt.Fprintln(a.out, "all queued recipients are due now")
			return nil
		}
		if *all || len(pos) != 1 {
			return errors.New("queue retry: give one message ID, or --all")
		}
		if err := st.RetryNow(pos[0]); err != nil {
			return fmt.Errorf("message %s: %w", pos[0], err)
		}
		fmt.Fprintf(a.out, "message %s is due now\n", pos[0])
	case "delete":
		if err := st.DeleteMessage(pos[0]); err != nil {
			return fmt.Errorf("message %s: %w", pos[0], err)
		}
		fmt.Fprintf(a.out, "deleted message %s (no bounce is sent)\n", pos[0])
	}
	return nil
}
