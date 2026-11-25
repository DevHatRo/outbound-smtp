package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"time"

	"github.com/DevHatRO/outbound-smtp/internal/dkim"
	"github.com/DevHatRO/outbound-smtp/internal/store"
)

// lookupTXT is replaced in tests.
var lookupTXT dkim.LookupTXT = net.DefaultResolver.LookupTXT

func (a *app) printRecord(k store.DKIMKey) error {
	rec, err := dkim.RecordFor(k)
	if err != nil {
		return err
	}
	state := "inactive"
	if k.Active {
		state = "ACTIVE (signing)"
	}
	fmt.Fprintf(a.out, "selector %s (%s, %s, created %s)\n\n  Name:  %s\n  Type:  TXT\n  Value: %s\n\n  Zone file form:\n  %s\n\n",
		k.Selector, k.Algorithm, state, when(k.CreatedAt), rec.Name, rec.Value, rec.Zone())
	return nil
}

func (a *app) checkDNS(k store.DKIMKey) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return dkim.VerifyDNS(ctx, lookupTXT, k)
}

func findKey(keys []store.DKIMKey, selector string) (store.DKIMKey, error) {
	for _, k := range keys {
		if (selector == "" && k.Active) || (selector != "" && k.Selector == selector) {
			return k, nil
		}
	}
	if selector == "" {
		return store.DKIMKey{}, errors.New("no active DKIM key; run 'dkim generate' first")
	}
	return store.DKIMKey{}, fmt.Errorf("selector %s: %w", selector, store.ErrNotFound)
}

func (a *app) dkim(st *store.Store, args []string) error {
	fs := flag.NewFlagSet("dkim", flag.ContinueOnError)
	selector := fs.String("selector", "", "selector name (default for new keys: sYYYYMMDD)")
	algorithm := fs.String("algorithm", dkim.RSA, "key type for new keys: rsa (2048 bit) or ed25519")
	force := fs.Bool("force", false, "rotate: activate even if the DNS record cannot be verified")
	verb, pos, err := a.sub("dkim", fs, args, map[string]int{"generate": 1, "show": 1, "verify": 1, "rotate": 1})
	if err != nil {
		return err
	}
	domain, err := store.NormalizeDomain(pos[0])
	if err != nil {
		return err
	}
	keys, err := st.ListDKIMKeys(domain) // newest first
	if err != nil {
		return err
	}

	generate := func() (store.DKIMKey, error) {
		sel := *selector
		if sel == "" {
			sel = "s" + time.Now().UTC().Format("20060102")
		}
		if _, err := store.NormalizeDomain(sel + ".example"); err != nil {
			return store.DKIMKey{}, fmt.Errorf("invalid selector %q", sel)
		}
		der, err := dkim.Generate(*algorithm)
		if err != nil {
			return store.DKIMKey{}, err
		}
		if err := st.AddDKIMKey(domain, sel, *algorithm, der); err != nil {
			return store.DKIMKey{}, fmt.Errorf("selector %s: %w (pick another with --selector)", sel, err)
		}
		fresh, err := st.ListDKIMKeys(domain)
		if err != nil {
			return store.DKIMKey{}, err
		}
		return findKey(fresh, sel)
	}

	switch verb {
	case "generate":
		k, err := generate()
		if err != nil {
			return err
		}
		fmt.Fprintf(a.out, "Publish this DNS record for %s:\n\n", domain)
		if err := a.printRecord(k); err != nil {
			return err
		}
		if k.Active {
			fmt.Fprintf(a.out, "This is the first key of %s, so it signs mail from now on.\nCheck the record with: outbound-smtp dkim verify %s\n", domain, domain)
		} else {
			fmt.Fprintf(a.out, "The key is inactive. After publishing the record, switch to it with:\n  outbound-smtp dkim rotate %s --selector %s\n", domain, k.Selector)
		}
	case "show":
		if len(keys) == 0 {
			return fmt.Errorf("%s has no DKIM keys; run 'dkim generate %s'", domain, domain)
		}
		for _, k := range keys {
			if err := a.printRecord(k); err != nil {
				return err
			}
		}
	case "verify":
		k, err := findKey(keys, *selector)
		if err != nil {
			return err
		}
		if err := a.checkDNS(k); err != nil {
			return err
		}
		fmt.Fprintf(a.out, "OK: %s._domainkey.%s matches the stored key\n", k.Selector, domain)
	case "rotate":
		// Rotation is two steps so mail is never signed with a selector that
		// is not in DNS yet: first a new inactive key, then the switch.
		var next store.DKIMKey
		found := false
		if *selector != "" {
			if k, err := findKey(keys, *selector); err == nil {
				next, found = k, true
			}
		} else if len(keys) > 0 && !keys[0].Active {
			next, found = keys[0], true // newest key, generated after the active one
		}
		if !found {
			k, err := generate()
			if err != nil {
				return err
			}
			fmt.Fprintf(a.out, "Step 1 of 2: new key generated. Publish this DNS record for %s:\n\n", domain)
			if err := a.printRecord(k); err != nil {
				return err
			}
			if !k.Active { // the first key of a domain is active at once
				fmt.Fprintf(a.out, "Step 2 of 2: once it is published, run 'outbound-smtp dkim rotate %s' again to start signing with it.\n", domain)
			}
			return nil
		}
		if next.Active {
			fmt.Fprintf(a.out, "selector %s is already active\n", next.Selector)
			return nil
		}
		if err := a.checkDNS(next); err != nil {
			if !*force {
				return fmt.Errorf("not switching to selector %s: %w (publish the record, or use --force)", next.Selector, err)
			}
			fmt.Fprintf(a.errw, "warning: %v; switching anyway because of --force\n", err)
		}
		if err := st.ActivateDKIMKey(domain, next.Selector); err != nil {
			return err
		}
		fmt.Fprintf(a.out, "now signing %s with selector %s\nKeep the old selector's DNS record for a week or so: mail signed with it may still be in transit.\n",
			domain, next.Selector)
	}
	return nil
}
