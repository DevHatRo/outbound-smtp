package smtpd

import (
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/DevHatRO/outbound-smtp/internal/store"
)

// principal is who is sending: an authenticated user or a trusted network.
// A session without a principal may not relay anything.
type principal struct {
	source   string   // store.SourceAuth or store.SourceNetwork
	ident    string   // username or CIDR
	patterns []string // allowed sender domains/addresses; empty = any configured domain
	rate     *int     // per-hour override, nil = global default
}

// senderAllowed reports whether addr (already known to be in a configured
// domain) passes the principal's restrictions. Patterns are lowercase
// domains ("example.com") or full addresses ("app@example.com").
func senderAllowed(patterns []string, addr string) bool {
	if len(patterns) == 0 {
		return true
	}
	addr = strings.ToLower(addr)
	domain := addr[strings.LastIndexByte(addr, '@')+1:]
	for _, p := range patterns {
		if p == addr || p == domain {
			return true
		}
	}
	return false
}

// matchNetwork returns the most specific trusted network containing ip.
func matchNetwork(nets []store.Network, ip netip.Addr) *store.Network {
	ip = ip.Unmap()
	var best *store.Network
	for i := range nets {
		p := nets[i].Prefix()
		if p.IsValid() && p.Contains(ip) && (best == nil || p.Bits() > best.Prefix().Bits()) {
			best = &nets[i]
		}
	}
	return best
}

// limiters hands out one token bucket per key.
type limiters struct {
	mu      sync.Mutex
	buckets map[string]*rate.Limiter
	window  time.Duration
}

func newLimiters(window time.Duration) *limiters {
	return &limiters{buckets: map[string]*rate.Limiter{}, window: window}
}

// get returns the bucket for key allowing n events per window (burst n).
// Changing n through the CLI takes effect on the next call.
func (l *limiters) get(key string, n int) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()
	// ponytail: unbounded keys (client IPs) are dropped wholesale at 10k entries,
	// which forgets auth-failure history under a wide attack; use an LRU if that matters.
	if len(l.buckets) > 10000 {
		l.buckets = map[string]*rate.Limiter{}
	}
	b, ok := l.buckets[key]
	if !ok {
		b = rate.NewLimiter(rate.Every(l.window/time.Duration(n)), n)
		l.buckets[key] = b
	} else if b.Burst() != n {
		b.SetLimit(rate.Every(l.window / time.Duration(n)))
		b.SetBurst(n)
	}
	return b
}

// allow consumes one event.
func (l *limiters) allow(key string, n int) bool { return l.get(key, n).Allow() }

// exhausted reports whether the bucket is empty, without consuming.
func (l *limiters) exhausted(key string, n int) bool { return l.get(key, n).Tokens() < 1 }
