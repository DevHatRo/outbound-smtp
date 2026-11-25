package smtpd

import (
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/DevHatRo/outbound-smtp/internal/store"
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

// limitKey is the address the per-client limits count against. An IPv6
// client usually controls a whole /64, so that is what gets counted;
// otherwise it would have a fresh allowance for every address in it.
func limitKey(ip netip.Addr) netip.Addr {
	if ip = ip.Unmap(); ip.Is6() {
		if p, err := ip.Prefix(64); err == nil {
			return p.Addr()
		}
	}
	return ip
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
	// Bound the map (keys include client IPs) by dropping only full buckets:
	// those carry no history, so an address that is currently limited stays limited.
	// ponytail: if 10k addresses are all mid-limit the map keeps growing until
	// they refill; cap with an LRU if that ever shows up.
	if len(l.buckets) > 10000 {
		for k, b := range l.buckets {
			if b.Tokens() >= float64(b.Burst()) {
				delete(l.buckets, k)
			}
		}
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

// authLimiter blocks an address after too many failed logins in a window.
// Attempts still being verified count against the limit, so parallel
// attempts cannot all pass on the last remaining failure.
type authLimiter struct {
	mu     sync.Mutex
	window time.Duration
	now    func() time.Time
	byKey  map[string]*authState
}

type authState struct {
	start   time.Time // start of the current window
	fails   int
	pending int
}

func newAuthLimiter(window time.Duration) *authLimiter {
	return &authLimiter{window: window, now: time.Now, byKey: map[string]*authState{}}
}

// begin admits one attempt for key, or reports that the address is blocked.
// The caller must call the returned function once with the outcome.
func (a *authLimiter) begin(key string, limit int) (finish func(failed bool), ok bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	if len(a.byKey) > 10000 { // drop addresses with nothing left to remember
		for k, st := range a.byKey {
			if st.pending == 0 && now.Sub(st.start) >= a.window {
				delete(a.byKey, k)
			}
		}
	}
	st := a.byKey[key]
	if st == nil {
		st = &authState{start: now}
		a.byKey[key] = st
	}
	if now.Sub(st.start) >= a.window {
		st.start, st.fails = now, 0
	}
	if st.fails+st.pending >= limit {
		return nil, false
	}
	st.pending++
	return func(failed bool) {
		a.mu.Lock()
		defer a.mu.Unlock()
		st.pending--
		if failed {
			st.fails++
		}
	}, true
}
