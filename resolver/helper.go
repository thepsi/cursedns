package resolver

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// defaultNegativeTTL bounds negative caching when a response carries no
// usable (in-bailiwick) SOA record to derive a TTL from - RFC 2308 expects
// one to be present, but not every server complies.
const defaultNegativeTTL = 60 * time.Second

// NameServer identifies a single nameserver a Helper can query: its name
// (for logging/tracing) and the IP address to send queries to.
type NameServer struct {
	Name string
	Addr netip.Addr
}

// LookupResult is the outcome of a Helper.Lookup call: either the cached
// answer, or the response returned by whichever nameserver answered.
type LookupResult struct {
	// RCode is the response code returned by the nameserver (or
	// dns.RcodeSuccess for a cache hit).
	RCode int

	// Answer, Ns and Extra mirror the corresponding sections of the
	// nameserver's response. On a cache hit, only Answer is populated.
	Answer []dns.RR
	Ns     []dns.RR
	Extra  []dns.RR
}

// Helper provides a Handler with the functionality the skeleton owns on its
// behalf: cache-backed lookups, root hints, and per-request tracing.
//
// A Helper is only valid for the lifetime of the request it was created
// for; a Handler must not retain one past its Handle call returning.
type Helper interface {
	// Lookup resolves a single (name, qtype) question using nameservers,
	// which the caller asserts are authoritative for zone (a suffix of, or
	// equal to, name). It first checks the shared cache; on a miss, it
	// queries each of nameservers in turn (non-recursively) until one
	// responds, caches any answer received, and returns the result.
	//
	// Records that a queried server had no authority over zone are
	// discarded rather than trusted: a response is only ever taken at its
	// word for names at or below zone. In particular, if a CNAME chain
	// leads outside zone, the CNAME itself is kept but any further chained
	// data for the new (out-of-zone) name is not — the caller must issue a
	// fresh Lookup for it, starting from RootHints or another zone it
	// already trusts.
	//
	// This performs a single resolution step. Handlers implementing
	// iterative/recursive resolution are expected to call Lookup
	// repeatedly, walking down the delegation chain using the Ns/Extra
	// records of each referral, narrowing zone as they go.
	Lookup(ctx context.Context, name string, qtype uint16, zone string, nameservers []NameServer) (*LookupResult, error)

	// RootHints returns the initial list of root nameservers to begin
	// resolution from, authoritative for RootZone.
	RootHints() []NameServer

	// Trace records a line of trace information about the current
	// request. Trace lines are logged together once the request
	// completes.
	Trace(format string, args ...any)
}

// requestHelper is the Helper implementation used by the server for each
// inbound request.
type requestHelper struct {
	cache     *Cache
	rootHints []NameServer
	client    *dns.Client

	mu    sync.Mutex
	lines []string
}

func newRequestHelper(cache *Cache, rootHints []NameServer, client *dns.Client) *requestHelper {
	return &requestHelper{
		cache:     cache,
		rootHints: rootHints,
		client:    client,
	}
}

func (h *requestHelper) Lookup(ctx context.Context, name string, qtype uint16, zone string, nameservers []NameServer) (*LookupResult, error) {
	name = dns.Fqdn(name)
	zone = dns.Fqdn(zone)

	if rrs, ok := h.cache.Get(name, qtype, dns.ClassINET); ok {
		h.Trace("cache hit for %s %s", name, dns.TypeToString[qtype])
		return &LookupResult{RCode: dns.RcodeSuccess, Answer: rrs}, nil
	}
	if rcode, ok := h.cache.GetNegative(name, qtype, dns.ClassINET); ok {
		h.Trace("negative cache hit for %s %s (%s)", name, dns.TypeToString[qtype], dns.RcodeToString[rcode])
		return &LookupResult{RCode: rcode}, nil
	}

	if len(nameservers) == 0 {
		return nil, fmt.Errorf("lookup %s %s: cache miss and no nameservers provided", name, dns.TypeToString[qtype])
	}

	h.Trace("cache miss for %s %s, querying %d nameserver(s)", name, dns.TypeToString[qtype], len(nameservers))

	req := new(dns.Msg)
	req.SetQuestion(name, qtype)
	req.RecursionDesired = false

	var lastErr error
	for _, ns := range nameservers {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		addr := net.JoinHostPort(ns.Addr.String(), "53")
		resp, _, err := h.client.ExchangeContext(ctx, req, addr)
		if err != nil {
			h.Trace("query to %s (%s) failed: %v", ns.Name, ns.Addr, err)
			lastErr = err
			continue
		}

		h.Trace("query to %s (%s) returned %s, %d answer(s), %d authority, %d additional",
			ns.Name, ns.Addr, dns.RcodeToString[resp.Rcode], len(resp.Answer), len(resp.Ns), len(resp.Extra))

		answer, nsRRs, extra, delegatedZone := filterInBailiwick(zone, name, resp.Answer, resp.Ns, resp.Extra)
		if discarded := (len(resp.Answer) + len(resp.Ns) + len(resp.Extra)) - (len(answer) + len(nsRRs) + len(extra)); discarded > 0 {
			h.Trace("discarded %d out-of-bailiwick record(s) from %s (%s)", discarded, ns.Name, ns.Addr)
		}

		if resp.Rcode == dns.RcodeSuccess && len(answer) > 0 {
			h.cache.Set(name, qtype, dns.ClassINET, answer)
		}
		if len(nsRRs) > 0 {
			h.cache.Set(delegatedZone, dns.TypeNS, dns.ClassINET, nsRRs)
		}
		for key, rrs := range groupByNameType(extra) {
			h.cache.Set(key.name, key.qtype, dns.ClassINET, rrs)
		}

		switch {
		case resp.Rcode == dns.RcodeNameError:
			ttl := negativeTTL(zone, resp.Ns)
			h.cache.SetNXDomain(name, dns.ClassINET, ttl)
			h.Trace("caching NXDOMAIN for %s (%s)", name, ttl)
		case resp.Rcode == dns.RcodeSuccess && len(answer) == 0 && !hasNS(resp.Ns):
			// No answer and the server didn't even attempt a referral (as
			// opposed to attempting one that got rejected as
			// out-of-bailiwick above) - a genuine NODATA response.
			ttl := negativeTTL(zone, resp.Ns)
			h.cache.SetNoData(name, qtype, dns.ClassINET, ttl)
			h.Trace("caching NODATA for %s %s (%s)", name, dns.TypeToString[qtype], ttl)
		}

		return &LookupResult{
			RCode:  resp.Rcode,
			Answer: answer,
			Ns:     nsRRs,
			Extra:  extra,
		}, nil
	}

	return nil, fmt.Errorf("lookup %s %s: all nameservers failed: %w", name, dns.TypeToString[qtype], lastErr)
}

// hasNS reports whether rrs contains any NS record, regardless of
// bailiwick - used to distinguish a genuine NODATA response (no attempt at
// a referral) from one where a referral was attempted but rejected as
// out-of-bailiwick, which should not be cached as if it were NODATA.
func hasNS(rrs []dns.RR) bool {
	for _, rr := range rrs {
		if _, ok := rr.(*dns.NS); ok {
			return true
		}
	}
	return false
}

// negativeTTL returns the TTL to use for a negative cache entry, per
// RFC 2308: the smaller of the zone's SOA record TTL and its MINIMUM field.
// Only an in-bailiwick SOA (one actually within zone) is trusted, for the
// same reason referral and glue records are checked elsewhere - an
// off-path server has no authority to dictate how long we treat an
// unrelated zone's name as absent.
func negativeTTL(zone string, ns []dns.RR) time.Duration {
	for _, rr := range ns {
		soa, ok := rr.(*dns.SOA)
		if !ok || !dns.IsSubDomain(zone, soa.Header().Name) {
			continue
		}
		ttl := soa.Hdr.Ttl
		if soa.Minttl < ttl {
			ttl = soa.Minttl
		}
		return time.Duration(ttl) * time.Second
	}
	return defaultNegativeTTL
}

// nameType groups records by owner name and type, for caching each glue
// record under its own cache key.
type nameType struct {
	name  string
	qtype uint16
}

func groupByNameType(rrs []dns.RR) map[nameType][]dns.RR {
	groups := make(map[nameType][]dns.RR)
	for _, rr := range rrs {
		key := nameType{name: rr.Header().Name, qtype: rr.Header().Rrtype}
		groups[key] = append(groups[key], rr)
	}
	return groups
}

// filterInBailiwick discards records that a nameserver, trusted only for
// zone, had no authority to supply — guarding against an off-path or
// compromised server using its response to inject records for unrelated
// names, either directly or riding along on a CNAME chain:
//
//   - answer records are accepted while following the CNAME chain rooted
//     at name, but only for as long as each successive name in that chain
//     remains at or below zone; a CNAME out of zone is kept (its owner is
//     still in zone), but nothing answering for its out-of-zone target is;
//   - ns records must share a single owner name (the delegated zone) that
//     is at or below zone, and is name or an ancestor of it — a referral
//     can only narrow the zone already being trusted, never redirect
//     outside it;
//   - extra (glue) records must fall at or below that delegated zone;
//   - a SOA record (accompanying a negative response) is kept only if its
//     owner is at or below zone.
//
// It returns the filtered sections along with the delegated zone name
// found in ns, if any.
//
// The DNS spec does not mandate that a CNAME chain's records appear in any
// particular order within the answer section (this has caused at least one
// real resolver outage when an upstream silently reordered its answers), so
// the chain is followed by repeatedly scanning the remaining records for
// the current expected name rather than assuming sequential order.
func filterInBailiwick(zone, name string, answer, ns, extra []dns.RR) (filteredAnswer, filteredNs, filteredExtra []dns.RR, delegatedZone string) {
	remaining := append([]dns.RR(nil), answer...)
	expect := name
	for dns.IsSubDomain(zone, expect) {
		var matched, rest []dns.RR
		for _, rr := range remaining {
			if strings.EqualFold(rr.Header().Name, expect) {
				matched = append(matched, rr)
			} else {
				rest = append(rest, rr)
			}
		}
		if len(matched) == 0 {
			break
		}
		filteredAnswer = append(filteredAnswer, matched...)
		remaining = rest

		var next string
		for _, rr := range matched {
			if cname, ok := rr.(*dns.CNAME); ok {
				next = cname.Target
				break
			}
		}
		if next == "" {
			break
		}
		expect = next
	}

	for _, rr := range ns {
		switch rr := rr.(type) {
		case *dns.NS:
			owner := rr.Header().Name
			if !dns.IsSubDomain(zone, owner) {
				continue // claims authority outside the zone this server was trusted for
			}
			if !dns.IsSubDomain(owner, name) {
				continue // owner is not name or an ancestor of it
			}
			if delegatedZone == "" {
				delegatedZone = owner
			} else if !strings.EqualFold(owner, delegatedZone) {
				continue // inconsistent delegation owner within one response
			}
			filteredNs = append(filteredNs, rr)
		case *dns.SOA:
			// Carries no delegation authority of its own; kept so negative
			// (NXDOMAIN/NODATA) responses can show the client the same
			// in-bailiwick SOA that negativeTTL already trusts for TTL
			// derivation.
			if dns.IsSubDomain(zone, rr.Header().Name) {
				filteredNs = append(filteredNs, rr)
			}
		}
	}

	if delegatedZone != "" {
		for _, rr := range extra {
			if dns.IsSubDomain(delegatedZone, rr.Header().Name) {
				filteredExtra = append(filteredExtra, rr)
			}
		}
	}

	return filteredAnswer, filteredNs, filteredExtra, delegatedZone
}

func (h *requestHelper) RootHints() []NameServer {
	return h.rootHints
}

func (h *requestHelper) Trace(format string, args ...any) {
	line := fmt.Sprintf("%s "+format, append([]any{time.Now().Format(time.RFC3339Nano)}, args...)...)
	h.mu.Lock()
	h.lines = append(h.lines, line)
	h.mu.Unlock()
}

// traceLines returns the trace lines recorded so far.
func (h *requestHelper) traceLines() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.lines...)
}
