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
	// Lookup resolves a single (name, qtype) question. It first checks the
	// shared cache; on a miss, it queries each of nameservers in turn
	// (non-recursively) until one responds, caches any answer received,
	// and returns the result.
	//
	// This performs a single resolution step. Handlers implementing
	// iterative/recursive resolution are expected to call Lookup
	// repeatedly, walking down the delegation chain using the Ns/Extra
	// records of each referral.
	Lookup(ctx context.Context, name string, qtype uint16, nameservers []NameServer) (*LookupResult, error)

	// RootHints returns the initial list of root nameservers to begin
	// resolution from.
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

func (h *requestHelper) Lookup(ctx context.Context, name string, qtype uint16, nameservers []NameServer) (*LookupResult, error) {
	name = dns.Fqdn(name)

	if rrs, ok := h.cache.Get(name, qtype, dns.ClassINET); ok {
		h.Trace("cache hit for %s %s", name, dns.TypeToString[qtype])
		return &LookupResult{RCode: dns.RcodeSuccess, Answer: rrs}, nil
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

		answer, nsRRs, extra, zone := filterInBailiwick(name, resp.Answer, resp.Ns, resp.Extra)
		if discarded := (len(resp.Answer) + len(resp.Ns) + len(resp.Extra)) - (len(answer) + len(nsRRs) + len(extra)); discarded > 0 {
			h.Trace("discarded %d out-of-bailiwick record(s) from %s (%s)", discarded, ns.Name, ns.Addr)
		}

		if resp.Rcode == dns.RcodeSuccess && len(answer) > 0 {
			h.cache.Set(name, qtype, dns.ClassINET, answer)
		}
		if len(nsRRs) > 0 {
			h.cache.Set(zone, dns.TypeNS, dns.ClassINET, nsRRs)
		}
		for key, rrs := range groupByNameType(extra) {
			h.cache.Set(key.name, key.qtype, dns.ClassINET, rrs)
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

// filterInBailiwick discards records that a nameserver had no authority to
// supply, guarding against an off-path or compromised server using its
// response to inject unrelated records into the cache:
//
//   - answer records must belong to name itself, or to a CNAME chain
//     rooted at name;
//   - ns records must share a single owner name (the delegated zone) that
//     is name or an ancestor of it;
//   - extra (glue) records must fall at or below that delegated zone.
//
// It returns the filtered sections along with the delegated zone name
// found in ns, if any.
//
// The DNS spec does not mandate that a CNAME chain's records appear in any
// particular order within the answer section (this has caused at least one
// real resolver outage when an upstream silently reordered its answers), so
// the chain is followed by repeatedly scanning the remaining records for
// the current expected name rather than assuming sequential order.
func filterInBailiwick(name string, answer, ns, extra []dns.RR) (filteredAnswer, filteredNs, filteredExtra []dns.RR, zone string) {
	remaining := append([]dns.RR(nil), answer...)
	expect := name
	for {
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
		nsRR, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		owner := nsRR.Header().Name
		if !dns.IsSubDomain(owner, name) {
			continue // owner is not name or an ancestor of it
		}
		if zone == "" {
			zone = owner
		} else if !strings.EqualFold(owner, zone) {
			continue // inconsistent delegation owner within one response
		}
		filteredNs = append(filteredNs, rr)
	}

	if zone != "" {
		for _, rr := range extra {
			if dns.IsSubDomain(zone, rr.Header().Name) {
				filteredExtra = append(filteredExtra, rr)
			}
		}
	}

	return filteredAnswer, filteredNs, filteredExtra, zone
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
