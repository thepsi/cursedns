package handlers

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/miekg/dns"

	"cursedns/resolver"
)

const (
	// maxHops bounds delegation hops within a single name/qtype resolution
	// (resolveIterative), guarding against a referral loop that never
	// narrows to an answer.
	maxHops = 20

	// maxCNAMERestarts bounds how many times resolution may restart from
	// root because a CNAME chain led to a name outside the zone the
	// previous nameserver was trusted for.
	maxCNAMERestarts = 8

	// maxGlueDepth bounds how deeply glueless-referral nameserver-address
	// resolution may nest (resolving one NS's address can itself hit a
	// glueless referral).
	maxGlueDepth = 4

	// maxTotalLookups bounds the total number of Helper.Lookup calls across
	// an entire Handle invocation - the main resolution chain plus every
	// nested glue resolution combined - regardless of how the other limits
	// above interact, so one inbound query can't be used to generate
	// unbounded outbound traffic.
	maxTotalLookups = 100
)

// RecursiveHandler is a Handler that performs real iterative/recursive DNS
// resolution: starting at the root, it follows delegations down to an
// authoritative answer, using Helper.Lookup as its single building block.
type RecursiveHandler struct{}

func (h *RecursiveHandler) Handle(ctx context.Context, query resolver.Query, helper resolver.Helper) (*resolver.Response, error) {
	budget := maxTotalLookups

	name := query.Name
	var answer []dns.RR
	for restarts := 0; restarts < maxCNAMERestarts; restarts++ {
		result, err := resolveIterative(ctx, helper, name, query.Type, &budget, 0)
		if err != nil {
			return nil, err
		}
		answer = append(answer, result.Answer...)

		if result.RCode != dns.RcodeSuccess || len(result.Answer) == 0 {
			// A terminal negative result (NXDOMAIN, or NODATA: success with
			// nothing further to chase) - pass through its authority
			// section (e.g. SOA) so the client sees the same negative
			// answer we cached it under.
			return &resolver.Response{RCode: result.RCode, Answer: answer, Ns: result.Ns}, nil
		}

		target, needsRestart := unresolvedCNAMETarget(result.Answer, name, query.Type)
		if !needsRestart {
			return &resolver.Response{RCode: dns.RcodeSuccess, Answer: answer}, nil
		}

		helper.Trace("restarting resolution from root for %s (left previous zone via CNAME)", target)
		name = target
	}

	return nil, fmt.Errorf("resolve %s %s: exceeded maximum CNAME restarts (%d)", query.Name, dns.TypeToString[query.Type], maxCNAMERestarts)
}

// resolveIterative resolves a single (name, qtype) question by walking the
// delegation chain from root, narrowing zone/nameservers one referral at a
// time. It does not itself follow CNAME chains across zone boundaries -
// that is handled by Handle, which restarts resolution for a new name when
// needed.
func resolveIterative(ctx context.Context, helper resolver.Helper, name string, qtype uint16, budget *int, depth int) (*resolver.LookupResult, error) {
	zone := resolver.RootZone
	nameservers := helper.RootHints()

	for hop := 0; hop < maxHops; hop++ {
		if *budget <= 0 {
			return nil, fmt.Errorf("resolve %s %s: exceeded lookup budget", name, dns.TypeToString[qtype])
		}
		*budget--

		result, err := helper.Lookup(ctx, name, qtype, zone, nameservers)
		if err != nil {
			return nil, err
		}

		if result.RCode != dns.RcodeSuccess {
			return result, nil
		}
		if len(result.Answer) > 0 {
			return result, nil
		}
		if !hasNS(result.Ns) {
			return result, nil // NODATA (Ns, if present, is just a passed-through SOA)
		}

		// A referral: filterInBailiwick guarantees every surviving NS
		// record shares one owner name, at or below zone and covering
		// name - that owner is the next, narrower zone.
		delegatedZone := delegationOwner(result.Ns)
		if strings.EqualFold(delegatedZone, zone) {
			return nil, fmt.Errorf("resolve %s %s: referral from %s made no progress", name, dns.TypeToString[qtype], zone)
		}

		next, err := resolveNameservers(ctx, helper, result.Ns, result.Extra, budget, depth)
		if err != nil {
			return nil, fmt.Errorf("resolve %s %s: referral to %s: %w", name, dns.TypeToString[qtype], delegatedZone, err)
		}

		helper.Trace("referral for %s %s: %s -> %s (%d nameserver address(es))", name, dns.TypeToString[qtype], zone, delegatedZone, len(next))
		zone = delegatedZone
		nameservers = next
	}

	return nil, fmt.Errorf("resolve %s %s: exceeded maximum hops (%d)", name, dns.TypeToString[qtype], maxHops)
}

// resolveNameservers turns a referral's Ns/Extra records into a list of
// addresses to query next. If the referral came with no usable glue (every
// nameserver's address was either not supplied or rejected as
// out-of-bailiwick by filterInBailiwick), it resolves one nameserver's
// address itself via a fresh, independent resolution starting at root.
func resolveNameservers(ctx context.Context, helper resolver.Helper, ns, extra []dns.RR, budget *int, depth int) ([]resolver.NameServer, error) {
	names := uniqueNSNames(ns)

	var out []resolver.NameServer
	for _, name := range names {
		for _, rr := range extra {
			switch rr := rr.(type) {
			case *dns.A:
				if strings.EqualFold(rr.Header().Name, name) {
					if addr, ok := netip.AddrFromSlice(rr.A); ok {
						out = append(out, resolver.NameServer{Name: name, Addr: addr})
					}
				}
			case *dns.AAAA:
				if strings.EqualFold(rr.Header().Name, name) {
					if addr, ok := netip.AddrFromSlice(rr.AAAA); ok {
						out = append(out, resolver.NameServer{Name: name, Addr: addr})
					}
				}
			}
		}
	}
	if len(out) > 0 {
		return out, nil
	}

	// Glueless referral.
	if depth >= maxGlueDepth {
		return nil, fmt.Errorf("glueless referral nesting too deep resolving %v", names)
	}

	var lastErr error
	for _, name := range names {
		result, err := resolveIterative(ctx, helper, name, dns.TypeA, budget, depth+1)
		if err != nil {
			lastErr = err
			continue
		}
		for _, rr := range result.Answer {
			if a, ok := rr.(*dns.A); ok {
				if addr, ok := netip.AddrFromSlice(a.A); ok {
					out = append(out, resolver.NameServer{Name: name, Addr: addr})
				}
			}
		}
		if len(out) > 0 {
			return out, nil
		}
	}

	if lastErr != nil {
		return nil, fmt.Errorf("could not resolve an address for any nameserver in %v: %w", names, lastErr)
	}
	return nil, fmt.Errorf("could not resolve an address for any nameserver in %v", names)
}

// hasNS reports whether rrs contains any NS record - used to distinguish a
// referral (continue the delegation walk) from a genuine NODATA result
// (Ns, if present, is just a passed-through SOA). A local copy of the same
// predicate resolver uses internally for its own, unrelated purpose
// (negative-cache classification): it operates purely on the exported
// []dns.RR, so duplicating six lines here is cheaper and more honest than
// widening resolver's exported API for it.
func hasNS(rrs []dns.RR) bool {
	for _, rr := range rrs {
		if _, ok := rr.(*dns.NS); ok {
			return true
		}
	}
	return false
}

// delegationOwner returns the owner name of the first NS record in ns
// (which, per filterInBailiwick, is shared by every NS record present -
// SOA records may also appear alongside them and are skipped here).
func delegationOwner(ns []dns.RR) string {
	for _, rr := range ns {
		if nsRR, ok := rr.(*dns.NS); ok {
			return nsRR.Header().Name
		}
	}
	return ""
}

// uniqueNSNames returns the distinct nameserver hostnames named by ns
// (which must all be *dns.NS records sharing one owner, per
// filterInBailiwick), preserving first-seen order.
func uniqueNSNames(ns []dns.RR) []string {
	seen := make(map[string]bool)
	var names []string
	for _, rr := range ns {
		nsRR, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		key := strings.ToLower(nsRR.Ns)
		if seen[key] {
			continue
		}
		seen[key] = true
		names = append(names, nsRR.Ns)
	}
	return names
}

// unresolvedCNAMETarget walks the CNAME chain in answer (the accumulated,
// already-trusted records for a resolveIterative call that started at
// name), reporting whether it ends in a CNAME whose target has no matching
// qtype record within answer - meaning the zone boundary of whichever
// nameserver supplied it cut the chain short, and resolution must restart
// from root for that target.
//
// A query for dns.TypeCNAME itself is never chased further: the client
// asked for the CNAME record, not its target's data.
func unresolvedCNAMETarget(answer []dns.RR, name string, qtype uint16) (target string, needsRestart bool) {
	if qtype == dns.TypeCNAME {
		return "", false
	}

	expect := name
	for hops := 0; hops <= len(answer); hops++ {
		var cname string
		found := false
		for _, rr := range answer {
			if !strings.EqualFold(rr.Header().Name, expect) {
				continue
			}
			found = true
			if rr.Header().Rrtype == qtype {
				return "", false
			}
			if c, ok := rr.(*dns.CNAME); ok {
				cname = c.Target
			}
		}
		if !found {
			return expect, hops > 0
		}
		if cname == "" {
			return "", false // records exist here, but nothing continues the chain or answers qtype
		}
		expect = cname
	}
	return "", false
}
