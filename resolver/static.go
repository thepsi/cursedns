package resolver

import (
	"context"
	"net/netip"

	"github.com/miekg/dns"
)

// StaticHandler is a dummy Handler for testing the server skeleton: it
// answers every A/AAAA query with a fixed address, ignoring the cache and
// root hints entirely, and returns NOERROR/no-data for any other query
// type.
type StaticHandler struct {
	// IPv4 and IPv6 are the addresses returned for A and AAAA queries,
	// respectively. Either may be the zero value to skip answering that
	// type (an empty NOERROR is returned instead).
	IPv4 netip.Addr
	IPv6 netip.Addr

	// TTL is the TTL, in seconds, applied to the returned record.
	TTL uint32
}

func (h *StaticHandler) Handle(ctx context.Context, query Query, helper Helper) (*Response, error) {
	helper.Trace("static handler answering %s %s", query.Name, dns.TypeToString[query.Type])

	hdr := dns.RR_Header{
		Name:  query.Name,
		Class: dns.ClassINET,
		Ttl:   h.TTL,
	}

	var answer []dns.RR
	switch query.Type {
	case dns.TypeA:
		if h.IPv4.IsValid() {
			hdr.Rrtype = dns.TypeA
			answer = []dns.RR{&dns.A{Hdr: hdr, A: h.IPv4.AsSlice()}}
		}
	case dns.TypeAAAA:
		if h.IPv6.IsValid() {
			hdr.Rrtype = dns.TypeAAAA
			answer = []dns.RR{&dns.AAAA{Hdr: hdr, AAAA: h.IPv6.AsSlice()}}
		}
	default:
		helper.Trace("no static answer configured for qtype %s", dns.TypeToString[query.Type])
	}

	return &Response{
		RCode:         dns.RcodeSuccess,
		Authoritative: true,
		Answer:        answer,
	}, nil
}
