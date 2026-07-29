// Package resolver provides a skeleton recursive DNS server: it owns the
// network listeners and DNS wire-format handling, and delegates the actual
// resolution logic to a caller-supplied Handler.
package resolver

import (
	"context"
	"net/netip"

	"github.com/miekg/dns"
)

// Query describes an inbound DNS question, as seen by a Handler.
//
// The skeleton only supports (and validates) requests carrying exactly one
// question, matching how DNS is used in practice. It also only ever hands a
// Handler queries with the RD (recursion desired) bit set - this server
// only offers a recursive service, so queries without RD are refused
// (RCODE REFUSED) before reaching a Handler.
type Query struct {
	// ID is the original query's DNS message ID. Handlers generally don't
	// need this (the server takes care of matching it in the response) but
	// it's useful for logging/tracing.
	ID uint16

	// Name is the fully-qualified (dot-terminated) question name.
	Name string

	// Type is the question type, e.g. dns.TypeA.
	Type uint16

	// Class is the question class, e.g. dns.ClassINET.
	Class uint16

	// ClientAddr is the address the query was received from.
	ClientAddr netip.AddrPort

	// Protocol is "udp" or "tcp", the transport the query arrived on.
	Protocol string
}

// Response is a handler's answer to a Query, mirroring the shape of a DNS
// reply at a high level. The server takes care of translating this into a
// real wire-format message (message ID, question section, EDNS0 handling,
// truncation, etc).
//
// The reply's AA bit is always cleared: this server only ever relays
// answers derived from other, genuinely authoritative nameservers, so it is
// never itself authoritative for anything it returns.
type Response struct {
	// RCode is the response code, e.g. dns.RcodeSuccess. The zero value is
	// dns.RcodeSuccess.
	RCode int

	// Answer, Ns and Extra mirror the corresponding sections of a DNS
	// message (answer / authority / additional).
	Answer []dns.RR
	Ns     []dns.RR
	Extra  []dns.RR
}

// Handler resolves a single Query, using helper for cache lookups, root
// hints and request tracing.
//
// If Handle returns an error, or ctx is cancelled before Handle returns, the
// server responds to the client with SERVFAIL.
type Handler interface {
	Handle(ctx context.Context, query Query, helper Helper) (*Response, error)
}
