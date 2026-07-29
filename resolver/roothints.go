package resolver

import "net/netip"

// RootZone is the DNS root zone, the zone RootHints is authoritative for.
const RootZone = "."

// rootHints is the standard IANA root server hints list
// (https://www.internic.net/domain/named.root), used as the default
// starting point for iterative resolution.
var rootHints = []NameServer{
	{Name: "a.root-servers.net.", Addr: netip.MustParseAddr("198.41.0.4")},
	{Name: "a.root-servers.net.", Addr: netip.MustParseAddr("2001:503:ba3e::2:30")},
	{Name: "b.root-servers.net.", Addr: netip.MustParseAddr("170.247.170.2")},
	{Name: "b.root-servers.net.", Addr: netip.MustParseAddr("2801:1b8:10::b")},
	{Name: "c.root-servers.net.", Addr: netip.MustParseAddr("192.33.4.12")},
	{Name: "c.root-servers.net.", Addr: netip.MustParseAddr("2001:500:2::c")},
	{Name: "d.root-servers.net.", Addr: netip.MustParseAddr("199.7.91.13")},
	{Name: "d.root-servers.net.", Addr: netip.MustParseAddr("2001:500:2d::d")},
	{Name: "e.root-servers.net.", Addr: netip.MustParseAddr("192.203.230.10")},
	{Name: "e.root-servers.net.", Addr: netip.MustParseAddr("2001:500:a8::e")},
	{Name: "f.root-servers.net.", Addr: netip.MustParseAddr("192.5.5.241")},
	{Name: "f.root-servers.net.", Addr: netip.MustParseAddr("2001:500:2f::f")},
	{Name: "g.root-servers.net.", Addr: netip.MustParseAddr("192.112.36.4")},
	{Name: "g.root-servers.net.", Addr: netip.MustParseAddr("2001:500:12::d0d")},
	{Name: "h.root-servers.net.", Addr: netip.MustParseAddr("198.97.190.53")},
	{Name: "h.root-servers.net.", Addr: netip.MustParseAddr("2001:500:1::53")},
	{Name: "i.root-servers.net.", Addr: netip.MustParseAddr("192.36.148.17")},
	{Name: "i.root-servers.net.", Addr: netip.MustParseAddr("2001:7fe::53")},
	{Name: "j.root-servers.net.", Addr: netip.MustParseAddr("192.58.128.30")},
	{Name: "j.root-servers.net.", Addr: netip.MustParseAddr("2001:503:c27::2:30")},
	{Name: "k.root-servers.net.", Addr: netip.MustParseAddr("193.0.14.129")},
	{Name: "k.root-servers.net.", Addr: netip.MustParseAddr("2001:7fd::1")},
	{Name: "l.root-servers.net.", Addr: netip.MustParseAddr("199.7.83.42")},
	{Name: "l.root-servers.net.", Addr: netip.MustParseAddr("2001:500:9f::42")},
	{Name: "m.root-servers.net.", Addr: netip.MustParseAddr("202.12.27.33")},
	{Name: "m.root-servers.net.", Addr: netip.MustParseAddr("2001:dc3::35")},
}

// RootHints returns the standard IANA root server hints.
func RootHints() []NameServer {
	return append([]NameServer(nil), rootHints...)
}
