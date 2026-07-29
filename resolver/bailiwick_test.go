package resolver

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func mustRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("NewRR(%q): %v", s, err)
	}
	return rr
}

func rrNames(rrs []dns.RR) []string {
	names := make([]string, len(rrs))
	for i, rr := range rrs {
		names[i] = rr.Header().Name
	}
	return names
}

// --- Answer section / CNAME chain following ---

func TestFilterInBailiwick_AnswerDirect(t *testing.T) {
	answer := []dns.RR{mustRR(t, "example.com. 60 IN A 5.5.5.5")}

	got, ns, extra, zone := filterInBailiwick("example.com.", "example.com.", answer, nil, nil)

	if len(got) != 1 {
		t.Fatalf("got %d answer record(s), want 1: %v", len(got), got)
	}
	if ns != nil || extra != nil || zone != "" {
		t.Fatalf("expected no ns/extra/zone for a plain answer, got ns=%v extra=%v zone=%q", ns, extra, zone)
	}
}

func TestFilterInBailiwick_AnswerChainInOrder(t *testing.T) {
	answer := []dns.RR{
		mustRR(t, "www.example.com. 60 IN CNAME app.example.com."),
		mustRR(t, "app.example.com. 60 IN A 1.2.3.4"),
	}

	got, _, _, _ := filterInBailiwick("example.com.", "www.example.com.", answer, nil, nil)

	if len(got) != 2 {
		t.Fatalf("got %d record(s), want both chain records: %v", len(got), got)
	}
}

func TestFilterInBailiwick_AnswerChainMultipleHops(t *testing.T) {
	answer := []dns.RR{
		mustRR(t, "a.example.com. 60 IN CNAME b.example.com."),
		mustRR(t, "b.example.com. 60 IN CNAME c.example.com."),
		mustRR(t, "c.example.com. 60 IN A 9.9.9.9"),
	}

	got, _, _, _ := filterInBailiwick("example.com.", "a.example.com.", answer, nil, nil)

	if len(got) != 3 {
		t.Fatalf("got %d record(s), want all 3 hops: %v", len(got), got)
	}
}

// The DNS spec does not mandate that a CNAME chain's records appear in
// chain order in the answer section - a real resolver (Cloudflare's
// 1.1.1.1) broke in production when an upstream started sending the
// target's record before its CNAME. filterInBailiwick must not assume
// sequential order.
func TestFilterInBailiwick_AnswerChainOutOfOrder(t *testing.T) {
	answer := []dns.RR{
		mustRR(t, "app.example.com. 60 IN A 1.2.3.4"),              // target listed first
		mustRR(t, "www.example.com. 60 IN CNAME app.example.com."), // CNAME listed second
	}

	got, _, _, _ := filterInBailiwick("example.com.", "www.example.com.", answer, nil, nil)

	if len(got) != 2 {
		t.Fatalf("out-of-order chain: got %d record(s), want 2: %v", len(got), got)
	}
}

func TestFilterInBailiwick_AnswerUnrelatedRecordDropped(t *testing.T) {
	answer := []dns.RR{
		mustRR(t, "www.example.com. 60 IN A 1.2.3.4"),
		mustRR(t, "other.example.com. 60 IN A 9.9.9.9"), // not part of the chain for www
	}

	got, _, _, _ := filterInBailiwick("example.com.", "www.example.com.", answer, nil, nil)

	if len(got) != 1 || got[0].Header().Name != "www.example.com." {
		t.Fatalf("expected only the queried name's record to survive, got %v", rrNames(got))
	}
}

// This is the core security case: a server that a caller trusts only for
// attacker.com must not be able to smuggle a validated-looking record for
// an unrelated victim domain (bank.com) by riding it on a CNAME chain. The
// CNAME assertion itself is within attacker.com's own authority and is
// kept, but bank.com's "address" is not attacker.com's to give out.
func TestFilterInBailiwick_AnswerChainStopsAtZoneBoundary(t *testing.T) {
	answer := []dns.RR{
		mustRR(t, "attacker.com. 60 IN CNAME bank.com."),
		mustRR(t, "bank.com. 60 IN A 6.6.6.6"), // spoofed, must be dropped
	}

	got, _, _, _ := filterInBailiwick("attacker.com.", "attacker.com.", answer, nil, nil)

	if len(got) != 1 {
		t.Fatalf("got %d record(s), want only the CNAME: %v", len(got), got)
	}
	if _, ok := got[0].(*dns.CNAME); !ok {
		t.Fatalf("expected the surviving record to be the CNAME, got %T", got[0])
	}
}

func TestFilterInBailiwick_AnswerNameOutsideZoneFromTheStart(t *testing.T) {
	// Malformed/mismatched call: the queried name isn't even within zone.
	// Nothing should be trusted.
	answer := []dns.RR{mustRR(t, "example.com. 60 IN A 5.5.5.5")}

	got, _, _, _ := filterInBailiwick("other.com.", "example.com.", answer, nil, nil)

	if len(got) != 0 {
		t.Fatalf("got %d record(s), want 0: %v", len(got), got)
	}
}

// A CNAME cycle must not hang the resolver: each record can be consumed at
// most once, so the chain-following loop is bounded by len(answer).
func TestFilterInBailiwick_AnswerChainCycleTerminates(t *testing.T) {
	answer := []dns.RR{
		mustRR(t, "a.example.com. 60 IN CNAME b.example.com."),
		mustRR(t, "b.example.com. 60 IN CNAME a.example.com."),
	}

	done := make(chan []dns.RR, 1)
	go func() {
		got, _, _, _ := filterInBailiwick("example.com.", "a.example.com.", answer, nil, nil)
		done <- got
	}()

	select {
	case got := <-done:
		if len(got) != 2 {
			t.Fatalf("got %d record(s), want both cycle records once each: %v", len(got), got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("filterInBailiwick did not terminate on a CNAME cycle")
	}
}

// --- NS referral bailiwick ---

func TestFilterInBailiwick_ReferralAccepted(t *testing.T) {
	ns := []dns.RR{
		mustRR(t, "example.com. 3600 IN NS ns1.example.com."),
		mustRR(t, "example.com. 3600 IN NS ns2.example.com."),
	}
	extra := []dns.RR{
		mustRR(t, "ns1.example.com. 3600 IN A 192.0.2.1"),
	}

	_, filteredNs, filteredExtra, zone := filterInBailiwick("com.", "www.example.com.", nil, ns, extra)

	if zone != "example.com." {
		t.Fatalf("zone = %q, want example.com.", zone)
	}
	if len(filteredNs) != 2 {
		t.Fatalf("got %d ns record(s), want 2: %v", len(filteredNs), filteredNs)
	}
	if len(filteredExtra) != 1 {
		t.Fatalf("got %d extra record(s), want 1: %v", len(filteredExtra), filteredExtra)
	}
}

// The core delegation-hijack case: a server trusted only for the .biz zone
// must not be able to redirect resolution of example.com (a name it has
// nothing to do with) to nameservers of its choosing.
func TestFilterInBailiwick_ReferralRejectedOutsideTrustedZone(t *testing.T) {
	ns := []dns.RR{mustRR(t, "example.com. 3600 IN NS ns.attacker.net.")}

	_, filteredNs, _, zone := filterInBailiwick("biz.", "example.com.", nil, ns, nil)

	if len(filteredNs) != 0 || zone != "" {
		t.Fatalf("expected the out-of-trusted-zone referral to be fully rejected, got ns=%v zone=%q", filteredNs, zone)
	}
}

func TestFilterInBailiwick_ReferralRejectedForUnrelatedName(t *testing.T) {
	// other.biz. is within the trusted zone (biz.) but has nothing to do
	// with the name actually being resolved (example.biz.).
	ns := []dns.RR{mustRR(t, "other.biz. 3600 IN NS ns.other.biz.")}

	_, filteredNs, _, zone := filterInBailiwick("biz.", "example.biz.", nil, ns, nil)

	if len(filteredNs) != 0 || zone != "" {
		t.Fatalf("expected the irrelevant referral to be rejected, got ns=%v zone=%q", filteredNs, zone)
	}
}

func TestFilterInBailiwick_ReferralInconsistentOwnersOnlyFirstKept(t *testing.T) {
	ns := []dns.RR{
		mustRR(t, "example.com. 3600 IN NS ns1.example.com."),
		mustRR(t, "evil.com. 3600 IN NS ns.evil.com."), // different owner, injected
	}

	_, filteredNs, _, zone := filterInBailiwick("com.", "example.com.", nil, ns, nil)

	if zone != "example.com." {
		t.Fatalf("zone = %q, want example.com.", zone)
	}
	if len(filteredNs) != 1 || filteredNs[0].Header().Name != "example.com." {
		t.Fatalf("expected only the example.com. NS to survive, got %v", rrNames(filteredNs))
	}
}

func TestFilterInBailiwick_ReferralNonNSRecordsIgnored(t *testing.T) {
	ns := []dns.RR{mustRR(t, "example.com. 3600 IN A 1.2.3.4")} // wrong type for this section

	_, filteredNs, _, zone := filterInBailiwick("com.", "example.com.", nil, ns, nil)

	if len(filteredNs) != 0 || zone != "" {
		t.Fatalf("expected non-NS records to be ignored, got ns=%v zone=%q", filteredNs, zone)
	}
}

// --- Extra (glue) bailiwick ---

func TestFilterInBailiwick_GlueInBailiwickKept(t *testing.T) {
	ns := []dns.RR{mustRR(t, "example.com. 3600 IN NS ns1.example.com.")}
	extra := []dns.RR{mustRR(t, "ns1.example.com. 3600 IN A 192.0.2.1")}

	_, _, filteredExtra, _ := filterInBailiwick("com.", "example.com.", nil, ns, extra)

	if len(filteredExtra) != 1 {
		t.Fatalf("got %d extra record(s), want 1: %v", len(filteredExtra), filteredExtra)
	}
}

// Classic out-of-bailiwick glue: a third-party nameserver hostname (common
// in practice - e.g. registrar- or CDN-hosted DNS) must not be trusted as
// glue from the parent's referral, since the parent has no authority over
// that hostname's zone. This also covers the injection case where a
// completely unrelated "glue" record for a victim domain is attached.
func TestFilterInBailiwick_GlueOutOfBailiwickDropped(t *testing.T) {
	ns := []dns.RR{mustRR(t, "example.com. 3600 IN NS dns1.registrar.net.")}
	extra := []dns.RR{
		mustRR(t, "dns1.registrar.net. 3600 IN A 198.51.100.1"), // out of bailiwick, not trusted
		mustRR(t, "victim.com. 3600 IN A 6.6.6.6"),              // injected, unrelated
	}

	_, _, filteredExtra, _ := filterInBailiwick("com.", "example.com.", nil, ns, extra)

	if len(filteredExtra) != 0 {
		t.Fatalf("expected all out-of-bailiwick glue to be dropped, got %v", filteredExtra)
	}
}

func TestFilterInBailiwick_GlueDroppedWhenNoReferralSurvives(t *testing.T) {
	// The only NS record is rejected (outside the trusted zone), so no
	// delegated zone is established; any accompanying "glue" must be
	// dropped too rather than trusted on its own.
	ns := []dns.RR{mustRR(t, "example.com. 3600 IN NS ns.attacker.net.")}
	extra := []dns.RR{mustRR(t, "ns.attacker.net. 3600 IN A 6.6.6.6")}

	_, filteredNs, filteredExtra, zone := filterInBailiwick("biz.", "example.com.", nil, ns, extra)

	if len(filteredNs) != 0 || len(filteredExtra) != 0 || zone != "" {
		t.Fatalf("expected everything dropped, got ns=%v extra=%v zone=%q", filteredNs, filteredExtra, zone)
	}
}

// --- Case sensitivity ---

// DNS names are case-insensitive, and real resolvers randomize query name
// case (0x20 encoding) specifically as an anti-spoofing measure - so
// bailiwick matching must not be case-sensitive, or that defense would
// itself break referral/chain handling.
func TestFilterInBailiwick_CaseInsensitive(t *testing.T) {
	answer := []dns.RR{
		mustRR(t, "WWW.Example.COM. 60 IN CNAME APP.example.com."),
		mustRR(t, "app.EXAMPLE.com. 60 IN A 1.2.3.4"),
	}
	ns := []dns.RR{mustRR(t, "EXAMPLE.com. 3600 IN NS NS1.example.com.")}
	extra := []dns.RR{mustRR(t, "ns1.EXAMPLE.com. 3600 IN A 192.0.2.1")}

	gotAnswer, gotNs, gotExtra, zone := filterInBailiwick("com.", "www.example.com.", answer, ns, extra)

	if len(gotAnswer) != 2 {
		t.Fatalf("case-insensitive chain: got %d record(s), want 2: %v", len(gotAnswer), gotAnswer)
	}
	if len(gotNs) != 1 || zone == "" {
		t.Fatalf("case-insensitive referral: got ns=%v zone=%q", gotNs, zone)
	}
	if len(gotExtra) != 1 {
		t.Fatalf("case-insensitive glue: got %v", gotExtra)
	}
}
