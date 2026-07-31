package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"cursedns/resolver"
)

func mustRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("NewRR(%q): %v", s, err)
	}
	return rr
}

// fakeLookupKey identifies one scripted Lookup call by the parameters that
// matter for these tests - the nameservers argument is deliberately not
// part of the key, since it's derived from the previous step and not worth
// asserting on here.
type fakeLookupKey struct {
	name  string
	qtype uint16
	zone  string
}

type fakeLookupResp struct {
	result *resolver.LookupResult
	err    error
}

// fakeHelper is a deterministic, in-memory Helper for testing
// RecursiveHandler's iteration/restart logic without any real network I/O.
// Responses are either scripted directly via responses, or computed by
// lookupFunc when set (for tests that need an unbounded/generated chain of
// responses, like the hop-limit and CNAME-restart-limit tests).
type fakeHelper struct {
	t          *testing.T
	roots      []resolver.NameServer
	responses  map[fakeLookupKey]fakeLookupResp
	lookupFunc func(ctx context.Context, name string, qtype uint16, zone string, nameservers []resolver.NameServer) (*resolver.LookupResult, error)

	calls []fakeLookupKey
}

func newFakeHelper(t *testing.T) *fakeHelper {
	return &fakeHelper{
		t:         t,
		roots:     []resolver.NameServer{{Name: "a.root-servers.net.", Addr: netip.MustParseAddr("198.41.0.4")}},
		responses: make(map[fakeLookupKey]fakeLookupResp),
	}
}

func (f *fakeHelper) script(name string, qtype uint16, zone string, result *resolver.LookupResult, err error) {
	f.responses[fakeLookupKey{name: strings.ToLower(name), qtype: qtype, zone: strings.ToLower(zone)}] = fakeLookupResp{result: result, err: err}
}

func (f *fakeHelper) Lookup(ctx context.Context, name string, qtype uint16, zone string, nameservers []resolver.NameServer) (*resolver.LookupResult, error) {
	key := fakeLookupKey{name: strings.ToLower(name), qtype: qtype, zone: strings.ToLower(zone)}
	f.calls = append(f.calls, key)

	if f.lookupFunc != nil {
		return f.lookupFunc(ctx, name, qtype, zone, nameservers)
	}

	resp, ok := f.responses[key]
	if !ok {
		f.t.Fatalf("unexpected lookup: name=%s qtype=%s zone=%s", name, dns.TypeToString[qtype], zone)
	}
	return resp.result, resp.err
}

func (f *fakeHelper) RootHints() []resolver.NameServer { return f.roots }
func (f *fakeHelper) Trace(format string, args ...any) {}

func TestRecursiveHandler_MultiHopDelegation(t *testing.T) {
	h := newFakeHelper(t)
	h.script("example.com.", dns.TypeA, ".", &resolver.LookupResult{
		RCode: dns.RcodeSuccess,
		Ns:    []dns.RR{mustRR(t, "com. 172800 IN NS a.gtld-servers.net.")},
		Extra: []dns.RR{mustRR(t, "a.gtld-servers.net. 172800 IN A 192.5.6.30")},
	}, nil)
	h.script("example.com.", dns.TypeA, "com.", &resolver.LookupResult{
		RCode: dns.RcodeSuccess,
		Ns:    []dns.RR{mustRR(t, "example.com. 172800 IN NS ns1.example.com.")},
		Extra: []dns.RR{mustRR(t, "ns1.example.com. 172800 IN A 192.0.2.1")},
	}, nil)
	h.script("example.com.", dns.TypeA, "example.com.", &resolver.LookupResult{
		RCode:  dns.RcodeSuccess,
		Answer: []dns.RR{mustRR(t, "example.com. 300 IN A 93.184.216.34")},
	}, nil)

	resp, err := (&RecursiveHandler{}).Handle(context.Background(), resolver.Query{Name: "example.com.", Type: dns.TypeA}, h)
	if err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}
	if resp.RCode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("got RCode=%d Answer=%v, want a single A record", resp.RCode, resp.Answer)
	}
	if len(h.calls) != 3 {
		t.Fatalf("got %d lookup call(s), want exactly 3 (root, com., example.com.): %v", len(h.calls), h.calls)
	}
}

func TestRecursiveHandler_InBailiwickCNAMEChainNoRestart(t *testing.T) {
	h := newFakeHelper(t)
	h.script("www.example.com.", dns.TypeA, ".", &resolver.LookupResult{
		RCode: dns.RcodeSuccess,
		Answer: []dns.RR{
			mustRR(t, "www.example.com. 300 IN CNAME app.example.com."),
			mustRR(t, "app.example.com. 300 IN A 1.2.3.4"),
		},
	}, nil)

	resp, err := (&RecursiveHandler{}).Handle(context.Background(), resolver.Query{Name: "www.example.com.", Type: dns.TypeA}, h)
	if err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}
	if len(resp.Answer) != 2 {
		t.Fatalf("got %d answer record(s), want 2 (CNAME + A): %v", len(resp.Answer), resp.Answer)
	}
	if len(h.calls) != 1 {
		t.Fatalf("got %d lookup call(s), want exactly 1 (no restart should have been needed): %v", len(h.calls), h.calls)
	}
}

func TestRecursiveHandler_CNAMECrossingZonesRestarts(t *testing.T) {
	h := newFakeHelper(t)
	// The previous zone's server can only vouch for the CNAME itself; the
	// target's data was cut by filterInBailiwick, so only the CNAME comes
	// back here.
	h.script("www.example.com.", dns.TypeA, ".", &resolver.LookupResult{
		RCode:  dns.RcodeSuccess,
		Answer: []dns.RR{mustRR(t, "www.example.com. 300 IN CNAME cdn.other.net.")},
	}, nil)
	h.script("cdn.other.net.", dns.TypeA, ".", &resolver.LookupResult{
		RCode:  dns.RcodeSuccess,
		Answer: []dns.RR{mustRR(t, "cdn.other.net. 300 IN A 9.9.9.9")},
	}, nil)

	resp, err := (&RecursiveHandler{}).Handle(context.Background(), resolver.Query{Name: "www.example.com.", Type: dns.TypeA}, h)
	if err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}
	if len(resp.Answer) != 2 {
		t.Fatalf("got %d answer record(s), want 2 (CNAME + restarted A): %v", len(resp.Answer), resp.Answer)
	}
	if len(h.calls) != 2 {
		t.Fatalf("got %d lookup call(s), want exactly 2 (one restart): %v", len(h.calls), h.calls)
	}
}

func TestRecursiveHandler_GluelessReferralResolvesNameserverAddress(t *testing.T) {
	h := newFakeHelper(t)
	h.script("example.com.", dns.TypeA, ".", &resolver.LookupResult{
		RCode: dns.RcodeSuccess,
		Ns:    []dns.RR{mustRR(t, "example.com. 300 IN NS ns1.example.com.")},
		// No Extra/glue at all.
	}, nil)
	h.script("ns1.example.com.", dns.TypeA, ".", &resolver.LookupResult{
		RCode:  dns.RcodeSuccess,
		Answer: []dns.RR{mustRR(t, "ns1.example.com. 300 IN A 192.0.2.1")},
	}, nil)
	h.script("example.com.", dns.TypeA, "example.com.", &resolver.LookupResult{
		RCode:  dns.RcodeSuccess,
		Answer: []dns.RR{mustRR(t, "example.com. 300 IN A 93.184.216.34")},
	}, nil)

	resp, err := (&RecursiveHandler{}).Handle(context.Background(), resolver.Query{Name: "example.com.", Type: dns.TypeA}, h)
	if err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("got %d answer record(s), want 1: %v", len(resp.Answer), resp.Answer)
	}
}

func TestRecursiveHandler_NXDomainKeepsAccumulatedCNAMEAnswer(t *testing.T) {
	h := newFakeHelper(t)
	h.script("www.example.com.", dns.TypeA, ".", &resolver.LookupResult{
		RCode:  dns.RcodeSuccess,
		Answer: []dns.RR{mustRR(t, "www.example.com. 300 IN CNAME ghost.example.org.")},
	}, nil)
	h.script("ghost.example.org.", dns.TypeA, ".", &resolver.LookupResult{
		RCode: dns.RcodeNameError,
		Ns:    []dns.RR{mustRR(t, "org. 3600 IN SOA a.iana-servers.net. hostmaster.org. 1 7200 3600 1209600 300")},
	}, nil)

	resp, err := (&RecursiveHandler{}).Handle(context.Background(), resolver.Query{Name: "www.example.com.", Type: dns.TypeA}, h)
	if err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}
	if resp.RCode != dns.RcodeNameError {
		t.Fatalf("RCode = %d, want RcodeNameError", resp.RCode)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("got %d answer record(s), want the CNAME to survive: %v", len(resp.Answer), resp.Answer)
	}
	if len(resp.Ns) != 1 {
		t.Fatalf("got %d ns record(s), want the SOA passed through: %v", len(resp.Ns), resp.Ns)
	}
}

func TestRecursiveHandler_NoData(t *testing.T) {
	h := newFakeHelper(t)
	h.script("example.com.", dns.TypeMX, ".", &resolver.LookupResult{
		RCode: dns.RcodeSuccess,
		Ns:    []dns.RR{mustRR(t, "example.com. 3600 IN SOA ns1.example.com. hostmaster.example.com. 1 7200 3600 1209600 300")},
	}, nil)

	resp, err := (&RecursiveHandler{}).Handle(context.Background(), resolver.Query{Name: "example.com.", Type: dns.TypeMX}, h)
	if err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}
	if resp.RCode != dns.RcodeSuccess {
		t.Fatalf("RCode = %d, want RcodeSuccess", resp.RCode)
	}
	if len(resp.Answer) != 0 {
		t.Fatalf("got %d answer record(s), want 0 (NODATA): %v", len(resp.Answer), resp.Answer)
	}
	if len(resp.Ns) != 1 {
		t.Fatalf("got %d ns record(s), want the SOA passed through: %v", len(resp.Ns), resp.Ns)
	}
}

// labelDeeper returns the zone that is exactly one label longer than zone
// while remaining a suffix of name, e.g. labelDeeper("a.b.example.com.",
// "example.com.") == "b.example.com.".
func labelDeeper(t *testing.T, name, zone string) string {
	t.Helper()
	nameLabels := dns.SplitDomainName(name)
	zoneLabels := dns.SplitDomainName(zone)
	n := len(zoneLabels) + 1
	if n > len(nameLabels) {
		t.Fatalf("labelDeeper: zone %q is already as deep as name %q", zone, name)
	}
	return strings.Join(nameLabels[len(nameLabels)-n:], ".") + "."
}

func TestRecursiveHandler_HopLimitExceeded(t *testing.T) {
	// 25 "h" labels beneath example.com. - deep enough that fully resolving
	// would take well over maxHops referrals, each one making genuine
	// forward progress (so the hop-count limit, not the no-progress guard,
	// is what ends this).
	var parts []string
	for i := 0; i < 25; i++ {
		parts = append(parts, "h")
	}
	name := strings.Join(parts, ".") + ".example.com."

	h := newFakeHelper(t)
	h.lookupFunc = func(ctx context.Context, qname string, qtype uint16, zone string, nameservers []resolver.NameServer) (*resolver.LookupResult, error) {
		child := labelDeeper(t, name, zone)
		return &resolver.LookupResult{
			RCode: dns.RcodeSuccess,
			Ns:    []dns.RR{mustRR(t, fmt.Sprintf("%s 300 IN NS ns.%s", child, child))},
			Extra: []dns.RR{mustRR(t, fmt.Sprintf("ns.%s 300 IN A 192.0.2.1", child))},
		}, nil
	}

	_, err := (&RecursiveHandler{}).Handle(context.Background(), resolver.Query{Name: name, Type: dns.TypeA}, h)
	if err == nil {
		t.Fatal("expected an error from exceeding the hop limit, got nil")
	}
	if len(h.calls) != maxHops {
		t.Fatalf("got %d lookup call(s), want exactly maxHops (%d)", len(h.calls), maxHops)
	}
}

func TestRecursiveHandler_CNAMERestartLimitExceeded(t *testing.T) {
	h := newFakeHelper(t)
	h.lookupFunc = func(ctx context.Context, qname string, qtype uint16, zone string, nameservers []resolver.NameServer) (*resolver.LookupResult, error) {
		target := "x" + qname
		return &resolver.LookupResult{
			RCode:  dns.RcodeSuccess,
			Answer: []dns.RR{mustRR(t, fmt.Sprintf("%s 300 IN CNAME %s", qname, target))},
		}, nil
	}

	_, err := (&RecursiveHandler{}).Handle(context.Background(), resolver.Query{Name: "www.example.com.", Type: dns.TypeA}, h)
	if err == nil {
		t.Fatal("expected an error from exceeding the CNAME restart limit, got nil")
	}
}

func TestRecursiveHandler_LookupErrorPropagates(t *testing.T) {
	h := newFakeHelper(t)
	wantErr := errors.New("network unreachable")
	h.script("example.com.", dns.TypeA, ".", nil, wantErr)

	_, err := (&RecursiveHandler{}).Handle(context.Background(), resolver.Query{Name: "example.com.", Type: dns.TypeA}, h)
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want it to wrap %v", err, wantErr)
	}
}

func TestRecursiveHandler_QueryingCNAMEDirectlyDoesNotRestart(t *testing.T) {
	h := newFakeHelper(t)
	h.script("www.example.com.", dns.TypeCNAME, ".", &resolver.LookupResult{
		RCode:  dns.RcodeSuccess,
		Answer: []dns.RR{mustRR(t, "www.example.com. 300 IN CNAME app.example.com.")},
	}, nil)

	resp, err := (&RecursiveHandler{}).Handle(context.Background(), resolver.Query{Name: "www.example.com.", Type: dns.TypeCNAME}, h)
	if err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("got %d answer record(s), want just the CNAME itself: %v", len(resp.Answer), resp.Answer)
	}
	if len(h.calls) != 1 {
		t.Fatalf("got %d lookup call(s), want exactly 1 (a CNAME query must never restart to chase its own target): %v", len(h.calls), h.calls)
	}
}
