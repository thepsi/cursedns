package resolver

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestCache_NXDomainAppliesToAllTypes(t *testing.T) {
	c := NewCache()
	c.SetNXDomain("nonexistent.example.com.", dns.ClassINET, time.Minute)

	if rcode, ok := c.GetNegative("nonexistent.example.com.", dns.TypeA, dns.ClassINET); !ok || rcode != dns.RcodeNameError {
		t.Fatalf("A: rcode=%d ok=%v, want RcodeNameError/true", rcode, ok)
	}
	if rcode, ok := c.GetNegative("nonexistent.example.com.", dns.TypeMX, dns.ClassINET); !ok || rcode != dns.RcodeNameError {
		t.Fatalf("MX: rcode=%d ok=%v, want RcodeNameError/true (NXDOMAIN covers all types)", rcode, ok)
	}
	if _, ok := c.GetNegative("other.example.com.", dns.TypeA, dns.ClassINET); ok {
		t.Fatal("unrelated name should not be affected")
	}
}

func TestCache_NoDataIsPerType(t *testing.T) {
	c := NewCache()
	c.SetNoData("example.com.", dns.TypeMX, dns.ClassINET, time.Minute)

	if rcode, ok := c.GetNegative("example.com.", dns.TypeMX, dns.ClassINET); !ok || rcode != dns.RcodeSuccess {
		t.Fatalf("MX: rcode=%d ok=%v, want RcodeSuccess/true", rcode, ok)
	}
	if _, ok := c.GetNegative("example.com.", dns.TypeA, dns.ClassINET); ok {
		t.Fatal("NODATA for MX must not apply to A")
	}
}

func TestCache_NegativeExpiry(t *testing.T) {
	c := NewCache()
	c.SetNXDomain("gone.example.com.", dns.ClassINET, 10*time.Millisecond)
	c.SetNoData("example.com.", dns.TypeMX, dns.ClassINET, 10*time.Millisecond)

	time.Sleep(30 * time.Millisecond)

	if _, ok := c.GetNegative("gone.example.com.", dns.TypeA, dns.ClassINET); ok {
		t.Fatal("expired NXDOMAIN entry should be gone")
	}
	if _, ok := c.GetNegative("example.com.", dns.TypeMX, dns.ClassINET); ok {
		t.Fatal("expired NODATA entry should be gone")
	}
}

func TestCache_PositiveAndNegativeDontLeakBetweenEachOther(t *testing.T) {
	c := NewCache()
	c.Set("example.com.", dns.TypeA, dns.ClassINET, []dns.RR{mustRR(t, "example.com. 300 IN A 1.2.3.4")})
	c.SetNoData("example.com.", dns.TypeMX, dns.ClassINET, time.Minute)

	if _, ok := c.GetNegative("example.com.", dns.TypeA, dns.ClassINET); ok {
		t.Fatal("a type with a positive cache entry must not also report a negative hit")
	}
	if _, ok := c.Get("example.com.", dns.TypeMX, dns.ClassINET); ok {
		t.Fatal("a type with only a negative cache entry must not report a positive hit")
	}
}

func TestNegativeTTL_UsesSmallerOfTTLAndMinimum(t *testing.T) {
	ns := []dns.RR{mustRR(t, "example.com. 3600 IN SOA ns1.example.com. hostmaster.example.com. 1 7200 3600 1209600 300")}

	got := negativeTTL("example.com.", ns)

	if got != 300*time.Second {
		t.Fatalf("got %v, want 300s (the MINIMUM field, smaller than the 3600s record TTL)", got)
	}
}

// A server trusted only for attacker.com must not be able to dictate how
// long we cache bank.com as absent by attaching a bogus SOA for it - the
// same bailiwick principle applied to referrals and glue elsewhere.
func TestNegativeTTL_IgnoresOutOfBailiwickSOA(t *testing.T) {
	ns := []dns.RR{mustRR(t, "bank.com. 3600 IN SOA ns1.bank.com. hostmaster.bank.com. 1 7200 3600 1209600 999999")}

	got := negativeTTL("attacker.com.", ns)

	if got != defaultNegativeTTL {
		t.Fatalf("got %v, want the default (%v); out-of-bailiwick SOA must be ignored", got, defaultNegativeTTL)
	}
}

func TestNegativeTTL_DefaultWhenNoSOA(t *testing.T) {
	got := negativeTTL("example.com.", nil)
	if got != defaultNegativeTTL {
		t.Fatalf("got %v, want default %v", got, defaultNegativeTTL)
	}
}

func TestHasNS(t *testing.T) {
	if hasNS(nil) {
		t.Fatal("empty slice should report false")
	}
	if hasNS([]dns.RR{mustRR(t, "example.com. 300 IN A 1.2.3.4")}) {
		t.Fatal("non-NS records should not count")
	}
	if !hasNS([]dns.RR{mustRR(t, "example.com. 300 IN NS ns1.example.com.")}) {
		t.Fatal("an NS record should be detected")
	}
}
