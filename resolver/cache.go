package resolver

import (
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Cache is a simple in-memory, TTL-aware record cache, keyed by question
// name/type/class. It also holds negative (NXDOMAIN/NODATA) entries.
type Cache struct {
	mu       sync.Mutex
	entries  map[cacheKey]cacheEntry
	nxdomain map[negNameKey]negEntry
	nodata   map[cacheKey]negEntry
}

type cacheKey struct {
	name   string
	qtype  uint16
	qclass uint16
}

type cacheEntry struct {
	rrs     []dns.RR
	expires time.Time
}

// negNameKey is unqualified by type: an NXDOMAIN response asserts that name
// doesn't exist at all, for any type, per RFC 2308.
type negNameKey struct {
	name   string
	qclass uint16
}

type negEntry struct {
	expires time.Time
}

// NewCache returns an empty Cache.
func NewCache() *Cache {
	return &Cache{
		entries:  make(map[cacheKey]cacheEntry),
		nxdomain: make(map[negNameKey]negEntry),
		nodata:   make(map[cacheKey]negEntry),
	}
}

// Get returns the cached records for (name, qtype, qclass), if present and
// not expired.
func (c *Cache) Get(name string, qtype, qclass uint16) ([]dns.RR, bool) {
	key := cacheKey{name: name, qtype: qtype, qclass: qclass}

	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	if time.Now().After(entry.expires) {
		delete(c.entries, key)
		return nil, false
	}
	return entry.rrs, true
}

// Set stores rrs under (name, qtype, qclass), expiring them after the
// smallest TTL among rrs.
func (c *Cache) Set(name string, qtype, qclass uint16, rrs []dns.RR) {
	if len(rrs) == 0 {
		return
	}

	ttl := rrs[0].Header().Ttl
	for _, rr := range rrs[1:] {
		if rr.Header().Ttl < ttl {
			ttl = rr.Header().Ttl
		}
	}

	key := cacheKey{name: name, qtype: qtype, qclass: qclass}
	entry := cacheEntry{
		rrs:     rrs,
		expires: time.Now().Add(time.Duration(ttl) * time.Second),
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = entry
}

// GetNegative reports whether (name, qtype, qclass) is covered by a cached
// negative response, returning the RCODE to answer with (dns.RcodeNameError
// for NXDOMAIN, dns.RcodeSuccess for NODATA).
//
// NXDOMAIN is checked independently of qtype: per RFC 2308, it asserts name
// doesn't exist at all, not just for the type originally queried.
func (c *Cache) GetNegative(name string, qtype, qclass uint16) (rcode int, ok bool) {
	nameKey := negNameKey{name: name, qclass: qclass}
	typeKey := cacheKey{name: name, qtype: qtype, qclass: qclass}

	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, ok := c.nxdomain[nameKey]; ok {
		if time.Now().After(entry.expires) {
			delete(c.nxdomain, nameKey)
		} else {
			return dns.RcodeNameError, true
		}
	}
	if entry, ok := c.nodata[typeKey]; ok {
		if time.Now().After(entry.expires) {
			delete(c.nodata, typeKey)
		} else {
			return dns.RcodeSuccess, true
		}
	}
	return 0, false
}

// SetNXDomain records that name does not exist, for ttl, at any type.
func (c *Cache) SetNXDomain(name string, qclass uint16, ttl time.Duration) {
	key := negNameKey{name: name, qclass: qclass}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nxdomain[key] = negEntry{expires: time.Now().Add(ttl)}
}

// SetNoData records that (name, qtype, qclass) exists but has no records of
// that type, for ttl.
func (c *Cache) SetNoData(name string, qtype, qclass uint16, ttl time.Duration) {
	key := cacheKey{name: name, qtype: qtype, qclass: qclass}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nodata[key] = negEntry{expires: time.Now().Add(ttl)}
}
