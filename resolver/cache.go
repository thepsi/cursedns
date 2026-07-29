package resolver

import (
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Cache is a simple in-memory, TTL-aware record cache, keyed by question
// name/type/class.
type Cache struct {
	mu      sync.Mutex
	entries map[cacheKey]cacheEntry
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

// NewCache returns an empty Cache.
func NewCache() *Cache {
	return &Cache{
		entries: make(map[cacheKey]cacheEntry),
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
