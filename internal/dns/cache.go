package dns

import (
	"fmt"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// CacheEntry represents a cached DNS response
type CacheEntry struct {
	Answer     []dns.RR
	Expiration time.Time
}

// Cache is a simple DNS cache
type Cache struct {
	mu      sync.RWMutex
	entries map[string]*CacheEntry
	maxSize int
	ttl     time.Duration
}

// NewCache creates a new DNS cache
func NewCache(maxSize int, ttl time.Duration) *Cache {
	return &Cache{
		entries: make(map[string]*CacheEntry),
		maxSize: maxSize,
		ttl:     ttl,
	}
}

// makeKey creates a cache key from domain and query type
func makeKey(domain string, qtype uint16) string {
	return fmt.Sprintf("%s:%d", domain, qtype)
}

// Get retrieves a cached response
func (c *Cache) Get(domain string, qtype uint16) []dns.RR {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	key := makeKey(domain, qtype)
	entry, exists := c.entries[key]
	if !exists {
		return nil
	}
	
	// Check if expired
	if time.Now().After(entry.Expiration) {
		return nil
	}
	
	// Return a copy of the answer
	answer := make([]dns.RR, len(entry.Answer))
	copy(answer, entry.Answer)
	return answer
}

// Set stores a response in the cache
func (c *Cache) Set(domain string, qtype uint16, answer []dns.RR) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	// Simple cache eviction - remove oldest entries if at capacity
	if len(c.entries) >= c.maxSize {
		// Remove ~10% of entries
		count := 0
		for k := range c.entries {
			delete(c.entries, k)
			count++
			if count > c.maxSize/10 {
				break
			}
		}
	}
	
	key := makeKey(domain, qtype)
	c.entries[key] = &CacheEntry{
		Answer:     answer,
		Expiration: time.Now().Add(c.ttl),
	}
}

// Clear empties the cache
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*CacheEntry)
}