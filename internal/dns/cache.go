package dns

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// CacheEntry represents a cached DNS response
type CacheEntry struct {
	Answer     []dns.RR
	Expiration time.Time
}

// Cache is a simple DNS cache
type Cache struct {
	mu         sync.RWMutex
	entries    map[string]*CacheEntry
	maxSize    int
	ttl        time.Duration
	shutdownCh chan struct{}
	wg         sync.WaitGroup
}

// NewCache creates a new DNS cache
func NewCache(maxSize int, ttl time.Duration) *Cache {
	c := &Cache{
		entries:    make(map[string]*CacheEntry),
		maxSize:    maxSize,
		ttl:        ttl,
		shutdownCh: make(chan struct{}),
	}
	
	// Start cleanup goroutine
	c.wg.Add(1)
	go c.cleanupExpired()
	
	return c
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

	// Evict expired entries first if at capacity
	if len(c.entries) >= c.maxSize {
		c.evictExpiredUnlocked()
	}
	
	// If still at capacity, evict oldest entries
	if len(c.entries) >= c.maxSize {
		c.evictOldestUnlocked(c.maxSize / 10) // Remove 10%
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

// cleanupExpired runs periodically to remove expired entries
func (c *Cache) cleanupExpired() {
	defer c.wg.Done()
	
	// Run cleanup every minute
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-c.shutdownCh:
			return
		case <-ticker.C:
			c.removeExpired()
		}
	}
}

// removeExpired removes all expired entries from the cache
func (c *Cache) removeExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	now := time.Now()
	expiredCount := 0
	
	for key, entry := range c.entries {
		if now.After(entry.Expiration) {
			delete(c.entries, key)
			expiredCount++
		}
	}
	
	if expiredCount > 0 {
		logrus.WithField("count", expiredCount).Debug("Removed expired DNS cache entries")
	}
}

// evictExpiredUnlocked removes expired entries (must be called with lock held)
func (c *Cache) evictExpiredUnlocked() int {
	now := time.Now()
	expiredCount := 0
	
	for key, entry := range c.entries {
		if now.After(entry.Expiration) {
			delete(c.entries, key)
			expiredCount++
		}
	}
	
	return expiredCount
}

// evictOldestUnlocked removes the oldest entries (must be called with lock held)
func (c *Cache) evictOldestUnlocked(count int) {
	if count <= 0 || len(c.entries) == 0 {
		return
	}
	
	// Find entries sorted by expiration
	type expiryEntry struct {
		key        string
		expiration time.Time
	}
	
	entries := make([]expiryEntry, 0, len(c.entries))
	for key, entry := range c.entries {
		entries = append(entries, expiryEntry{
			key:        key,
			expiration: entry.Expiration,
		})
	}
	
	// Sort by expiration time (oldest first)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].expiration.Before(entries[j].expiration)
	})
	
	// Remove the oldest entries
	toRemove := count
	if toRemove > len(entries) {
		toRemove = len(entries)
	}
	
	for i := 0; i < toRemove; i++ {
		delete(c.entries, entries[i].key)
	}
	
	if toRemove > 0 {
		logrus.WithField("count", toRemove).Debug("Evicted oldest DNS cache entries")
	}
}

// Stop gracefully shuts down the cache
func (c *Cache) Stop() {
	close(c.shutdownCh)
	c.wg.Wait()
}
