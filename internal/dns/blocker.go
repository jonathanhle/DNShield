package dns

import (
	"strings"
	"sync"
	
	"dnshield/internal/security"
)

// Blocker manages domain blocking
type Blocker struct {
	mu             sync.RWMutex
	blockedDomains map[string]bool
	whitelist      map[string]bool
}

// NewBlocker creates a new domain blocker instance.
// The blocker maintains thread-safe maps of blocked domains and whitelist entries.
func NewBlocker() *Blocker {
	return &Blocker{
		blockedDomains: make(map[string]bool),
		whitelist:      make(map[string]bool),
	}
}

// UpdateDomains updates the blocked domains list
func (b *Blocker) UpdateDomains(domains []string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Clear and rebuild
	b.blockedDomains = make(map[string]bool)
	for _, domain := range domains {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if domain != "" {
			b.blockedDomains[domain] = true
		}
	}
}

// UpdateWhitelist updates the whitelist
func (b *Blocker) UpdateWhitelist(domains []string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.whitelist = make(map[string]bool)
	for _, domain := range domains {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if domain != "" {
			b.whitelist[domain] = true
		}
	}
}

// IsBlocked checks if a domain should be blocked based on configured rules.
// It performs hierarchical matching, checking the full domain and parent
// domains against the blocklist while respecting whitelist entries.
//
// The lookup order is:
//  1. Check if domain is a captive portal detection domain (never block)
//  2. Check whitelist (if whitelisted, never block)
//  3. Check exact domain match in blocklist
//  4. Check parent domains (e.g., sub.example.com checks example.com)
//
// Example:
//
//	blocked := blocker.IsBlocked("ads.example.com")
//
// Thread-Safety: This method is safe for concurrent use.
func (b *Blocker) IsBlocked(domain string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()

	domain = strings.ToLower(domain)

	// Never block captive portal detection domains
	if security.IsCaptivePortalDomain(domain) {
		return false
	}

	// Check whitelist
	if b.whitelist[domain] {
		return false
	}

	// Check exact match
	if b.blockedDomains[domain] {
		return true
	}

	// Check parent domains (e.g., subdomain.example.com → example.com)
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts); i++ {
		parent := strings.Join(parts[i:], ".")
		if b.blockedDomains[parent] {
			return true
		}
	}

	return false
}

// GetBlockedCount returns the number of blocked domains
func (b *Blocker) GetBlockedCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.blockedDomains)
}
