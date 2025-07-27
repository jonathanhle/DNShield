package dns

import (
	"strings"
	"sync"
)

// Blocker manages domain blocking
type Blocker struct {
	mu             sync.RWMutex
	blockedDomains map[string]bool
	allowlist      map[string]bool // Renamed from whitelist

	// Track metadata for logging
	userEmail string
	groupName string
}

// NewBlocker creates a new domain blocker instance.
// The blocker maintains thread-safe maps of blocked domains and allowlist entries.
func NewBlocker() *Blocker {
	return &Blocker{
		blockedDomains: make(map[string]bool),
		allowlist:      make(map[string]bool),
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

// UpdateAllowlist updates the allowlist
func (b *Blocker) UpdateAllowlist(domains []string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.allowlist = make(map[string]bool)
	for _, domain := range domains {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if domain != "" {
			b.allowlist[domain] = true
		}
	}
}

// UpdateMetadata updates user and group information for logging
func (b *Blocker) UpdateMetadata(userEmail, groupName string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.userEmail = userEmail
	b.groupName = groupName
}

// IsBlocked checks if a domain should be blocked based on configured rules.
// It performs hierarchical matching, checking the full domain and parent
// domains against the blocklist while respecting whitelist entries.
//
// The lookup order is:
//  1. Check allowlist (if allowed, never block)
//  2. Check exact domain match in blocklist
//  3. Check parent domains (e.g., sub.example.com checks example.com)
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

	// Check allowlist first (allowlist always wins)
	if b.allowlist[domain] {
		return false
	}

	// Also check parent domains in allowlist
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts); i++ {
		parent := strings.Join(parts[i:], ".")
		if b.allowlist[parent] {
			return false
		}
	}

	// Check exact match
	if b.blockedDomains[domain] {
		return true
	}

	// Check parent domains in blocklist (e.g., subdomain.example.com → example.com)
	// Note: we already checked allowlist parent domains above
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

// GetAllowlistCount returns the number of allowed domains
func (b *Blocker) GetAllowlistCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.allowlist)
}

// GetMetadata returns the current user and group for logging
func (b *Blocker) GetMetadata() (userEmail, groupName string) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.userEmail, b.groupName
}
