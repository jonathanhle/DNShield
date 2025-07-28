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
	allowlist      map[string]bool // Renamed from whitelist
	allowOnlyMode  bool            // When true, block everything except allowlist

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

// UpdateWhitelist is a backward compatibility alias for UpdateAllowlist
func (b *Blocker) UpdateWhitelist(domains []string) {
	b.UpdateAllowlist(domains)
}

// UpdateMetadata updates user and group information for logging
func (b *Blocker) UpdateMetadata(userEmail, groupName string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.userEmail = userEmail
	b.groupName = groupName
}

// SetAllowOnlyMode enables or disables allow-only mode
func (b *Blocker) SetAllowOnlyMode(enabled bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.allowOnlyMode = enabled
}

// IsBlocked checks if a domain should be blocked based on configured rules.
// It supports two modes:
// 1. Normal mode: Block domains in blocklist unless they're in allowlist
// 2. Allow-only mode: Block everything except domains in allowlist
//
// The lookup order is:
//  1. Check if domain is a captive portal detection domain (never block)
//  2. Check allowlist (if allowed, never block)
//  3. In allow-only mode: block if not in allowlist
//  4. In normal mode: check blocklist
//  5. Check parent domains (e.g., sub.example.com checks example.com)
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

	// In allow-only mode, block everything not explicitly allowed
	if b.allowOnlyMode {
		return true
	}

	// Normal mode: check blocklist
	// Check exact match
	if b.blockedDomains[domain] {
		return true
	}

	// Check parent domains in blocklist (e.g., subdomain.example.com → example.com)
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

// IsAllowOnlyMode returns whether allow-only mode is enabled
func (b *Blocker) IsAllowOnlyMode() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.allowOnlyMode
}
