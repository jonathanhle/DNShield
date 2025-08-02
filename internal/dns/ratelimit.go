package dns

import (
	"net"
	"sync"
	"time"
)

// RateLimiter implements rate limiting for DNS queries
type RateLimiter struct {
	mu          sync.Mutex
	clients     map[string]*clientInfo
	maxQueries  int           // Max queries per window
	window      time.Duration // Time window
	cleanupTime time.Duration // How often to clean up old entries
	lastCleanup time.Time
	shutdownCh  chan struct{}
	wg          sync.WaitGroup
}

type clientInfo struct {
	queries []time.Time
}

// NewRateLimiter creates a new DNS rate limiter
func NewRateLimiter(maxQueries int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		clients:     make(map[string]*clientInfo),
		maxQueries:  maxQueries,
		window:      window,
		cleanupTime: 5 * time.Minute,
		lastCleanup: time.Now(),
		shutdownCh:  make(chan struct{}),
	}
	
	// Start cleanup goroutine
	rl.wg.Add(1)
	go rl.cleanupRoutine()
	
	return rl
}

// Allow checks if a client is allowed to make a query
func (rl *RateLimiter) Allow(clientIP net.IP) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	// Get client key
	key := clientIP.String()
	
	// Get or create client info
	client, exists := rl.clients[key]
	if !exists {
		client = &clientInfo{
			queries: make([]time.Time, 0, rl.maxQueries),
		}
		rl.clients[key] = client
	}
	
	now := time.Now()
	cutoff := now.Add(-rl.window)
	
	// Remove old queries outside the window
	validQueries := make([]time.Time, 0, len(client.queries))
	for _, queryTime := range client.queries {
		if queryTime.After(cutoff) {
			validQueries = append(validQueries, queryTime)
		}
	}
	client.queries = validQueries
	
	// Check if limit exceeded
	if len(client.queries) >= rl.maxQueries {
		return false
	}
	
	// Add current query
	client.queries = append(client.queries, now)
	return true
}

// GetClientRate returns the current query rate for a client
func (rl *RateLimiter) GetClientRate(clientIP net.IP) int {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	key := clientIP.String()
	client, exists := rl.clients[key]
	if !exists {
		return 0
	}
	
	now := time.Now()
	cutoff := now.Add(-rl.window)
	
	count := 0
	for _, queryTime := range client.queries {
		if queryTime.After(cutoff) {
			count++
		}
	}
	
	return count
}

// cleanup removes old client entries to prevent memory leak
func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	now := time.Now()
	cutoff := now.Add(-rl.window * 2) // Keep entries for 2x the window
	
	for key, client := range rl.clients {
		// Check if client has any recent queries
		hasRecent := false
		for _, queryTime := range client.queries {
			if queryTime.After(cutoff) {
				hasRecent = true
				break
			}
		}
		
		// Remove if no recent queries
		if !hasRecent {
			delete(rl.clients, key)
		}
	}
	
	rl.lastCleanup = now
}

// cleanupRoutine runs periodic cleanup
func (rl *RateLimiter) cleanupRoutine() {
	defer rl.wg.Done()
	ticker := time.NewTicker(rl.cleanupTime)
	defer ticker.Stop()
	
	for {
		select {
		case <-rl.shutdownCh:
			return
		case <-ticker.C:
			rl.cleanup()
		}
	}
}

// Stop stops the rate limiter and cleans up resources
func (rl *RateLimiter) Stop() {
	close(rl.shutdownCh)
	rl.wg.Wait()
}