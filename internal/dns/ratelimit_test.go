package dns

import (
	"net"
	"testing"
	"time"
)

func TestRateLimiter(t *testing.T) {
	// Create rate limiter: 3 queries per 100ms
	rl := NewRateLimiter(3, 100*time.Millisecond)
	defer rl.Stop()
	
	clientIP := net.ParseIP("192.168.1.100")
	
	t.Run("AllowWithinLimit", func(t *testing.T) {
		// First 3 queries should be allowed
		for i := 0; i < 3; i++ {
			if !rl.Allow(clientIP) {
				t.Errorf("Query %d should be allowed", i+1)
			}
		}
		
		// 4th query should be denied
		if rl.Allow(clientIP) {
			t.Error("4th query should be denied")
		}
		
		// Check rate
		rate := rl.GetClientRate(clientIP)
		if rate != 3 {
			t.Errorf("Expected rate 3, got %d", rate)
		}
	})
	
	t.Run("AllowAfterWindow", func(t *testing.T) {
		// Wait for window to expire
		time.Sleep(150 * time.Millisecond)
		
		// Should allow queries again
		if !rl.Allow(clientIP) {
			t.Error("Query should be allowed after window expires")
		}
	})
	
	t.Run("DifferentClients", func(t *testing.T) {
		client1 := net.ParseIP("10.0.0.1")
		client2 := net.ParseIP("10.0.0.2")
		
		// Fill client1's quota
		for i := 0; i < 3; i++ {
			rl.Allow(client1)
		}
		
		// Client2 should still be allowed
		if !rl.Allow(client2) {
			t.Error("Different client should have separate quota")
		}
		
		// Client1 should be rate limited
		if rl.Allow(client1) {
			t.Error("Client1 should be rate limited")
		}
	})
	
	t.Run("Cleanup", func(t *testing.T) {
		// Create many clients
		for i := 0; i < 100; i++ {
			ip := net.IPv4(192, 168, byte(i/256), byte(i%256))
			rl.Allow(ip)
		}
		
		// Wait for entries to become old
		time.Sleep(300 * time.Millisecond)
		
		// Trigger cleanup
		rl.cleanup()
		
		// Old entries should be removed
		// (This is mainly to ensure cleanup doesn't panic)
	})
}

func TestRateLimiterConcurrency(t *testing.T) {
	rl := NewRateLimiter(100, time.Second)
	defer rl.Stop()
	
	// Test concurrent access from multiple goroutines
	done := make(chan bool)
	
	for i := 0; i < 10; i++ {
		go func(id int) {
			ip := net.IPv4(10, 0, 0, byte(id))
			for j := 0; j < 50; j++ {
				rl.Allow(ip)
				time.Sleep(time.Millisecond)
			}
			done <- true
		}(i)
	}
	
	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
	
	// If we get here without panic, concurrency is handled correctly
}