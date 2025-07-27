package dns

import (
	"sync"
	"testing"
	"time"
	
	"dnshield/internal/config"
)

// TestCaptivePortalRealWorldScenarios tests realistic captive portal detection patterns
func TestCaptivePortalRealWorldScenarios(t *testing.T) {
	tests := []struct {
		name        string
		scenario    func(*CaptivePortalDetector)
		shouldBypass bool
		description string
	}{
		{
			name: "Apple Device Connection Pattern",
			scenario: func(d *CaptivePortalDetector) {
				// Simulate typical Apple device captive portal check sequence
				d.RecordRequest("captive.apple.com")
				time.Sleep(100 * time.Millisecond)
				d.RecordRequest("gsp64-ssl.ls.apple.com")
				time.Sleep(50 * time.Millisecond)
				d.RecordRequest("www.apple.com")
			},
			shouldBypass: true,
			description: "Apple devices check multiple domains in sequence",
		},
		{
			name: "Android Device Pattern",
			scenario: func(d *CaptivePortalDetector) {
				// Android 9+ pattern
				d.RecordRequest("connectivitycheck.gstatic.com")
				d.RecordRequest("www.google.com")
				time.Sleep(200 * time.Millisecond)
				d.RecordRequest("android.clients.google.com")
			},
			shouldBypass: true,
			description: "Android devices use multiple Google domains",
		},
		{
			name: "Windows 10/11 Pattern",
			scenario: func(d *CaptivePortalDetector) {
				// Windows connectivity check
				d.RecordRequest("www.msftconnecttest.com")
				d.RecordRequest("dns.msftncsi.com")
				time.Sleep(100 * time.Millisecond)
				d.RecordRequest("www.msftncsi.com")
				d.RecordRequest("www.msftconnecttest.com") // Retry
			},
			shouldBypass: true,
			description: "Windows often retries the same domain",
		},
		{
			name: "Coffee Shop WiFi (Starbucks Pattern)",
			scenario: func(d *CaptivePortalDetector) {
				// Starbucks Google WiFi pattern
				d.RecordRequest("captive.apple.com") // Device check
				time.Sleep(300 * time.Millisecond)
				d.RecordRequest("sbux-portal.globalreachtech.com")
				d.RecordRequest("datavalet.io")
			},
			shouldBypass: true,
			description: "Coffee shop portals often redirect to specific providers",
		},
		{
			name: "Airline WiFi (Gogo Pattern)",
			scenario: func(d *CaptivePortalDetector) {
				// In-flight WiFi connection
				d.RecordRequest("captive.apple.com")
				time.Sleep(500 * time.Millisecond) // Slower satellite connection
				d.RecordRequest("gogoinflight.com")
				d.RecordRequest("auth.gogoinflight.com")
			},
			shouldBypass: true,
			description: "Airline WiFi has longer delays between requests",
		},
		{
			name: "Hotel WiFi Multi-Stage",
			scenario: func(d *CaptivePortalDetector) {
				// Hotel WiFi often has multiple redirects
				d.RecordRequest("detectportal.firefox.com")
				time.Sleep(200 * time.Millisecond)
				d.RecordRequest("secure.guestinternet.com")
				time.Sleep(100 * time.Millisecond)
				d.RecordRequest("attwifi.com")
			},
			shouldBypass: true,
			description: "Hotels often use multiple redirect services",
		},
		{
			name: "False Positive Prevention",
			scenario: func(d *CaptivePortalDetector) {
				// User browsing to captive portal domains manually
				d.RecordRequest("captive.apple.com")
				time.Sleep(10 * time.Second) // Long delay
				d.RecordRequest("connectivitycheck.gstatic.com")
			},
			shouldBypass: false,
			description: "Long delays between requests shouldn't trigger bypass",
		},
		{
			name: "Mixed Traffic Pattern",
			scenario: func(d *CaptivePortalDetector) {
				// Mix of captive portal and regular domains
				d.RecordRequest("stackoverflow.com")
				d.RecordRequest("captive.apple.com")
				d.RecordRequest("github.com")
				d.RecordRequest("www.msftconnecttest.com")
				d.RecordRequest("reddit.com")
			},
			shouldBypass: false,
			description: "Mixed traffic shouldn't trigger bypass",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.CaptivePortalConfig{
				Enabled:            true,
				DetectionThreshold: 3,
				DetectionWindow:    5 * time.Second,
				BypassDuration:     5 * time.Minute,
			}
			detector := NewCaptivePortalDetector(cfg)
			
			tt.scenario(detector)
			
			if detector.IsInBypassMode() != tt.shouldBypass {
				t.Errorf("%s: expected bypass=%v, got %v. %s", 
					tt.name, tt.shouldBypass, detector.IsInBypassMode(), tt.description)
			}
		})
	}
}

// TestCaptivePortalTimeBasedBehavior tests time-sensitive scenarios
func TestCaptivePortalTimeBasedBehavior(t *testing.T) {
	t.Run("Detection Window Expiration", func(t *testing.T) {
		cfg := &config.CaptivePortalConfig{
			Enabled:            true,
			DetectionThreshold: 3,
			DetectionWindow:    2 * time.Second,
			BypassDuration:     5 * time.Minute,
		}
		detector := NewCaptivePortalDetector(cfg)
		
		// Add requests that should expire
		detector.RecordRequest("captive.apple.com")
		detector.RecordRequest("connectivitycheck.gstatic.com")
		
		// Wait for detection window to expire
		time.Sleep(2100 * time.Millisecond)
		
		// This should be the only "active" request
		detector.RecordRequest("detectportal.firefox.com")
		
		if detector.IsInBypassMode() {
			t.Error("Bypass should not trigger with expired requests")
		}
		
		// Now add more within window
		detector.RecordRequest("www.msftconnecttest.com")
		detector.RecordRequest("captive.apple.com")
		
		if !detector.IsInBypassMode() {
			t.Error("Bypass should trigger with 3 requests in window")
		}
	})
	
	t.Run("Bypass Mode Expiration", func(t *testing.T) {
		cfg := &config.CaptivePortalConfig{
			Enabled:            true,
			DetectionThreshold: 2,
			DetectionWindow:    5 * time.Second,
			BypassDuration:     1 * time.Second, // Very short for testing
		}
		detector := NewCaptivePortalDetector(cfg)
		
		// Trigger bypass
		detector.RecordRequest("captive.apple.com")
		detector.RecordRequest("connectivitycheck.gstatic.com")
		
		if !detector.IsInBypassMode() {
			t.Fatal("Bypass should be active")
		}
		
		// Check remaining time
		_, remaining := detector.GetBypassStatus()
		if remaining > 1*time.Second || remaining <= 0 {
			t.Errorf("Unexpected remaining time: %v", remaining)
		}
		
		// Wait for bypass to expire
		time.Sleep(1100 * time.Millisecond)
		
		if detector.IsInBypassMode() {
			t.Error("Bypass should have expired")
		}
	})
	
	t.Run("Bypass Extension Prevention", func(t *testing.T) {
		cfg := &config.CaptivePortalConfig{
			Enabled:            true,
			DetectionThreshold: 2,
			DetectionWindow:    5 * time.Second,
			BypassDuration:     2 * time.Second,
		}
		detector := NewCaptivePortalDetector(cfg)
		
		// Trigger bypass
		detector.RecordRequest("captive.apple.com")
		detector.RecordRequest("connectivitycheck.gstatic.com")
		
		originalEnd := time.Now().Add(2 * time.Second)
		
		// Wait a bit
		time.Sleep(500 * time.Millisecond)
		
		// More captive portal requests shouldn't extend bypass
		detector.RecordRequest("detectportal.firefox.com")
		detector.RecordRequest("www.msftconnecttest.com")
		
		// Check that end time hasn't changed significantly
		_, remaining := detector.GetBypassStatus()
		newEnd := time.Now().Add(remaining)
		
		if newEnd.Sub(originalEnd) > 100*time.Millisecond {
			t.Error("Bypass duration should not be extended by new requests")
		}
	})
}

// TestCaptivePortalConcurrency tests thread safety
func TestCaptivePortalConcurrency(t *testing.T) {
	cfg := &config.CaptivePortalConfig{
		Enabled:            true,
		DetectionThreshold: 10,
		DetectionWindow:    5 * time.Second,
		BypassDuration:     5 * time.Minute,
	}
	detector := NewCaptivePortalDetector(cfg)
	
	// Simulate concurrent DNS requests from multiple goroutines
	var wg sync.WaitGroup
	domains := []string{
		"captive.apple.com",
		"connectivitycheck.gstatic.com",
		"detectportal.firefox.com",
		"www.msftconnecttest.com",
		"example.com",
		"google.com",
	}
	
	// 100 goroutines making requests
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				domain := domains[j%len(domains)]
				detector.RecordRequest(domain)
				
				// Random operations
				if j%3 == 0 {
					detector.IsInBypassMode()
				}
				if j%5 == 0 {
					detector.GetBypassStatus()
				}
				
				time.Sleep(time.Duration(id%10) * time.Millisecond)
			}
		}(i)
	}
	
	// Concurrent manual operations
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			if i%2 == 0 {
				detector.EnableBypass()
			} else {
				detector.DisableBypass()
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()
	
	wg.Wait()
	
	// Just verify we didn't crash - the exact state depends on timing
	t.Log("Concurrent operations completed without panic")
}

// TestCaptivePortalEdgeCases tests various edge cases
func TestCaptivePortalEdgeCases(t *testing.T) {
	t.Run("Rapid Repeated Requests", func(t *testing.T) {
		cfg := &config.CaptivePortalConfig{
			Enabled:            true,
			DetectionThreshold: 3,
			DetectionWindow:    5 * time.Second,
			BypassDuration:     5 * time.Minute,
		}
		detector := NewCaptivePortalDetector(cfg)
		
		// Same domain requested many times rapidly
		for i := 0; i < 100; i++ {
			detector.RecordRequest("captive.apple.com")
		}
		
		// Should still count as one unique domain
		if detector.IsInBypassMode() {
			t.Error("Repeated requests to same domain shouldn't trigger bypass")
		}
		
		// Add different domains
		detector.RecordRequest("connectivitycheck.gstatic.com")
		detector.RecordRequest("detectportal.firefox.com")
		
		if !detector.IsInBypassMode() {
			t.Error("Should trigger with 3 unique domains")
		}
	})
	
	t.Run("Empty Domain Handling", func(t *testing.T) {
		cfg := &config.CaptivePortalConfig{
			Enabled:            true,
			DetectionThreshold: 2,
			DetectionWindow:    5 * time.Second,
			BypassDuration:     5 * time.Minute,
		}
		detector := NewCaptivePortalDetector(cfg)
		
		// Empty domains should be ignored
		detector.RecordRequest("")
		detector.RecordRequest("   ")
		detector.RecordRequest("captive.apple.com")
		detector.RecordRequest("")
		detector.RecordRequest("connectivitycheck.gstatic.com")
		
		if !detector.IsInBypassMode() {
			t.Error("Empty domains should be ignored in detection")
		}
	})
	
	t.Run("Case Sensitivity", func(t *testing.T) {
		cfg := &config.CaptivePortalConfig{
			Enabled:            true,
			DetectionThreshold: 3,
			DetectionWindow:    5 * time.Second,
			BypassDuration:     5 * time.Minute,
		}
		detector := NewCaptivePortalDetector(cfg)
		
		// DNS is case-insensitive
		detector.RecordRequest("Captive.Apple.Com")
		detector.RecordRequest("CONNECTIVITYCHECK.GSTATIC.COM")
		detector.RecordRequest("DetectPortal.Firefox.Com")
		
		if !detector.IsInBypassMode() {
			t.Error("Detection should be case-insensitive")
		}
	})
}

// TestCaptivePortalMetrics tests that we can gather useful metrics
func TestCaptivePortalMetrics(t *testing.T) {
	cfg := &config.CaptivePortalConfig{
		Enabled:            true,
		DetectionThreshold: 3,
		DetectionWindow:    5 * time.Second,
		BypassDuration:     5 * time.Minute,
	}
	detector := NewCaptivePortalDetector(cfg)
	
	// Track various events
	var (
		detectionCount int
		bypassCount    int
	)
	
	// Simulate multiple detection cycles
	for cycle := 0; cycle < 3; cycle++ {
		// Reset detector state
		detector.DisableBypass()
		time.Sleep(100 * time.Millisecond)
		
		// Record pattern
		detector.RecordRequest("captive.apple.com")
		detector.RecordRequest("connectivitycheck.gstatic.com")
		detector.RecordRequest("detectportal.firefox.com")
		
		if detector.IsInBypassMode() {
			detectionCount++
			bypassCount++
		}
		
		// Wait and try manual enable
		time.Sleep(200 * time.Millisecond)
		detector.EnableBypass()
		if detector.IsInBypassMode() {
			bypassCount++
		}
	}
	
	t.Logf("Detection cycles: %d, Total bypasses: %d", detectionCount, bypassCount)
	
	if detectionCount != 3 {
		t.Errorf("Expected 3 detection cycles, got %d", detectionCount)
	}
	
	if bypassCount != 6 { // 3 auto + 3 manual
		t.Errorf("Expected 6 total bypasses, got %d", bypassCount)
	}
}

// BenchmarkCaptivePortalDetection measures performance
func BenchmarkCaptivePortalDetection(b *testing.B) {
	cfg := &config.CaptivePortalConfig{
		Enabled:            true,
		DetectionThreshold: 3,
		DetectionWindow:    5 * time.Second,
		BypassDuration:     5 * time.Minute,
	}
	detector := NewCaptivePortalDetector(cfg)
	
	domains := []string{
		"captive.apple.com",
		"google.com",
		"connectivitycheck.gstatic.com",
		"facebook.com",
		"detectportal.firefox.com",
		"example.com",
	}
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		domain := domains[i%len(domains)]
		detector.RecordRequest(domain)
		detector.IsInBypassMode()
	}
}

// BenchmarkConcurrentDetection measures performance under concurrent load
func BenchmarkConcurrentDetection(b *testing.B) {
	cfg := &config.CaptivePortalConfig{
		Enabled:            true,
		DetectionThreshold: 3,
		DetectionWindow:    5 * time.Second,
		BypassDuration:     5 * time.Minute,
	}
	detector := NewCaptivePortalDetector(cfg)
	
	domains := []string{
		"captive.apple.com",
		"google.com",
		"connectivitycheck.gstatic.com",
		"facebook.com",
	}
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			domain := domains[i%len(domains)]
			detector.RecordRequest(domain)
			detector.IsInBypassMode()
			i++
		}
	})
}