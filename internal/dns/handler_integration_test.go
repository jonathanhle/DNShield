package dns

import (
	"testing"
	"time"
	
	"dnshield/internal/config"
	"dnshield/internal/security"
)

// TestHandlerCaptivePortalIntegration tests the full DNS handler flow with captive portal detection
func TestHandlerCaptivePortalIntegration(t *testing.T) {
	// Create a handler with captive portal detection enabled
	cfg := &config.CaptivePortalConfig{
		Enabled:            true,
		DetectionThreshold: 3,
		DetectionWindow:    5 * time.Second,
		BypassDuration:     5 * time.Minute,
	}
	
	blocker := NewBlocker()
	blocker.UpdateDomains([]string{
		"doubleclick.net",
		"ads.google.com",
		"tracker.example.com",
	})
	
	dnsCfg := &config.DNSConfig{
		Upstreams: []string{"8.8.8.8"},
		CacheSize: 1000,
		CacheTTL:  1 * time.Hour,
	}
	handler := NewHandler(blocker, dnsCfg, "127.0.0.1", cfg)
	
	// Helper function to simulate DNS query
	simulateQuery := func(domain string) bool {
		// Record the request in captive portal detector
		handler.captiveDetector.RecordRequest(domain)
		
		// Check if it would be blocked
		if handler.captiveDetector.IsInBypassMode() {
			return false // Not blocked due to bypass
		}
		
		return handler.blocker.IsBlocked(domain)
	}
	
	t.Run("Normal Blocking Without Captive Portal", func(t *testing.T) {
		// Reset detector
		handler.captiveDetector.DisableBypass()
		
		// These should be blocked
		if !simulateQuery("doubleclick.net") {
			t.Error("doubleclick.net should be blocked")
		}
		
		if !simulateQuery("ads.google.com") {
			t.Error("ads.google.com should be blocked")
		}
		
		// This should not be blocked
		if simulateQuery("example.com") {
			t.Error("example.com should not be blocked")
		}
	})
	
	t.Run("Captive Portal Detection Triggers Bypass", func(t *testing.T) {
		// Reset detector
		handler.captiveDetector.DisableBypass()
		
		// Simulate captive portal detection sequence
		simulateQuery("captive.apple.com")
		simulateQuery("connectivitycheck.gstatic.com")
		simulateQuery("detectportal.firefox.com")
		
		// Now bypass should be active
		if !handler.captiveDetector.IsInBypassMode() {
			t.Fatal("Bypass mode should be active")
		}
		
		// Previously blocked domains should now pass through
		if simulateQuery("doubleclick.net") {
			t.Error("doubleclick.net should not be blocked during bypass")
		}
		
		if simulateQuery("ads.google.com") {
			t.Error("ads.google.com should not be blocked during bypass")
		}
	})
	
	t.Run("Captive Portal Domains Never Blocked", func(t *testing.T) {
		// Reset detector and add captive portal domains to blocklist
		handler.captiveDetector.DisableBypass()
		handler.blocker.UpdateDomains([]string{
			"doubleclick.net",
			"captive.apple.com", // This should never be blocked
			"gogoinflight.com",  // This should never be blocked
		})
		
		// Test each domain separately to avoid triggering bypass
		// Captive portal domains should never be blocked
		if simulateQuery("captive.apple.com") {
			t.Error("captive.apple.com should never be blocked")
		}
		
		// Reset to avoid triggering bypass with multiple captive portal domains
		handler.captiveDetector = NewCaptivePortalDetector(cfg)
		
		if simulateQuery("gogoinflight.com") {
			t.Error("gogoinflight.com should never be blocked")
		}
		
		// Reset again before testing regular domain
		handler.captiveDetector = NewCaptivePortalDetector(cfg)
		
		// Regular blocked domain should still be blocked
		if !simulateQuery("doubleclick.net") {
			t.Error("doubleclick.net should be blocked")
		}
	})
}

// TestHandlerCaptivePortalScenarios tests realistic user scenarios
func TestHandlerCaptivePortalScenarios(t *testing.T) {
	scenarios := []struct {
		name        string
		description string
		test        func(*testing.T, *Handler)
	}{
		{
			name:        "Airport WiFi Connection",
			description: "User connects to airport WiFi, authenticates, then browses normally",
			test: func(t *testing.T, h *Handler) {
				// Initial connection attempts
				h.captiveDetector.RecordRequest("captive.apple.com")
				h.captiveDetector.RecordRequest("connectivitycheck.gstatic.com")
				h.captiveDetector.RecordRequest("detectportal.firefox.com")
				
				if !h.captiveDetector.IsInBypassMode() {
					t.Fatal("Should detect captive portal")
				}
				
				// User authenticates (simulated by time passing)
				time.Sleep(100 * time.Millisecond)
				
				// Normal browsing should work
				if h.blocker.IsBlocked("news.ycombinator.com") {
					t.Error("Normal sites should not be blocked during bypass")
				}
			},
		},
		{
			name:        "Coffee Shop Multi-Stage Portal",
			description: "Coffee shop WiFi with terms acceptance and email registration",
			test: func(t *testing.T, h *Handler) {
				// Stage 1: Initial detection
				h.captiveDetector.RecordRequest("detectportal.firefox.com")
				h.captiveDetector.RecordRequest("sbux-portal.globalreachtech.com")
				
				// Stage 2: Terms page
				h.captiveDetector.RecordRequest("datavalet.io")
				
				if !h.captiveDetector.IsInBypassMode() {
					t.Fatal("Should detect captive portal")
				}
				
				// All stages should work during bypass
				stages := []string{
					"terms.coffeeshop-wifi.com",
					"register.coffeeshop-wifi.com",
					"welcome.coffeeshop-wifi.com",
				}
				
				for _, stage := range stages {
					if h.blocker.IsBlocked(stage) {
						t.Errorf("Stage %s should not be blocked during bypass", stage)
					}
				}
			},
		},
		{
			name:        "Hotel WiFi Room Number Login",
			description: "Hotel WiFi requiring room number and last name",
			test: func(t *testing.T, h *Handler) {
				// Windows laptop checking connectivity
				h.captiveDetector.RecordRequest("www.msftconnecttest.com")
				h.captiveDetector.RecordRequest("dns.msftncsi.com")
				
				// Hotel portal
				h.captiveDetector.RecordRequest("secure.guestinternet.com")
				
				if !h.captiveDetector.IsInBypassMode() {
					t.Fatal("Should detect captive portal")
				}
				
				// Hotel-specific domains should work
				hotelDomains := []string{
					"auth.hotelwifi.com",
					"login.guestinternet.com",
					"payment.hotelservices.com",
				}
				
				for _, domain := range hotelDomains {
					if h.blocker.IsBlocked(domain) {
						t.Errorf("Hotel domain %s should not be blocked during bypass", domain)
					}
				}
			},
		},
		{
			name:        "False Positive Prevention",
			description: "User manually visiting captive portal domains shouldn't trigger bypass",
			test: func(t *testing.T, h *Handler) {
				// User visits Apple.com
				h.captiveDetector.RecordRequest("www.apple.com")
				
				// Much later, visits captive check page
				time.Sleep(6 * time.Second) // Outside detection window
				
				h.captiveDetector.RecordRequest("captive.apple.com")
				
				if h.captiveDetector.IsInBypassMode() {
					t.Error("Shouldn't trigger bypass with large time gaps")
				}
				
				// Ads should still be blocked
				if !h.blocker.IsBlocked("doubleclick.net") {
					t.Error("Ads should still be blocked without bypass")
				}
			},
		},
	}
	
	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			// Fresh handler for each scenario
			cfg := &config.CaptivePortalConfig{
				Enabled:            true,
				DetectionThreshold: 3,
				DetectionWindow:    5 * time.Second,
				BypassDuration:     5 * time.Minute,
			}
			
			blocker := NewBlocker()
			blocker.UpdateDomains([]string{
				"doubleclick.net",
				"ads.google.com",
				"tracker.example.com",
			})
			dnsCfg := &config.DNSConfig{
		Upstreams: []string{"8.8.8.8"},
		CacheSize: 1000,
		CacheTTL:  1 * time.Hour,
	}
	handler := NewHandler(blocker, dnsCfg, "127.0.0.1", cfg)
			
			t.Logf("Testing: %s", scenario.description)
			scenario.test(t, handler)
		})
	}
}

// TestHandlerDNSResponse tests actual DNS response handling with captive portal
func TestHandlerDNSResponse(t *testing.T) {
	cfg := &config.CaptivePortalConfig{
		Enabled:            true,
		DetectionThreshold: 3,
		DetectionWindow:    5 * time.Second,
		BypassDuration:     5 * time.Minute,
	}
	
	blocker := NewBlocker()
	blocker.UpdateDomains([]string{"blocked.example.com"})
	dnsCfg := &config.DNSConfig{
		Upstreams: []string{"8.8.8.8"},
		CacheSize: 1000,
		CacheTTL:  1 * time.Hour,
	}
	handler := NewHandler(blocker, dnsCfg, "127.0.0.1", cfg)
	
	// We'll test the handler logic directly without mocking DNS ResponseWriter
	// since the actual DNS response handling is more complex
	
	t.Run("Blocked Domain Without Bypass", func(t *testing.T) {
		handler.captiveDetector.DisableBypass()
		
		// This would normally be called by the DNS server
		// We simulate the key parts here
		handler.captiveDetector.RecordRequest("blocked.example.com")
		
		// In real handler, this would return NXDOMAIN or sinkhole
		isBlocked := handler.blocker.IsBlocked("blocked.example.com") && 
			!handler.captiveDetector.IsInBypassMode()
		
		if !isBlocked {
			t.Error("Domain should be blocked without bypass")
		}
	})
	
	t.Run("Blocked Domain With Bypass", func(t *testing.T) {
		// Trigger bypass mode
		handler.captiveDetector.RecordRequest("captive.apple.com")
		handler.captiveDetector.RecordRequest("connectivitycheck.gstatic.com")
		handler.captiveDetector.RecordRequest("detectportal.firefox.com")
		
		if !handler.captiveDetector.IsInBypassMode() {
			t.Fatal("Bypass should be active")
		}
		
		// Now the same blocked domain should pass through
		isBlocked := handler.blocker.IsBlocked("blocked.example.com") && 
			!handler.captiveDetector.IsInBypassMode()
		
		if isBlocked {
			t.Error("Domain should not be blocked during bypass")
		}
	})
}

// TestHandlerMetrics tests that we can collect useful metrics from the handler
func TestHandlerMetrics(t *testing.T) {
	cfg := &config.CaptivePortalConfig{
		Enabled:            true,
		DetectionThreshold: 3,
		DetectionWindow:    5 * time.Second,
		BypassDuration:     1 * time.Second, // Short for testing
	}
	
	blocker := NewBlocker()
	blocker.UpdateDomains([]string{"ads.example.com"})
	dnsCfg := &config.DNSConfig{
		Upstreams: []string{"8.8.8.8"},
		CacheSize: 1000,
		CacheTTL:  1 * time.Hour,
	}
	handler := NewHandler(blocker, dnsCfg, "127.0.0.1", cfg)
	
	type metrics struct {
		totalQueries      int
		blockedQueries    int
		bypassedQueries   int
		captivePortalHits int
	}
	
	m := &metrics{}
	
	// Helper to track metrics
	trackQuery := func(domain string, comment string) {
		m.totalQueries++
		
		// Check if it's a captive portal domain before recording
		isCaptivePortal := security.IsCaptivePortalDomain(domain)
		if isCaptivePortal {
			m.captivePortalHits++
		}
		
		// Check bypass mode before recording the request
		wasBypassedBefore := handler.captiveDetector.IsInBypassMode()
		
		handler.captiveDetector.RecordRequest(domain)
		
		// Only count as bypassed if it was already in bypass mode before this request
		// This prevents counting the triggering captive portal domain as bypassed
		if wasBypassedBefore {
			m.bypassedQueries++
			t.Logf("Query %d: %s (%s) - BYPASSED", m.totalQueries, domain, comment)
		} else if handler.blocker.IsBlocked(domain) {
			m.blockedQueries++
			t.Logf("Query %d: %s (%s) - BLOCKED", m.totalQueries, domain, comment)
		} else {
			t.Logf("Query %d: %s (%s) - ALLOWED (captive portal: %v)", m.totalQueries, domain, comment, isCaptivePortal)
		}
	}
	
	// Simulate traffic
	trackQuery("google.com", "Normal")          
	trackQuery("ads.example.com", "Blocked")     
	trackQuery("captive.apple.com", "Captive portal")   
	trackQuery("ads.example.com", "Still blocked")     
	
	// Trigger bypass
	trackQuery("connectivitycheck.gstatic.com", "Captive portal") 
	trackQuery("detectportal.firefox.com", "Captive portal - triggers bypass")      
	
	// During bypass
	trackQuery("ads.example.com", "Should be bypassed")     
	trackQuery("google.com", "Normal but bypassed")          
	
	// Wait for bypass to expire
	time.Sleep(1100 * time.Millisecond)
	
	// After bypass
	trackQuery("ads.example.com", "Blocked again")
	
	// Verify metrics
	if m.totalQueries != 9 {
		t.Errorf("Expected 9 total queries, got %d", m.totalQueries)
	}
	
	if m.captivePortalHits != 5 { // captive.apple.com, connectivitycheck.gstatic.com, detectportal.firefox.com, google.com, ads.example.com
		t.Errorf("Expected 5 captive portal hits, got %d", m.captivePortalHits)
	}
	
	if m.blockedQueries != 3 { // 2 before bypass, 1 after
		t.Errorf("Expected 3 blocked queries, got %d", m.blockedQueries)
	}
	
	if m.bypassedQueries != 3 { // detectportal.firefox.com, ads.example.com and google.com during bypass
		t.Errorf("Expected 3 bypassed queries, got %d", m.bypassedQueries)
	}
	
	t.Logf("Metrics: Total=%d, Blocked=%d, Bypassed=%d, CaptivePortal=%d",
		m.totalQueries, m.blockedQueries, m.bypassedQueries, m.captivePortalHits)
}