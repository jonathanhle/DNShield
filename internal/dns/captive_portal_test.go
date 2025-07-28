package dns

import (
	"testing"
	"time"
	
	"dnshield/internal/config"
)

func TestCaptivePortalDetector(t *testing.T) {
	detector := NewCaptivePortalDetector(nil) // Uses defaults

	// Test that non-captive portal domains don't trigger bypass
	detector.RecordRequest("example.com")
	detector.RecordRequest("google.com")
	if detector.IsInBypassMode() {
		t.Error("Bypass mode should not be enabled for non-captive portal domains")
	}

	// Test that multiple captive portal domains trigger bypass
	detector.RecordRequest("captive.apple.com")
	detector.RecordRequest("connectivitycheck.gstatic.com")
	detector.RecordRequest("detectportal.firefox.com")
	
	if !detector.IsInBypassMode() {
		t.Error("Bypass mode should be enabled after threshold captive portal requests")
	}

	// Test bypass status
	inBypass, remaining := detector.GetBypassStatus()
	if !inBypass {
		t.Error("GetBypassStatus should report bypass mode as active")
	}
	if remaining <= 0 || remaining > 5*time.Minute {
		t.Errorf("Unexpected remaining bypass time: %v", remaining)
	}

	// Test manual disable
	detector.DisableBypass()
	if detector.IsInBypassMode() {
		t.Error("Bypass mode should be disabled after manual disable")
	}

	// Test manual enable
	detector.EnableBypass()
	if !detector.IsInBypassMode() {
		t.Error("Bypass mode should be enabled after manual enable")
	}
}

func TestCaptivePortalDomainList(t *testing.T) {
	// Test some known captive portal domains
	blocker := NewBlocker()
	blocker.UpdateDomains([]string{"doubleclick.net", "ads.google.com"})

	// These should never be blocked even if in blocklist
	testDomains := []string{
		"captive.apple.com",
		"connectivitycheck.gstatic.com",
		"detectportal.firefox.com",
		"www.msftconnecttest.com",
		// Test new airline domains
		"gogoinflight.com",
		"wifi.gogoinflight.com",
		"captive.gogoinflight.com",
		"auth.gogoinflight.com", // subdomain test
		"deltawifi.com",
		"wifi.delta.com",
		// Test coffee shop domains
		"wifi.panerabread.com",
		"sbux-portal.globalreachtech.com",
		// Test hotel domains
		"secure.guestinternet.com",
		"attwifi.com",
		"login.attwifi.com", // subdomain test
	}

	for _, domain := range testDomains {
		if blocker.IsBlocked(domain) {
			t.Errorf("Captive portal domain %s should never be blocked", domain)
		}
	}
}

func TestCaptivePortalDetectorWithConfig(t *testing.T) {
	// Test with custom configuration
	cfg := &config.CaptivePortalConfig{
		Enabled:            true,
		DetectionThreshold: 2,      // Lower threshold
		DetectionWindow:    5 * time.Second,
		BypassDuration:     2 * time.Minute,
		AdditionalDomains:  []string{"custom-portal.test"},
	}
	
	detector := NewCaptivePortalDetector(cfg)
	
	// Test that custom domain is recognized
	detector.RecordRequest("custom-portal.test")
	detector.RecordRequest("captive.apple.com")
	
	// Should trigger with just 2 domains due to custom threshold
	if !detector.IsInBypassMode() {
		t.Error("Bypass mode should be enabled with custom threshold of 2")
	}
	
	// Test bypass duration
	inBypass, remaining := detector.GetBypassStatus()
	if !inBypass {
		t.Error("Should be in bypass mode")
	}
	if remaining > 2*time.Minute {
		t.Errorf("Bypass duration should be 2 minutes, got: %v", remaining)
	}
}

func TestCaptivePortalDetectorDisabled(t *testing.T) {
	// Test with detection disabled
	cfg := &config.CaptivePortalConfig{
		Enabled: false,
	}
	
	detector := NewCaptivePortalDetector(cfg)
	
	// Even with captive portal domains, should not trigger
	detector.RecordRequest("captive.apple.com")
	detector.RecordRequest("connectivitycheck.gstatic.com")
	detector.RecordRequest("detectportal.firefox.com")
	
	if detector.IsInBypassMode() {
		t.Error("Bypass mode should not be enabled when detection is disabled")
	}
}