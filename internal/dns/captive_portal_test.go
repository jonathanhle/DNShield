package dns

import (
	"testing"
	"time"
)

func TestCaptivePortalDetector(t *testing.T) {
	detector := NewCaptivePortalDetector()

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
	}

	for _, domain := range testDomains {
		if blocker.IsBlocked(domain) {
			t.Errorf("Captive portal domain %s should never be blocked", domain)
		}
	}
}