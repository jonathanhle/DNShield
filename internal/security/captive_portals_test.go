package security

import (
	"testing"
)

func TestIsCaptivePortalDomain(t *testing.T) {
	tests := []struct {
		domain   string
		expected bool
	}{
		// Exact matches
		{"captive.apple.com", true},
		{"gogoinflight.com", true},
		{"deltawifi.com", true},
		{"wifi.panerabread.com", true},
		{"secure.guestinternet.com", true},
		{"android.clients.google.com", true},
		{"clients4.google.com", true},
		{"www.androidbak.net", true},
		{"captive-portal.selectwifi.xfinity.com", true},
		{"securelogin.arubanetworks.com", true},
		
		// Subdomain matches
		{"auth.gogoinflight.com", true},
		{"login.gogoinflight.com", true},
		{"wifi.deltawifi.com", true},
		{"portal.attwifi.com", true},
		{"subdomain.unitedwifi.com", true},
		{"login.selectwifi.xfinity.com", true}, // Xfinity subdomain
		
		// Non-captive portal domains
		{"facebook.com", false},
		{"twitter.com", false},
		{"notacaptiveportal.com", false},
		{"randomdomain.org", false},
		
		// These are actually in the list
		{"google.com", true},
		{"example.com", true},
		
		// Edge cases
		{"", false},
		{"gogoinflight", false}, // Missing .com
		{"com", false},
	}
	
	for _, test := range tests {
		result := IsCaptivePortalDomain(test.domain)
		if result != test.expected {
			t.Errorf("IsCaptivePortalDomain(%q) = %v, expected %v", test.domain, result, test.expected)
		}
	}
}

func TestIsCaptivePortalDomainWithAdditional(t *testing.T) {
	additionalDomains := []string{
		"custom-portal.company.com",
		"wifi.hotel-chain.com",
	}
	
	tests := []struct {
		domain   string
		expected bool
	}{
		// Built-in domains
		{"captive.apple.com", true},
		{"auth.gogoinflight.com", true},
		
		// Additional exact matches
		{"custom-portal.company.com", true},
		{"wifi.hotel-chain.com", true},
		
		// Additional subdomain matches
		{"login.custom-portal.company.com", true},
		{"guest.wifi.hotel-chain.com", true},
		
		// Non-captive portal domains
		{"random.com", false},
		{"company.com", false}, // Parent of additional domain, but not included
	}
	
	for _, test := range tests {
		result := IsCaptivePortalDomainWithAdditional(test.domain, additionalDomains)
		if result != test.expected {
			t.Errorf("IsCaptivePortalDomainWithAdditional(%q) = %v, expected %v", test.domain, result, test.expected)
		}
	}
}

// Verify that example.com is actually in the captive portal list
func TestExampleComIsInList(t *testing.T) {
	if !IsCaptivePortalDomain("example.com") {
		t.Error("example.com should be in the captive portal domain list")
	}
}