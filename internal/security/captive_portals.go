package security

// CaptivePortalDomains contains domains used by various operating systems
// and browsers to detect captive portals. These should never be blocked.
var CaptivePortalDomains = map[string]bool{
	// Apple
	"captive.apple.com":     true,
	"mask.icloud.com":       true,
	"mask-h2.icloud.com":    true,
	
	// Windows
	"www.msftconnecttest.com": true,
	"msftncsi.com":           true,
	"www.msftncsi.com":       true,
	"ipv6.msftncsi.com":      true,
	
	// Android
	"connectivitycheck.gstatic.com":     true,
	"connectivitycheck.android.com":     true,
	"connectivitycheck.platform.hicloud.com": true,
	"www.google.com":                    true, // Android fallback
	"clients3.google.com":               true,
	"clients.l.google.com":              true,
	
	// Firefox
	"detectportal.firefox.com": true,
	
	// Chrome
	"www.gstatic.com":       true,
	
	// Amazon Fire OS
	"spectrum.s3.amazonaws.com": true,
	
	// Ubuntu/NetworkManager
	"connectivity-check.ubuntu.com": true,
	"nmcheck.gnome.org":            true,
	"network-test.debian.org":      true,
	
	// Apple additional domains
	"www.apple.com":         true,
	"www.appleiphonecell.com": true,
	"www.itools.info":       true,
	"www.ibook.info":        true,
	"www.airport.us":        true,
	"www.thinkdifferent.us": true,
	
	// Linux/ConnMan
	"ipv4.connman.net":      true,
	"ipv6.connman.net":      true,
	"connman.net":           true,
	
	// Cloudflare WARP
	"engage.cloudflareclient.com": true,
	
	// Additional connectivity check domains
	"play.googleapis.com":    true,
	"www.googleapis.com":     true,
	"cp.cloudflare.com":      true,
	"1.1.1.1":                true,
	"one.one.one.one":        true,
	
	// Hotel/Airport WiFi providers often use these
	"neverssl.com":           true,
	"example.com":            true,
	"example.net":            true,
	"example.org":            true,
	"wifi.google.com":        true,
	"gstatic.com":            true,
	"google.com":             true,
	"www.yahoo.com":          true,
	"yahoo.com":              true,
}

// IsCaptivePortalDomain checks if a domain is used for captive portal detection
func IsCaptivePortalDomain(domain string) bool {
	return CaptivePortalDomains[domain]
}

// IsCaptivePortalDomainWithAdditional checks if a domain is a captive portal domain,
// including any additional domains from configuration
func IsCaptivePortalDomainWithAdditional(domain string, additionalDomains []string) bool {
	// Check built-in list first
	if CaptivePortalDomains[domain] {
		return true
	}
	
	// Check additional domains from config
	for _, d := range additionalDomains {
		if d == domain {
			return true
		}
	}
	
	return false
}