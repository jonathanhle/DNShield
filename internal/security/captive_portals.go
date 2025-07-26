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
	
	// Android
	"connectivitycheck.gstatic.com":     true,
	"connectivitycheck.android.com":     true,
	"connectivitycheck.platform.hicloud.com": true,
	"www.google.com":                    true, // Android fallback
	
	// Firefox
	"detectportal.firefox.com": true,
	
	// Amazon Fire OS
	"spectrum.s3.amazonaws.com": true,
	
	// Ubuntu/NetworkManager
	"connectivity-check.ubuntu.com": true,
	"nmcheck.gnome.org":            true,
	
	// Other common captive portal endpoints
	"clients3.google.com":    true,
	"clients.l.google.com":   true,
	"play.googleapis.com":    true,
	"www.gstatic.com":       true,
	"www.apple.com":         true,
	"www.appleiphonecell.com": true,
	"www.itools.info":       true,
	"www.ibook.info":        true,
	"www.airport.us":        true,
	"www.thinkdifferent.us": true,
	"ipv6.connman.net":      true,
	"connman.net":           true,
}

// IsCaptivePortalDomain checks if a domain is used for captive portal detection
func IsCaptivePortalDomain(domain string) bool {
	return CaptivePortalDomains[domain]
}