package security

import "strings"

// CaptivePortalDomains contains domains used by various operating systems
// and browsers to detect captive portals. These should never be blocked.
// NOTE: Wildcard entries (*.domain.com) are handled by the IsCaptivePortalDomain function
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
	"clients4.google.com":               true,
	"android.clients.google.com":        true,
	"www.androidbak.net":                true,
	
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
	
	// Airline WiFi Providers - Gogo
	"gogoinflight.com":       true,
	"gogoinair.com":          true,
	"wifi.gogoinflight.com":  true,
	"captive.gogoinflight.com": true,
	
	// Airline WiFi Providers - Viasat
	"viasat.com":             true,
	"inflight.viasat.com":    true,
	
	// Airline WiFi Providers - WiFi Onboard (formerly Gogo)
	"inflightinternet.com":   true,
	"wifi.inflightinternet.com": true,
	"wifionboard.com":        true,
	"care.inflightinternet.com": true,
	
	// Airline WiFi Providers - Panasonic Avionics
	"portal-pax.exconnect.panasonic.aero": true,
	"panasonic.aero":         true,
	
	// Airline WiFi Providers - Other
	"wifilauncher.com":       true,
	"flyfi.com":              true,
	"fly-fi.com":             true,
	"inflight-wifi.com":      true,
	
	// US Airlines Specific
	"deltawifi.com":          true,
	"wifi.delta.com":         true,
	"unitedwifi.com":         true,
	"wifi.united.com":        true,
	"guestwifi.united.com":   true, // United guest WiFi
	"aainflight.com":         true,
	"southwestwifi.com":      true,
	"alaskawifi.com":         true,
	"amtrakconnect.com":      true, // Amtrak trains
	
	// International Airlines
	"lufthansa-flynet.com":   true,
	"shop.ba.com":            true,
	"airfrance.com":          true,
	"connect.airfrance.com":  true,
	
	// Coffee Shops - Starbucks
	"sbux-portal.globalreachtech.com": true,
	"secure.datavalet.io":    true,
	"aruba.odyssys.net":      true,
	"sbux-portal.appspot.com": true,
	
	// Coffee Shops - Panera Bread
	"wifi.panerabread.com":   true,
	"iportal.panerabread.com": true,
	
	// Hotel WiFi Providers
	"secure.guestinternet.com": true, // Hilton
	"attwifi.com":            true,
	"mywifi.attwifi.com":     true,
	"securelogin.arubanetworks.com": true, // Aruba Networks - common for hotels/enterprise
	"snap.selectnetworx.com": true, // Hilton Dana Point
	"globalsuite.net":        true, // Hyatt Hotels
	"bap.aws.opennetworkexchange.net": true, // Hyatt Hotels
	"marriott.com":           true, // Marriott Hotels
	"cloud5.com":             true, // Marriott Hotels
	"splash.skyadmin.io":     true, // Montage Hotels
	"hotelwifi.com":          true, // Multiple Hotels
	"registerforhsia.com":    true, // Multiple Hotels
	"danmagi.com":            true, // Multiple Hotels
	"redwoodsystemsgroup.com": true, // Multiple Hotels
	
	// Public WiFi Providers
	"captive-portal.selectwifi.xfinity.com": true, // Xfinity WiFi
	"d2uzsrnmmf6tds.cloudfront.net":         true, // CloudFront CDN
	"via.boingohotspot.net":   true, // Boingo - airports and multiple airlines
	"login.yyc.com":           true, // Calgary Airport
	
	// Generic Captive Portal Detection
	"hotspot-detect.html":    true,
	"generate_204":           true,
	"blank.html":             true,
}

// CaptivePortalParentDomains contains parent domains where all subdomains
// should be treated as captive portal domains
var CaptivePortalParentDomains = map[string]bool{
	// Airline WiFi Providers
	"gogoinflight.com":     true,
	"gogoinair.com":        true,
	"viasat.com":           true,
	"inflightinternet.com": true,
	"wifionboard.com":      true,
	"panasonic.aero":       true,
	"wifilauncher.com":     true,
	"flyfi.com":            true,
	"inflight-wifi.com":    true,
	
	// US Airlines
	"deltawifi.com":     true,
	"unitedwifi.com":    true,
	"aainflight.com":    true,
	"southwestwifi.com": true,
	"alaskawifi.com":    true,
	
	// International Airlines
	"lufthansa-flynet.com": true,
	"airfrance.com":        true,
	
	// Hotel WiFi
	"attwifi.com": true,
	
	// Public WiFi Providers
	"selectwifi.xfinity.com": true, // Xfinity WiFi
	"boingohotspot.net": true, // Boingo - airports and multiple airlines
	"yyc.com": true, // Calgary Airport
	"selectnetworx.com": true, // Hilton Dana Point
	"opennetworkexchange.net": true, // Hyatt Hotels
	"skyadmin.io": true, // Montage Hotels
}

// IsCaptivePortalDomain checks if a domain is used for captive portal detection
func IsCaptivePortalDomain(domain string) bool {
	// Check exact match first
	if CaptivePortalDomains[domain] {
		return true
	}
	
	// Check if it's a subdomain of a captive portal parent domain
	for parent := range CaptivePortalParentDomains {
		if domain == parent || strings.HasSuffix(domain, "."+parent) {
			return true
		}
	}
	
	return false
}

// IsCaptivePortalDomainWithAdditional checks if a domain is a captive portal domain,
// including any additional domains from configuration
func IsCaptivePortalDomainWithAdditional(domain string, additionalDomains []string) bool {
	// Check built-in list first (including parent domain matching)
	if IsCaptivePortalDomain(domain) {
		return true
	}
	
	// Check additional domains from config
	for _, d := range additionalDomains {
		if d == domain || strings.HasSuffix(domain, "."+d) {
			return true
		}
	}
	
	return false
}