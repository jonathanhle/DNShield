package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
	
	"github.com/miekg/dns"
)

// CaptivePortalSimulator simulates a captive portal environment for testing DNShield
type CaptivePortalSimulator struct {
	authenticatedClients map[string]time.Time
	portalDomain         string
	redirectURL          string
}

func NewCaptivePortalSimulator() *CaptivePortalSimulator {
	return &CaptivePortalSimulator{
		authenticatedClients: make(map[string]time.Time),
		portalDomain:        "captive.test.local",
		redirectURL:         "http://captive.test.local:8080/login",
	}
}

// Start runs the captive portal simulator
func (s *CaptivePortalSimulator) Start() {
	// Start HTTP server for captive portal
	go s.startHTTPServer()
	
	// Start DNS server to intercept captive portal detection
	go s.startDNSServer()
	
	fmt.Println("Captive Portal Simulator Started")
	fmt.Println("================================")
	fmt.Println("Configuration:")
	fmt.Printf("  Portal Domain: %s\n", s.portalDomain)
	fmt.Printf("  Portal URL: %s\n", s.redirectURL)
	fmt.Println("\nTo test DNShield captive portal detection:")
	fmt.Println("1. Configure DNShield to use 127.0.0.1 as DNS server")
	fmt.Println("2. The simulator will intercept captive portal detection domains")
	fmt.Println("3. Access the portal at http://captive.test.local:8080")
	fmt.Println("\nPress Ctrl+C to stop")
	
	// Keep running
	select {}
}

// startHTTPServer runs the captive portal web interface
func (s *CaptivePortalSimulator) startHTTPServer() {
	http.HandleFunc("/", s.handlePortalRedirect)
	http.HandleFunc("/login", s.handleLogin)
	http.HandleFunc("/authenticate", s.handleAuthenticate)
	http.HandleFunc("/success", s.handleSuccess)
	
	// Captive portal detection endpoints
	http.HandleFunc("/generate_204", s.handleConnectivityCheck)        // Android
	http.HandleFunc("/success.txt", s.handleAppleSuccess)              // Apple
	http.HandleFunc("/hotspot-detect.html", s.handleAppleDetect)       // Apple
	http.HandleFunc("/connecttest.txt", s.handleWindowsTest)           // Windows
	http.HandleFunc("/redirect", s.handleWindowsRedirect)              // Windows
	
	log.Println("Starting HTTP server on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal("HTTP server error:", err)
	}
}

// handlePortalRedirect redirects all requests to login page
func (s *CaptivePortalSimulator) handlePortalRedirect(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	
	// Check if already authenticated
	if _, authenticated := s.authenticatedClients[clientIP]; authenticated {
		http.Redirect(w, r, "http://example.com", http.StatusFound)
		return
	}
	
	// Redirect to login
	http.Redirect(w, r, s.redirectURL, http.StatusFound)
}

// handleLogin shows the login page
func (s *CaptivePortalSimulator) handleLogin(w http.ResponseWriter, r *http.Request) {
	html := `
<!DOCTYPE html>
<html>
<head>
	<title>Test Captive Portal</title>
	<style>
		body {
			font-family: Arial, sans-serif;
			max-width: 600px;
			margin: 50px auto;
			padding: 20px;
			background: #f0f0f0;
		}
		.container {
			background: white;
			padding: 30px;
			border-radius: 10px;
			box-shadow: 0 2px 10px rgba(0,0,0,0.1);
		}
		h1 {
			color: #333;
			text-align: center;
		}
		.info {
			background: #e8f4f8;
			padding: 15px;
			border-radius: 5px;
			margin: 20px 0;
		}
		button {
			background: #007bff;
			color: white;
			border: none;
			padding: 10px 30px;
			border-radius: 5px;
			cursor: pointer;
			font-size: 16px;
			display: block;
			margin: 20px auto;
		}
		button:hover {
			background: #0056b3;
		}
		.status {
			text-align: center;
			margin-top: 20px;
			color: #666;
		}
	</style>
</head>
<body>
	<div class="container">
		<h1>Test Captive Portal</h1>
		<div class="info">
			<h3>Simulated Captive Portal for DNShield Testing</h3>
			<p>This simulates a typical captive portal that you might encounter at:</p>
			<ul>
				<li>Coffee shops (Starbucks, etc.)</li>
				<li>Airports and airlines</li>
				<li>Hotels</li>
				<li>Public WiFi hotspots</li>
			</ul>
		</div>
		
		<form action="/authenticate" method="POST">
			<h3>Terms of Service</h3>
			<p>By clicking "Connect", you agree to our terms of service and acceptable use policy.</p>
			
			<button type="submit">Connect to Internet</button>
		</form>
		
		<div class="status">
			<p>Client IP: ` + r.RemoteAddr + `</p>
			<p>Detection Domain: ` + r.Host + `</p>
		</div>
	</div>
</body>
</html>
`
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, html)
}

// handleAuthenticate processes the authentication
func (s *CaptivePortalSimulator) handleAuthenticate(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	
	clientIP := getClientIP(r)
	s.authenticatedClients[clientIP] = time.Now()
	
	log.Printf("Client authenticated: %s", clientIP)
	http.Redirect(w, r, "/success", http.StatusFound)
}

// handleSuccess shows success page
func (s *CaptivePortalSimulator) handleSuccess(w http.ResponseWriter, r *http.Request) {
	html := `
<!DOCTYPE html>
<html>
<head>
	<title>Connected!</title>
	<style>
		body {
			font-family: Arial, sans-serif;
			text-align: center;
			padding: 50px;
		}
		.success {
			color: #28a745;
			font-size: 24px;
			margin: 20px 0;
		}
	</style>
</head>
<body>
	<h1 class="success">✓ Successfully Connected!</h1>
	<p>You are now connected to the internet.</p>
	<p>DNShield should have detected the captive portal and enabled bypass mode.</p>
	<p><a href="http://example.com">Test your connection</a></p>
</body>
</html>
`
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, html)
}

// Connectivity check handlers for different operating systems
func (s *CaptivePortalSimulator) handleConnectivityCheck(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	if _, authenticated := s.authenticatedClients[clientIP]; authenticated {
		w.WriteHeader(http.StatusNoContent) // 204 No Content
	} else {
		http.Redirect(w, r, s.redirectURL, http.StatusFound)
	}
}

func (s *CaptivePortalSimulator) handleAppleSuccess(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	if _, authenticated := s.authenticatedClients[clientIP]; authenticated {
		fmt.Fprint(w, "Success")
	} else {
		http.Redirect(w, r, s.redirectURL, http.StatusFound)
	}
}

func (s *CaptivePortalSimulator) handleAppleDetect(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	if _, authenticated := s.authenticatedClients[clientIP]; authenticated {
		fmt.Fprint(w, "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>")
	} else {
		// Apple expects specific HTML for captive portal detection
		html := `<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>`
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, html)
	}
}

func (s *CaptivePortalSimulator) handleWindowsTest(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	if _, authenticated := s.authenticatedClients[clientIP]; authenticated {
		fmt.Fprint(w, "Microsoft Connect Test")
	} else {
		http.Redirect(w, r, s.redirectURL, http.StatusFound)
	}
}

func (s *CaptivePortalSimulator) handleWindowsRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, s.redirectURL, http.StatusFound)
}

// startDNSServer intercepts DNS queries for captive portal domains
func (s *CaptivePortalSimulator) startDNSServer() {
	server := &dns.Server{
		Addr: ":8053",
		Net:  "udp",
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Authoritative = true
			
			for _, q := range r.Question {
				log.Printf("DNS Query: %s", q.Name)
				
				// Check if it's a captive portal detection domain
				if s.isCaptivePortalDomain(q.Name) {
					// Respond with our IP
					if q.Qtype == dns.TypeA {
						rr := &dns.A{
							Hdr: dns.RR_Header{
								Name:   q.Name,
								Rrtype: dns.TypeA,
								Class:  dns.ClassINET,
								Ttl:    60,
							},
							A: net.ParseIP("127.0.0.1"),
						}
						m.Answer = append(m.Answer, rr)
					}
				}
			}
			
			w.WriteMsg(m)
		}),
	}
	
	log.Println("Starting DNS server on :8053")
	log.Println("To use: Configure DNShield upstream to 127.0.0.1:8053")
	
	if err := server.ListenAndServe(); err != nil {
		log.Fatal("DNS server error:", err)
	}
}

// isCaptivePortalDomain checks if domain is a captive portal detection domain
func (s *CaptivePortalSimulator) isCaptivePortalDomain(domain string) bool {
	captiveDomains := []string{
		"captive.apple.com.",
		"gsp1.apple.com.",
		"www.apple.com.",
		"connectivitycheck.gstatic.com.",
		"android.clients.google.com.",
		"clients4.google.com.",
		"detectportal.firefox.com.",
		"www.msftconnecttest.com.",
		"dns.msftncsi.com.",
		"example.com.",
		"neverssl.com.",
		s.portalDomain + ".",
	}
	
	domain = strings.ToLower(domain)
	for _, cd := range captiveDomains {
		if domain == cd || strings.HasSuffix(domain, "."+cd) {
			return true
		}
	}
	return false
}

// getClientIP extracts client IP from request
func getClientIP(r *http.Request) string {
	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip = r.Header.Get("X-Real-IP")
	}
	if ip == "" {
		ip = r.RemoteAddr
	}
	
	// Remove port if present
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	
	return ip
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "help" {
		fmt.Println("Captive Portal Simulator for DNShield Testing")
		fmt.Println("============================================")
		fmt.Println("\nUsage: go run captive_portal_simulator.go")
		fmt.Println("\nThis tool simulates a captive portal environment to test DNShield's")
		fmt.Println("captive portal detection and bypass functionality without needing")
		fmt.Println("access to real public WiFi networks.")
		fmt.Println("\nFeatures:")
		fmt.Println("- Simulates common captive portal detection endpoints")
		fmt.Println("- Provides a login page similar to real captive portals")
		fmt.Println("- Tracks authenticated clients")
		fmt.Println("- Includes DNS server for testing DNS interception")
		return
	}
	
	simulator := NewCaptivePortalSimulator()
	simulator.Start()
}