// Package proxy implements an HTTPS intercepting proxy that generates TLS certificates
// dynamically for blocked domains. This enables transparent HTTPS filtering without
// browser certificate warnings. The proxy serves custom block pages for filtered
// domains while maintaining security through proper certificate validation.
package proxy

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"html"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

var blockPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Website Blocked - DNShield</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 3rem;
            max-width: 500px;
            text-align: center;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
        h1 {
            font-size: 2.5rem;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
        }
        .icon { font-size: 3rem; }
        p { 
            font-size: 1.1rem; 
            line-height: 1.6;
            margin-bottom: 1rem;
            opacity: 0.9;
        }
        .domain {
            background: rgba(255, 255, 255, 0.2);
            padding: 0.5rem 1rem;
            border-radius: 10px;
            margin: 1rem 0;
            font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace;
            word-break: break-all;
            font-size: 0.95rem;
        }
        .reason {
            font-size: 0.9rem;
            opacity: 0.8;
            margin-top: 2rem;
        }
        .timestamp {
            font-size: 0.8rem;
            opacity: 0.6;
            margin-top: 1rem;
        }
        .agent-info {
            font-size: 0.7rem;
            opacity: 0.5;
            margin-top: 2rem;
        }
        @media (max-width: 600px) {
            .container { margin: 1rem; padding: 2rem; }
            h1 { font-size: 2rem; }
            .icon { font-size: 2.5rem; }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1><span class="icon">🚫</span> Access Blocked</h1>
        <p>The website you're trying to visit has been blocked by your enterprise DNS filter.</p>
        <div class="domain">{{.Domain}}</div>
        <p>This domain was blocked for your protection.</p>
        <p class="reason">{{.Reason}}</p>
        <p class="timestamp">{{.Timestamp}}</p>
        <p class="agent-info">DNShield v{{.Version}}</p>
    </div>
</body>
</html>`

// HTTPSProxy handles HTTPS requests with dynamic certificates
type HTTPSProxy struct {
	certGen     *CertGenerator
	httpServer  *http.Server
	httpsServer *http.Server
	blockPage   *template.Template
}

// BlockPageData contains data for the block page template
type BlockPageData struct {
	Domain    string
	Reason    string
	Timestamp string
	Version   string
}

// sanitizeDomain validates and sanitizes a domain name to prevent XSS
func sanitizeDomain(domain string) string {
	// Remove any potential HTML/JavaScript
	domain = html.EscapeString(domain)
	
	// Validate domain format (basic check)
	// Allow alphanumeric, dots, hyphens, and colons (for ports)
	var sanitized strings.Builder
	for _, ch := range domain {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || 
		   (ch >= '0' && ch <= '9') || ch == '.' || ch == '-' || ch == ':' {
			sanitized.WriteRune(ch)
		}
	}
	
	result := sanitized.String()
	
	// Additional validation - ensure it looks like a domain
	if len(result) == 0 || len(result) > 253 {
		return "invalid-domain"
	}
	
	return result
}

// sanitizeHeader ensures header values don't contain newlines or other dangerous characters
func sanitizeHeader(value string) string {
	// Remove any newlines, carriage returns, or null bytes
	value = strings.ReplaceAll(value, "\n", "")
	value = strings.ReplaceAll(value, "\r", "")
	value = strings.ReplaceAll(value, "\x00", "")
	
	// URL encode for extra safety
	return url.QueryEscape(value)
}

// NewHTTPSProxy creates a new HTTPS proxy
func NewHTTPSProxy(certGen *CertGenerator) (*HTTPSProxy, error) {
	// Parse block page template
	tmpl, err := template.New("blockpage").Parse(blockPageHTML)
	if err != nil {
		return nil, fmt.Errorf("failed to parse block page template: %v", err)
	}

	proxy := &HTTPSProxy{
		certGen:   certGen,
		blockPage: tmpl,
	}

	// Create HTTP server (redirect to HTTPS)
	proxy.httpServer = &http.Server{
		Addr:         ":80",
		Handler:      http.HandlerFunc(proxy.handleHTTPRedirect),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	// Create HTTPS server
	proxy.httpsServer = &http.Server{
		Addr:         ":443",
		Handler:      http.HandlerFunc(proxy.handleHTTPS),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{
			GetCertificate: certGen.GetCertificate,
		},
	}

	return proxy, nil
}

// Start starts both HTTP and HTTPS servers
func (p *HTTPSProxy) Start() error {
	// Start HTTP server
	go func() {
		logrus.Info("Starting HTTP server on :80")
		if err := p.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logrus.WithError(err).Error("HTTP server error")
		}
	}()

	// Start HTTPS server
	go func() {
		logrus.Info("Starting HTTPS server on :443")
		if err := p.httpsServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			logrus.WithError(err).Error("HTTPS server error")
		}
	}()

	return nil
}

// Stop stops both servers
func (p *HTTPSProxy) Stop() error {
	var errs []error

	if err := p.httpServer.Close(); err != nil {
		errs = append(errs, err)
	}

	if err := p.httpsServer.Close(); err != nil {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors stopping servers: %v", errs)
	}

	return nil
}

// handleHTTPRedirect redirects HTTP to HTTPS
func (p *HTTPSProxy) handleHTTPRedirect(w http.ResponseWriter, r *http.Request) {
	target := "https://" + r.Host + r.RequestURI
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}

// handleHTTPS serves the block page
func (p *HTTPSProxy) handleHTTPS(w http.ResponseWriter, r *http.Request) {
	domain := r.Host
	if host, _, err := net.SplitHostPort(domain); err == nil {
		domain = host
	}
	
	// Sanitize the domain to prevent XSS
	safeDomain := sanitizeDomain(domain)

	logrus.WithFields(logrus.Fields{
		"domain":      domain,
		"safeDomain": safeDomain,
	}).Info("Serving block page")

	data := BlockPageData{
		Domain:    safeDomain, // Use sanitized domain in template
		Reason:    "This domain is blocked by your organization's security policy",
		Timestamp: time.Now().Format("2006-01-02 15:04:05"),
		Version:   "1.0.0",
	}

	var buf bytes.Buffer
	if err := p.blockPage.Execute(&buf, data); err != nil {
		logrus.WithError(err).Error("Failed to render block page")
		http.Error(w, "Blocked", http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'")
	
	// Sanitize domain for header to prevent header injection
	w.Header().Set("X-Blocked-Domain", sanitizeHeader(safeDomain))
	
	w.WriteHeader(http.StatusOK)
	w.Write(buf.Bytes())
}
