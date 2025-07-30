package rules

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"dnshield/internal/utils"
)

// Parser parses blocklist files
type Parser struct {
	httpClient *http.Client
}

// NewParser creates a new rule parser
func NewParser() *Parser {
	return &Parser{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// ParseHostsFile parses a hosts file format blocklist
func (p *Parser) ParseHostsFile(content string) []string {
	var domains []string
	scanner := bufio.NewScanner(strings.NewReader(content))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse hosts file format (e.g., "0.0.0.0 example.com")
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			// Skip localhost entries
			domain := parts[1]
			if domain != "localhost" && domain != "localhost.localdomain" {
				domains = append(domains, domain)
			}
		}
	}

	return domains
}

// FetchAndParseURL fetches and parses a blocklist from URL
func (p *Parser) FetchAndParseURL(urlStr string) ([]string, error) {
	// Validate URL to prevent SSRF attacks
	if err := validateBlocklistURL(urlStr); err != nil {
		return nil, err
	}
	
	logrus.WithField("url", urlStr).Debug("Fetching blocklist")

	resp, err := p.httpClient.Get(urlStr)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Limit response body size to prevent DoS
	limitedReader := utils.LimitedReader(resp.Body, int64(utils.MaxRulesFileSize))
	
	scanner := bufio.NewScanner(limitedReader)
	var domains []string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Try to parse as hosts file format
		if strings.Contains(line, " ") || strings.Contains(line, "\t") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				domain := parts[1]
				if domain != "localhost" && domain != "localhost.localdomain" {
					domains = append(domains, domain)
				}
			}
		} else {
			// Plain domain format
			domains = append(domains, line)
		}
	}

	logrus.WithFields(logrus.Fields{
		"url":     urlStr,
		"domains": len(domains),
	}).Info("Parsed blocklist")

	return domains, scanner.Err()
}

// MergeDomains merges multiple domain lists and removes duplicates
func MergeDomains(lists ...[]string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, list := range lists {
		for _, domain := range list {
			domain = strings.ToLower(strings.TrimSpace(domain))
			if domain != "" && !seen[domain] {
				seen[domain] = true
				result = append(result, domain)
			}
		}
	}

	return result
}

// validateBlocklistURL validates a URL to prevent SSRF attacks
func validateBlocklistURL(urlStr string) error {
	// Parse the URL
	u, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("invalid URL: %v", err)
	}
	
	// Only allow HTTP and HTTPS
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("only http and https URLs are allowed")
	}
	
	// Validate hostname
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("URL must have a hostname")
	}
	
	// Resolve the hostname to check for private IPs
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("failed to resolve hostname: %v", err)
	}
	
	// Check each resolved IP
	for _, ip := range ips {
		if isPrivateIP(ip) {
			return fmt.Errorf("URL resolves to private IP address: %s", ip)
		}
		if isLoopbackIP(ip) {
			return fmt.Errorf("URL resolves to loopback address: %s", ip)
		}
		if isLinkLocalIP(ip) {
			return fmt.Errorf("URL resolves to link-local address: %s", ip)
		}
	}
	
	// Validate port
	port := u.Port()
	if port != "" {
		// Only allow standard HTTP/HTTPS ports
		if port != "80" && port != "443" && port != "8080" && port != "8443" {
			return fmt.Errorf("non-standard port not allowed: %s", port)
		}
	}
	
	return nil
}

// isPrivateIP checks if an IP is in a private range
func isPrivateIP(ip net.IP) bool {
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"fc00::/7", // IPv6 unique local
	}
	
	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	
	return false
}

// isLoopbackIP checks if an IP is a loopback address
func isLoopbackIP(ip net.IP) bool {
	return ip.IsLoopback()
}

// isLinkLocalIP checks if an IP is a link-local address
func isLinkLocalIP(ip net.IP) bool {
	return ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}
