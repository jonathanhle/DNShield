package rules

import (
	"bufio"
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
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
func (p *Parser) FetchAndParseURL(url string) ([]string, error) {
	logrus.WithField("url", url).Debug("Fetching blocklist")

	resp, err := p.httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, err
	}

	scanner := bufio.NewScanner(resp.Body)
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
		"url":     url,
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
