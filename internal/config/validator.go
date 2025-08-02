package config

import (
	"fmt"
	"net/url"
)


// SanitizeConfigForLogging returns a sanitized version of the config for logging
func SanitizeConfigForLogging(cfg *Config) map[string]interface{} {
	sanitized := make(map[string]interface{})

	// Agent configuration
	agent := make(map[string]interface{})
	agent["log_level"] = cfg.Agent.LogLevel
	agent["allow_disable"] = cfg.Agent.AllowDisable
	agent["dns_port"] = cfg.Agent.DNSPort
	sanitized["agent"] = agent

	// DNS configuration
	dns := make(map[string]interface{})
	dns["upstreams"] = cfg.DNS.Upstreams
	dns["cache_size"] = cfg.DNS.CacheSize
	dns["cache_ttl"] = cfg.DNS.CacheTTL
	dns["rate_limit_queries"] = cfg.DNS.RateLimitQueries
	dns["rate_limit_window"] = cfg.DNS.RateLimitWindow
	sanitized["dns"] = dns

	// S3 configuration (sanitized)
	if cfg.S3.Bucket != "" {
		s3 := make(map[string]interface{})
		s3["bucket"] = cfg.S3.Bucket
		s3["region"] = cfg.S3.Region
		s3["update_interval"] = cfg.S3.UpdateInterval
		// Explicitly not including AccessKeyID or SecretKey
		s3["credentials"] = "[CONFIGURED]"
		sanitized["s3"] = s3
	}

	// Logging configuration (sanitized)
	logging := make(map[string]interface{})
	if cfg.Logging.Splunk.Enabled {
		splunk := make(map[string]interface{})
		splunk["enabled"] = true
		splunk["endpoint"] = "[CONFIGURED]"
		splunk["token"] = "[REDACTED]"
		splunk["index"] = cfg.Logging.Splunk.Index
		logging["splunk"] = splunk
	}
	if cfg.Logging.S3.Enabled {
		s3Log := make(map[string]interface{})
		s3Log["enabled"] = true
		s3Log["batch_interval"] = cfg.Logging.S3.BatchInterval
		logging["s3"] = s3Log
	}
	sanitized["logging"] = logging

	// Blocking configuration
	blocking := make(map[string]interface{})
	blocking["default_action"] = cfg.Blocking.DefaultAction
	blocking["block_type"] = cfg.Blocking.BlockType
	sanitized["blocking"] = blocking

	// Test domains
	if len(cfg.TestDomains) > 0 {
		sanitized["test_domains_count"] = len(cfg.TestDomains)
	}

	return sanitized
}

// ValidateConfig performs basic configuration validation
func ValidateConfig(cfg *Config) error {
	// Check required fields
	if cfg.Agent.DNSPort == 0 {
		cfg.Agent.DNSPort = 53 // Default
	}

	if len(cfg.DNS.Upstreams) == 0 {
		return fmt.Errorf("no DNS upstreams configured")
	}

	// Validate DNS upstreams
	for _, upstream := range cfg.DNS.Upstreams {
		if upstream == "" {
			return fmt.Errorf("empty DNS upstream configured")
		}
	}

	// Validate S3 configuration if present
	if cfg.S3.Bucket != "" {
		if cfg.S3.Region == "" {
			return fmt.Errorf("S3 bucket configured but region not specified")
		}
	}

	// Validate rate limiting
	if cfg.DNS.RateLimitQueries < 0 {
		return fmt.Errorf("invalid rate limit queries: %d", cfg.DNS.RateLimitQueries)
	}
	
	// Validate Splunk endpoint if configured
	if cfg.Logging.Splunk.Enabled && cfg.Logging.Splunk.Endpoint != "" {
		u, err := url.Parse(cfg.Logging.Splunk.Endpoint)
		if err != nil {
			return fmt.Errorf("invalid Splunk endpoint URL: %v", err)
		}
		
		// Only allow HTTPS for Splunk
		if u.Scheme != "https" {
			return fmt.Errorf("Splunk endpoint must use HTTPS")
		}
		
		// Basic hostname validation
		if u.Hostname() == "" {
			return fmt.Errorf("Splunk endpoint must have a hostname")
		}
	}

	return nil
}