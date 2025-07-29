package config

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
)

// ValidateCredentialSecurity checks for insecure credential practices
func ValidateCredentialSecurity(cfg *Config) {
	warnings := []string{}

	// Check for AWS credentials in config
	if cfg.S3.AccessKeyID != "" || cfg.S3.SecretKey != "" {
		warnings = append(warnings, "AWS credentials found in configuration file - consider using environment variables or IAM roles")
	}

	// Check for Splunk token in config
	if cfg.Logging.Splunk.Enabled && cfg.Logging.Splunk.Token != "" {
		warnings = append(warnings, "Splunk HEC token found in configuration file - consider using environment variables")
	}

	// Check if running in debug mode
	if cfg.Agent.LogLevel == "debug" {
		warnings = append(warnings, "Running in debug mode - sensitive data may be exposed in logs")
		
		// Extra warning if PII logging is enabled
		if os.Getenv("DNSHIELD_ENABLE_PII_LOGGING") == "true" {
			warnings = append(warnings, "PII logging is enabled - client IPs and domains will be logged")
		}
	}

	// Log warnings
	for _, warning := range warnings {
		logrus.Warn(fmt.Sprintf("SECURITY: %s", warning))
	}
}

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

	return nil
}