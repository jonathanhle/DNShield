package config

import (
	"fmt"
	"os"
	"strings"
	
	"github.com/sirupsen/logrus"
)

// CredentialSource represents where credentials come from
type CredentialSource string

const (
	CredentialSourceNone        CredentialSource = "none"
	CredentialSourceEnvironment CredentialSource = "environment"
	CredentialSourceConfig      CredentialSource = "config"
	CredentialSourceIAMRole     CredentialSource = "iam-role"
)

// AWSCredentials holds AWS credential information
type AWSCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	Source          CredentialSource
}

// GetAWSCredentials retrieves AWS credentials from the most secure available source
func GetAWSCredentials(s3Config *S3Config) (*AWSCredentials, error) {
	// Priority order (most secure to least secure):
	// 1. IAM Role (no credentials needed)
	// 2. Environment variables
	// 3. Config file (deprecated, will warn)

	// Check for IAM role by looking for specific environment variables
	if os.Getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI") != "" ||
		os.Getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI") != "" ||
		os.Getenv("AWS_EXECUTION_ENV") != "" {
		return &AWSCredentials{
			Source: CredentialSourceIAMRole,
		}, nil
	}

	// Check environment variables
	accessKey := os.Getenv("AWS_ACCESS_KEY_ID")
	secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	
	if accessKey != "" && secretKey != "" {
		return &AWSCredentials{
			AccessKeyID:     accessKey,
			SecretAccessKey: secretKey,
			Source:          CredentialSourceEnvironment,
		}, nil
	}

	// Check config file (deprecated)
	if s3Config.AccessKeyID != "" && s3Config.SecretKey != "" {
		// Log warning about insecure practice
		fmt.Fprintf(os.Stderr, "WARNING: AWS credentials found in config file. This is insecure!\n")
		fmt.Fprintf(os.Stderr, "Please use environment variables or IAM roles instead.\n")
		fmt.Fprintf(os.Stderr, "Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables.\n\n")
		
		return &AWSCredentials{
			AccessKeyID:     s3Config.AccessKeyID,
			SecretAccessKey: s3Config.SecretKey,
			Source:          CredentialSourceConfig,
		}, nil
	}

	// No credentials found - AWS SDK will try default credential chain
	return &AWSCredentials{
		Source: CredentialSourceNone,
	}, nil
}

// SanitizeConfig removes sensitive information from config for logging
func SanitizeConfig(cfg *Config) Config {
	sanitized := *cfg
	
	// Clear S3 credentials
	if sanitized.S3.AccessKeyID != "" {
		sanitized.S3.AccessKeyID = "***REDACTED***"
	}
	if sanitized.S3.SecretKey != "" {
		sanitized.S3.SecretKey = "***REDACTED***"
	}
	
	// Clear any other sensitive fields that might be added in the future
	return sanitized
}

// ValidateCredentialSecurity checks if credentials are stored securely
func ValidateCredentialSecurity(cfg *Config) []string {
	var warnings []string
	
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
	
	// Check if credentials might be in the config file path itself
	configPath := os.Getenv("DNSHIELD_CONFIG")
	if configPath != "" && (strings.Contains(configPath, "key") || strings.Contains(configPath, "secret")) {
		warnings = append(warnings, "Config file path contains potential credentials")
	}
	
	// Log warnings for convenience (caller can still use returned warnings)
	for _, warning := range warnings {
		logrus.Warn(fmt.Sprintf("SECURITY: %s", warning))
	}
	
	return warnings
}