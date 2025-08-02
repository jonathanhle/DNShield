package logging

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/sirupsen/logrus"
)

// SensitivePatterns defines regex patterns for sensitive data
var SensitivePatterns = []*regexp.Regexp{
	// AWS Access Key ID (20 characters, starts with AKIA, ASIA, or AIDA)
	regexp.MustCompile(`\b(A[IS])[A-Z]{2}[A-Z0-9]{16}\b`),
	// AWS Secret Access Key (40 characters)
	regexp.MustCompile(`\b[A-Za-z0-9/+=]{40}\b`),
	// Generic API keys (32+ hex characters)
	regexp.MustCompile(`\b[a-fA-F0-9]{32,}\b`),
	// Base64 encoded keys (common for private keys)
	regexp.MustCompile(`\b[A-Za-z0-9+/]{100,}={0,2}\b`),
	// JWT tokens
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`),
	// Email addresses (PII)
	regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`),
	// IP addresses (PII in some contexts)
	regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`),
}

// SensitiveFieldNames are field names that should be redacted
var SensitiveFieldNames = map[string]bool{
	"password":        true,
	"secret":          true,
	"key":             true,
	"token":           true,
	"accesskeyid":     true,
	"secretkey":       true,
	"secretaccesskey": true,
	"apikey":          true,
	"privatekey":      true,
	"credentials":     true,
	"authorization":   true,
}

// SafeLogger wraps logrus to provide automatic sanitization
type SafeLogger struct {
	*logrus.Logger
	enablePIILogging bool
}

// NewSafeLogger creates a new logger with sanitization
func NewSafeLogger(enablePII bool) *SafeLogger {
	return &SafeLogger{
		Logger:           logrus.StandardLogger(),
		enablePIILogging: enablePII,
	}
}

// SanitizeString removes sensitive patterns from a string
func SanitizeString(s string) string {
	// First, check for obvious AWS credentials
	if strings.Contains(s, "AKIA") || strings.Contains(s, "ASIA") {
		s = strings.ReplaceAll(s, s, "[REDACTED-AWS-KEY]")
		return s
	}

	// Apply regex patterns
	for _, pattern := range SensitivePatterns {
		s = pattern.ReplaceAllString(s, "[REDACTED]")
	}

	return s
}

// SanitizeFields removes sensitive data from log fields
func SanitizeFields(fields logrus.Fields) logrus.Fields {
	sanitized := make(logrus.Fields)
	
	for k, v := range fields {
		// Check if field name is sensitive
		if SensitiveFieldNames[strings.ToLower(k)] {
			sanitized[k] = "[REDACTED]"
			continue
		}

		// Sanitize the value
		switch val := v.(type) {
		case string:
			sanitized[k] = SanitizeString(val)
		case error:
			if val != nil {
				sanitized[k] = SanitizeString(val.Error())
			}
		case fmt.Stringer:
			sanitized[k] = SanitizeString(val.String())
		default:
			// For other types, convert to string and sanitize
			sanitized[k] = SanitizeString(fmt.Sprintf("%v", val))
		}
	}

	return sanitized
}

// WithField adds a sanitized field
func (s *SafeLogger) WithField(key string, value interface{}) *logrus.Entry {
	fields := logrus.Fields{key: value}
	return s.Logger.WithFields(SanitizeFields(fields))
}

// WithFields adds sanitized fields
func (s *SafeLogger) WithFields(fields logrus.Fields) *logrus.Entry {
	return s.Logger.WithFields(SanitizeFields(fields))
}

// WithError adds a sanitized error
func (s *SafeLogger) WithError(err error) *logrus.Entry {
	if err == nil {
		return s.Logger.WithError(err)
	}
	
	// Create a sanitized error
	sanitizedErr := fmt.Errorf("%s", SanitizeString(err.Error()))
	return s.Logger.WithError(sanitizedErr)
}

// ConfigSanitizer sanitizes configuration for logging
type ConfigSanitizer struct{}

// SanitizeConfig returns a safe version of config for logging
func (cs *ConfigSanitizer) SanitizeConfig(cfg interface{}) map[string]interface{} {
	// This is a simplified version - in production, use reflection
	// to deeply sanitize nested structures
	result := make(map[string]interface{})
	
	// For now, return a generic sanitized version
	result["status"] = "config loaded"
	result["sensitive_fields"] = "[REDACTED]"
	
	return result
}

// LogConfig safely logs configuration
func LogConfig(cfg interface{}) {
	cs := &ConfigSanitizer{}
	sanitized := cs.SanitizeConfig(cfg)
	logrus.WithFields(logrus.Fields(sanitized)).Info("Configuration loaded")
}

// Hook for sanitizing all log entries
type SanitizingHook struct {
	enablePIILogging bool
}

// NewSanitizingHook creates a new sanitizing hook
func NewSanitizingHook(enablePII bool) *SanitizingHook {
	return &SanitizingHook{
		enablePIILogging: enablePII,
	}
}

// Levels returns all log levels
func (h *SanitizingHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

// Fire sanitizes log entries before they're written
func (h *SanitizingHook) Fire(entry *logrus.Entry) error {
	// Sanitize message
	entry.Message = SanitizeString(entry.Message)
	
	// Sanitize fields
	if entry.Data != nil {
		entry.Data = SanitizeFields(entry.Data)
	}
	
	// Remove PII if not enabled
	if !h.enablePIILogging {
		// Remove IP addresses from message
		ipPattern := regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)
		entry.Message = ipPattern.ReplaceAllString(entry.Message, "[IP-REDACTED]")
		
		// Remove client IPs from fields
		if _, ok := entry.Data["client_ip"]; ok {
			entry.Data["client_ip"] = "[IP-REDACTED]"
		}
		if _, ok := entry.Data["clientIP"]; ok {
			entry.Data["clientIP"] = "[IP-REDACTED]"
		}
	}
	
	return nil
}

// InstallSanitizingHook installs the sanitizing hook globally
func InstallSanitizingHook(enablePII bool) {
	hook := NewSanitizingHook(enablePII)
	logrus.AddHook(hook)
}