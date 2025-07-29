package logging

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestSanitizeString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "AWS Access Key",
			input:    "Found key: AKIAIOSFODNN7EXAMPLE",
			expected: "[REDACTED-AWS-KEY]",
		},
		{
			name:     "AWS Secret Key",
			input:    "Secret: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			expected: "Secret: [REDACTED]",
		},
		{
			name:     "Mixed content with key",
			input:    "Using credentials AKIAIOSFODNN7EXAMPLE for S3",
			expected: "[REDACTED-AWS-KEY]",
		},
		{
			name:     "Email address",
			input:    "User logged in: user@example.com",
			expected: "User logged in: [REDACTED]",
		},
		{
			name:     "IP address",
			input:    "Connection from 192.168.1.100",
			expected: "Connection from [REDACTED]",
		},
		{
			name:     "JWT token",
			input:    "Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			expected: "Token: [REDACTED]",
		},
		{
			name:     "Clean string",
			input:    "This is a normal log message",
			expected: "This is a normal log message",
		},
		{
			name:     "API key hex",
			input:    "API Key: a1b2c3d4e5f6789012345678901234567890abcd",
			expected: "API Key: [REDACTED]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeString(tt.input)
			if result != tt.expected {
				t.Errorf("SanitizeString() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestSanitizeFields(t *testing.T) {
	fields := logrus.Fields{
		"message":   "Normal message",
		"password":  "supersecret",
		"apikey":    "12345678901234567890123456789012",
		"user":      "john@example.com",
		"client_ip": "192.168.1.100",
		"error":     errors.New("Failed with key AKIAIOSFODNN7EXAMPLE"),
	}

	sanitized := SanitizeFields(fields)

	// Check sanitization
	if sanitized["password"] != "[REDACTED]" {
		t.Errorf("Expected password to be redacted, got %v", sanitized["password"])
	}
	if sanitized["apikey"] != "[REDACTED]" {
		t.Errorf("Expected apikey to be redacted, got %v", sanitized["apikey"])
	}
	if sanitized["user"] != "[REDACTED]" {
		t.Errorf("Expected user email to be redacted, got %v", sanitized["user"])
	}
	if sanitized["client_ip"] != "[REDACTED]" {
		t.Errorf("Expected client_ip to be redacted, got %v", sanitized["client_ip"])
	}
	if !strings.Contains(sanitized["error"].(string), "[REDACTED") {
		t.Errorf("Expected error to contain redacted AWS key, got %v", sanitized["error"])
	}
}

func TestSanitizingHook(t *testing.T) {
	// Create a logger with custom output
	var buf bytes.Buffer
	logger := logrus.New()
	logger.Out = &buf
	logger.SetLevel(logrus.InfoLevel)
	logger.SetFormatter(&logrus.TextFormatter{
		DisableTimestamp: true,
		DisableColors:    true,
	})

	// Add sanitizing hook
	hook := NewSanitizingHook(false) // PII disabled
	logger.AddHook(hook)

	// Test various log scenarios
	logger.WithField("password", "mysecret").Info("Login attempt")
	output := buf.String()
	if strings.Contains(output, "mysecret") {
		t.Error("Password not redacted from log output")
	}
	if !strings.Contains(output, "[REDACTED]") {
		t.Error("Expected [REDACTED] in log output")
	}

	// Test IP redaction when PII is disabled
	buf.Reset()
	logger.Info("Connection from 192.168.1.100")
	output = buf.String()
	if strings.Contains(output, "192.168.1.100") {
		t.Error("IP address not redacted when PII logging disabled")
	}
	if !strings.Contains(output, "[IP-REDACTED]") {
		t.Error("Expected [IP-REDACTED] in log output")
	}

	// Test AWS key redaction
	buf.Reset()
	logger.WithError(errors.New("AWS error with key AKIAIOSFODNN7EXAMPLE")).Error("Failed")
	output = buf.String()
	if strings.Contains(output, "AKIAIOSFODNN7EXAMPLE") {
		t.Error("AWS key not redacted from error")
	}
}

func TestSanitizingHookWithPII(t *testing.T) {
	// Create a logger with custom output
	var buf bytes.Buffer
	logger := logrus.New()
	logger.Out = &buf
	logger.SetLevel(logrus.InfoLevel)
	logger.SetFormatter(&logrus.TextFormatter{
		DisableTimestamp: true,
		DisableColors:    true,
	})

	// Add sanitizing hook with PII enabled
	hook := NewSanitizingHook(true) // PII enabled
	logger.AddHook(hook)

	// Test that IPs are not redacted when PII is enabled
	logger.Info("Connection from 192.168.1.100")
	output := buf.String()
	if !strings.Contains(output, "192.168.1.100") {
		t.Error("IP address should not be redacted when PII logging enabled")
	}

	// But sensitive data should still be redacted
	buf.Reset()
	logger.WithField("apikey", "12345678901234567890123456789012").Info("API call")
	output = buf.String()
	if strings.Contains(output, "12345678901234567890123456789012") {
		t.Error("API key not redacted even with PII enabled")
	}
}