// Package audit provides security audit logging for DNS Guardian.
// It tracks sensitive operations like certificate generation, CA access,
// and configuration changes for compliance and security monitoring.
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// EventType represents the type of audit event
type EventType string

const (
	// Certificate operations
	EventCertGenerated    EventType = "CERT_GENERATED"
	EventCertCacheHit     EventType = "CERT_CACHE_HIT"
	EventCAAccess         EventType = "CA_ACCESS"
	EventCAInstalled      EventType = "CA_INSTALLED"
	EventCAUninstalled    EventType = "CA_UNINSTALLED"
	
	// Security operations
	EventKeychainAccess   EventType = "KEYCHAIN_ACCESS"
	EventKeychainStore    EventType = "KEYCHAIN_STORE"
	EventSecurityViolation EventType = "SECURITY_VIOLATION"
	
	// Configuration changes
	EventConfigChange     EventType = "CONFIG_CHANGE"
	EventRulesUpdate      EventType = "RULES_UPDATE"
	
	// Service lifecycle
	EventServiceStart     EventType = "SERVICE_START"
	EventServiceStop      EventType = "SERVICE_STOP"
)

// Event represents an audit log entry
type Event struct {
	Timestamp   time.Time              `json:"timestamp"`
	Type        EventType              `json:"type"`
	Severity    string                 `json:"severity"`
	Message     string                 `json:"message"`
	Details     map[string]interface{} `json:"details,omitempty"`
	User        string                 `json:"user,omitempty"`
	ProcessID   int                    `json:"process_id"`
	ProcessName string                 `json:"process_name"`
}

// Logger handles audit logging
type Logger struct {
	file       *os.File
	encoder    *json.Encoder
	mu         sync.Mutex
	logPath    string
}

var (
	defaultLogger *Logger
	once         sync.Once
)

// Initialize sets up the audit logger
func Initialize() error {
	var err error
	once.Do(func() {
		// Create audit directory
		home, _ := os.UserHomeDir()
		auditDir := filepath.Join(home, ".dns-guardian", "audit")
		if mkErr := os.MkdirAll(auditDir, 0700); mkErr != nil {
			err = mkErr
			return
		}
		
		// Create log file with timestamp
		logFile := fmt.Sprintf("audit-%s.log", time.Now().Format("2006-01-02"))
		logPath := filepath.Join(auditDir, logFile)
		
		// Open file
		file, openErr := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if openErr != nil {
			err = openErr
			return
		}
		
		defaultLogger = &Logger{
			file:    file,
			encoder: json.NewEncoder(file),
			logPath: logPath,
		}
		
		// Log initialization
		Log(EventServiceStart, "info", "Audit logging initialized", nil)
	})
	
	return err
}

// Log records an audit event
func Log(eventType EventType, severity string, message string, details map[string]interface{}) {
	if defaultLogger == nil {
		// Fallback to regular logging if audit not initialized
		logrus.WithFields(logrus.Fields{
			"audit_type": eventType,
			"details":    details,
		}).Info(message)
		return
	}
	
	event := Event{
		Timestamp:   time.Now(),
		Type:        eventType,
		Severity:    severity,
		Message:     message,
		Details:     details,
		ProcessID:   os.Getpid(),
		ProcessName: filepath.Base(os.Args[0]),
	}
	
	// Add user if available
	if user := os.Getenv("USER"); user != "" {
		event.User = user
	}
	
	defaultLogger.mu.Lock()
	defer defaultLogger.mu.Unlock()
	
	// Write to audit log
	if err := defaultLogger.encoder.Encode(event); err != nil {
		logrus.WithError(err).Error("Failed to write audit log")
	}
	
	// Also log to standard logger for real-time monitoring
	logrus.WithFields(logrus.Fields{
		"audit_type": eventType,
		"severity":   severity,
		"details":    details,
	}).Info(message)
}

// LogCertGeneration logs certificate generation events
func LogCertGeneration(domain string, duration time.Duration, cached bool) {
	eventType := EventCertGenerated
	if cached {
		eventType = EventCertCacheHit
	}
	
	Log(eventType, "info", fmt.Sprintf("Certificate for %s", domain), map[string]interface{}{
		"domain":   domain,
		"duration": duration.String(),
		"cached":   cached,
	})
}

// LogCAAccess logs CA key access
func LogCAAccess(operation string, success bool) {
	severity := "info"
	if !success {
		severity = "warning"
	}
	
	Log(EventCAAccess, severity, fmt.Sprintf("CA %s", operation), map[string]interface{}{
		"operation": operation,
		"success":   success,
	})
}

// LogSecurityViolation logs potential security issues
func LogSecurityViolation(violation string, details map[string]interface{}) {
	Log(EventSecurityViolation, "critical", violation, details)
}

// LogConfigChange logs configuration modifications
func LogConfigChange(change string, oldValue, newValue interface{}) {
	Log(EventConfigChange, "warning", change, map[string]interface{}{
		"old_value": oldValue,
		"new_value": newValue,
	})
}

// Close closes the audit logger
func Close() error {
	if defaultLogger != nil {
		Log(EventServiceStop, "info", "Audit logging stopped", nil)
		return defaultLogger.file.Close()
	}
	return nil
}

// GetLogPath returns the current audit log path
func GetLogPath() string {
	if defaultLogger != nil {
		return defaultLogger.logPath
	}
	return ""
}