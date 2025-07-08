// Package ca handles Certificate Authority operations for DNS Guardian.
package ca

import (
	"crypto"
	"crypto/x509"
	"os"
	"runtime"
)

// Manager defines the interface for CA operations
type Manager interface {
	Certificate() *x509.Certificate
	CertificatePEM() []byte
	SignCertificate(template, parent *x509.Certificate, pub crypto.PublicKey) ([]byte, error)
	InstallCA() error
}

// UseKeychain determines if Keychain storage should be used
func UseKeychain() bool {
	// Check if we're on macOS
	if runtime.GOOS != "darwin" {
		return false
	}
	
	// Check environment variable
	if os.Getenv("DNS_GUARDIAN_USE_KEYCHAIN") == "true" {
		return true
	}
	
	// Check if we're in v2.0 mode (for crypto exchange)
	if os.Getenv("DNS_GUARDIAN_SECURITY_MODE") == "v2" {
		return true
	}
	
	return false
}

// LoadOrCreateManager loads existing CA or creates new one based on configuration
func LoadOrCreateManager() (Manager, error) {
	if UseKeychain() {
		return LoadOrCreateKeychainCA()
	}
	
	// Use legacy file-based CA for compatibility
	legacyCA, err := LoadOrCreateLegacyCA()
	if err != nil {
		return nil, err
	}
	
	return &LegacyCAAdapter{ca: legacyCA}, nil
}