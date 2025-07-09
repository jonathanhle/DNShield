// Package ca handles Certificate Authority operations for DNShield.
package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"path/filepath"
)

// LegacyCAAdapter adapts the legacy CA to the Manager interface
type LegacyCAAdapter struct {
	ca *CA
}

// LoadOrCreateLegacyCA loads or creates a legacy file-based CA
func LoadOrCreateLegacyCA() (*CA, error) {
	caPath := GetCAPath()
	certPath := filepath.Join(caPath, caCertFile)
	keyPath := filepath.Join(caPath, caKeyFile)

	// Try to load existing CA
	if ca, err := loadCA(certPath, keyPath); err == nil {
		return ca, nil
	}

	// Create new CA
	return createCA(caPath)
}

// Certificate returns the CA certificate
func (a *LegacyCAAdapter) Certificate() *x509.Certificate {
	return a.ca.cert
}

// CertificatePEM returns the CA certificate in PEM format
func (a *LegacyCAAdapter) CertificatePEM() []byte {
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: a.ca.cert.Raw,
	})
	return certPEM
}

// SignCertificate signs a certificate using the CA
func (a *LegacyCAAdapter) SignCertificate(template, parent *x509.Certificate, pub crypto.PublicKey) ([]byte, error) {
	return x509.CreateCertificate(rand.Reader, template, parent, pub, a.ca.key)
}

// InstallCA installs the CA certificate in the system
func (a *LegacyCAAdapter) InstallCA() error {
	return a.ca.InstallCA()
}

// GenerateCert generates a certificate for the legacy CA (compatibility method)
func (a *LegacyCAAdapter) GenerateCert(domain string) (*x509.Certificate, *rsa.PrivateKey, error) {
	return a.ca.GenerateCert(domain)
}
