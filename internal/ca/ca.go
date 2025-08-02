// Package ca handles Certificate Authority operations for DNShield.
// It manages CA generation, storage, and certificate signing to enable
// HTTPS interception without browser warnings.
//
// Security Warning: CA private keys can sign certificates for ANY domain.
// They must be protected with appropriate file permissions and should be
// stored in the system keychain in production deployments. See SECURITY.md
// for detailed security considerations.
package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"dnshield/internal/security"
)

const (
	caDir      = ".dnshield"
	caCertFile = "ca.crt"
	caKeyFile  = "ca.key"
)

type CA struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
}

// GetCAPath returns the path to CA directory
func GetCAPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join("/tmp", caDir)
	}
	return filepath.Join(home, caDir)
}

// LoadOrCreateCA loads an existing CA or creates a new one if none exists (legacy version).
// This is the primary entry point for CA initialization.
//
// The CA is stored in ~/.dnshield/ with the following files:
//   - ca.crt: The CA certificate (public)
//   - ca.key: The CA private key (must be protected)
//
// Security Warning: The CA private key can sign certificates for ANY domain.
// In production environments, consider using macOS Keychain for key storage.
// See SECURITY.md for detailed security considerations.
//
// Returns an error if CA operations fail.
func LoadOrCreateCA() (*CA, error) {
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

// loadCA loads CA from files
func loadCA(certPath, keyPath string) (*CA, error) {
	// Read certificate
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}

	block, rest := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM")
	}
	if len(rest) > 0 {
		// Log warning about extra data but continue
		// This is common with certificate chains
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	// Read key
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	block, rest = pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode key PEM")
	}
	if len(rest) > 0 {
		// Extra data after private key is suspicious
		return nil, fmt.Errorf("unexpected data after private key PEM block")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8
		keyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		var ok bool
		key, ok = keyInterface.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not an RSA private key")
		}
	}

	return &CA{cert: cert, key: key}, nil
}

// createCA creates a new CA
func createCA(caPath string) (*CA, error) {
	// Create directory
	if err := os.MkdirAll(caPath, 0700); err != nil {
		return nil, err
	}
	
	// Use a lock file to prevent concurrent CA creation
	lockPath := filepath.Join(caPath, ".ca_creation.lock")
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		if os.IsExist(err) {
			// Another process is creating the CA, wait and retry loading
			time.Sleep(100 * time.Millisecond)
			certPath := filepath.Join(caPath, caCertFile)
			keyPath := filepath.Join(caPath, caKeyFile)
			return loadCA(certPath, keyPath)
		}
		return nil, fmt.Errorf("failed to acquire CA creation lock: %v", err)
	}
	defer func() {
		lockFile.Close()
		os.Remove(lockPath)
	}()

	// Generate key
	key, err := rsa.GenerateKey(rand.Reader, security.CAKeyBits)
	if err != nil {
		return nil, err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"DNShield"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now().Add(-security.CertificateNotBeforeOffset),
		NotAfter:              time.Now().Add(time.Duration(security.CAValidityYears) * 365 * 24 * time.Hour), // 2 years
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	// Generate certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	// Save certificate
	certPath := filepath.Join(caPath, caCertFile)
	certFile, err := os.Create(certPath)
	if err != nil {
		return nil, err
	}
	defer certFile.Close()

	err = pem.Encode(certFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	if err != nil {
		return nil, err
	}

	// Save key
	keyPath := filepath.Join(caPath, caKeyFile)
	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, err
	}
	defer keyFile.Close()

	err = pem.Encode(keyFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	if err != nil {
		return nil, err
	}

	return &CA{cert: cert, key: key}, nil
}

// InstallCA installs the CA certificate in the system keychain
func (ca *CA) InstallCA() error {
	certPath := filepath.Join(GetCAPath(), caCertFile)

	// On macOS, use security command with Touch ID
	// The -p option allows Touch ID authentication
	cmd := exec.Command("sudo", "-p", "Touch ID or enter password: ", "security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", certPath)

	// Set up for interactive authentication
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to install CA: %v", err)
	}

	return nil
}

// GenerateCert generates a TLS certificate for the specified domain.
// The certificate is signed by the CA and valid for one year.
//
// Security considerations:
//   - Uses 2048-bit RSA keys for performance (4096-bit for CA)
//   - Includes both the domain and wildcard subdomain
//   - Should only be called for domains that are actually blocked
//   - Consider implementing certificate transparency in production
//
// Parameters:
//   - domain: The domain name to generate a certificate for
//
// Returns:
//   - The generated certificate
//   - The private key for the certificate
//   - An error if generation fails
func (ca *CA) GenerateCert(domain string) (*x509.Certificate, *rsa.PrivateKey, error) {
	// Generate key
	key, err := rsa.GenerateKey(rand.Reader, security.CertificateKeyBits)
	if err != nil {
		return nil, nil, err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			CommonName: domain,
		},
		NotBefore:   time.Now().Add(-security.CertificateNotBeforeOffset),
		NotAfter:    time.Now().Add(security.GetDomainCertificateValidity()), // 5 minutes
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    getDNSNames(domain),
	}

	// Generate certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, nil, err
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	return cert, key, nil
}

// GetCert returns the CA certificate
func (ca *CA) GetCert() *x509.Certificate {
	return ca.cert
}

// GetKey returns the CA private key
func (ca *CA) GetKey() *rsa.PrivateKey {
	return ca.key
}

// getDNSNames returns the DNS names for a certificate based on security configuration
func getDNSNames(domain string) []string {
	if security.IncludeWildcardDomains {
		return []string{domain, "*." + domain}
	}
	return []string{domain}
}
