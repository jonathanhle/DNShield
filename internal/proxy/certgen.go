package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"sync"
	"time"

	"dns-guardian/internal/audit"
	"dns-guardian/internal/ca"
	"dns-guardian/internal/security"
	"github.com/sirupsen/logrus"
)

// cachedCert wraps a certificate with its expiration time
type cachedCert struct {
	cert      *tls.Certificate
	expiresAt time.Time
}

// CertGenerator generates certificates dynamically
type CertGenerator struct {
	ca    ca.Manager
	cache map[string]*cachedCert
	mu    sync.RWMutex
}

// NewCertGenerator creates a new certificate generator
func NewCertGenerator(caManager ca.Manager) *CertGenerator {
	gen := &CertGenerator{
		ca:    caManager,
		cache: make(map[string]*cachedCert),
	}
	
	// Start cache cleanup goroutine
	go gen.cleanupExpiredCerts()
	
	return gen
}

// GetCertificate generates or retrieves a cached TLS certificate for the
// specified domain. It implements the tls.Config.GetCertificate interface
// for dynamic certificate generation during TLS handshakes.
//
// The function maintains an in-memory cache of generated certificates to
// improve performance. Cache entries expire based on certificate validity.
//
// Security considerations:
//   - This function should only be called for domains blocked by DNS
//   - In future versions, add domain validation before generation
//   - Consider implementing rate limiting to prevent abuse
//   - Add audit logging for all certificate generation events
//
// Parameters:
//   - hello: The TLS ClientHello containing the requested server name
//
// Returns:
//   - A valid TLS certificate for the domain
//   - An error if certificate generation fails
func (g *CertGenerator) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	domain := hello.ServerName
	
	// Check cache
	g.mu.RLock()
	if cached, ok := g.cache[domain]; ok {
		// Check if certificate is still valid
		if time.Now().Before(cached.expiresAt) {
			g.mu.RUnlock()
			logrus.WithField("domain", domain).Debug("Certificate cache hit")
			audit.LogCertGeneration(domain, 0, true)
			return cached.cert, nil
		}
		// Certificate expired, remove from cache
		g.mu.RUnlock()
		g.mu.Lock()
		delete(g.cache, domain)
		g.mu.Unlock()
		logrus.WithField("domain", domain).Debug("Certificate cache expired")
	} else {
		g.mu.RUnlock()
	}
	
	// Generate new certificate
	start := time.Now()
	
	// Generate key pair
	key, err := rsa.GenerateKey(rand.Reader, security.CertificateKeyBits)
	if err != nil {
		return nil, err
	}
	
	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			CommonName: domain,
		},
		NotBefore:    time.Now().Add(-security.CertificateNotBeforeOffset),
		NotAfter:     time.Now().Add(security.GetDomainCertificateValidity()), // 5 minutes
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     getDNSNames(domain),
	}
	
	// Sign certificate
	certDER, err := g.ca.SignCertificate(template, g.ca.Certificate(), &key.PublicKey)
	if err != nil {
		return nil, err
	}
	
	// Parse certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}
	
	// Convert to tls.Certificate
	tlsCert := &tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  key,
		Leaf:        cert,
	}
	
	// Cache it with expiration time
	// Use certificate NotAfter minus buffer for cache expiration
	cacheTTL := security.GetCacheTTL()
	expiresAt := time.Now().Add(cacheTTL)
	
	g.mu.Lock()
	g.cache[domain] = &cachedCert{
		cert:      tlsCert,
		expiresAt: expiresAt,
	}
	g.mu.Unlock()
	
	logrus.WithFields(logrus.Fields{
		"domain":    domain,
		"cacheTTL":  cacheTTL,
		"expiresAt": expiresAt.Format(time.RFC3339),
	}).Debug("Certificate cached")
	
	duration := time.Since(start)
	logrus.WithFields(logrus.Fields{
		"domain":   domain,
		"duration": duration,
		"validity": security.GetDomainCertificateValidity(),
		"notAfter": cert.NotAfter.Format(time.RFC3339),
	}).Info("Generated certificate")
	
	// Audit log the certificate generation
	audit.LogCertGeneration(domain, duration, false)
	
	return tlsCert, nil
}

// ClearCache clears the certificate cache
func (g *CertGenerator) ClearCache() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.cache = make(map[string]*cachedCert)
}

// cleanupExpiredCerts runs periodically to remove expired certificates from cache
func (g *CertGenerator) cleanupExpiredCerts() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for range ticker.C {
		now := time.Now()
		expired := []string{}
		
		// Find expired certificates
		g.mu.RLock()
		for domain, cached := range g.cache {
			if now.After(cached.expiresAt) {
				expired = append(expired, domain)
			}
		}
		g.mu.RUnlock()
		
		// Remove expired certificates
		if len(expired) > 0 {
			g.mu.Lock()
			for _, domain := range expired {
				delete(g.cache, domain)
			}
			g.mu.Unlock()
			
			logrus.WithField("count", len(expired)).Debug("Cleaned up expired certificates")
		}
	}
}

// getDNSNames returns the DNS names for a certificate based on security configuration
func getDNSNames(domain string) []string {
	if security.IncludeWildcardDomains {
		return []string{domain, "*." + domain}
	}
	return []string{domain}
}