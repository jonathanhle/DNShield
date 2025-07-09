// Package security defines hardcoded security constants for DNShield.
// These values are compiled into the binary and cannot be modified at runtime,
// providing defense against configuration tampering in high-security environments.
package security

import "time"

// Certificate validity periods - hardcoded for security
// These values are specifically chosen for high-security environments
// where certificate compromise must be minimized.
const (
	// CAValidityYears is the validity period for the Certificate Authority
	// 2 years balances security with operational overhead of CA rotation
	CAValidityYears = 2

	// DomainValidityMinutes is the validity period for domain certificates in minutes
	// 5 minutes minimizes the window for certificate abuse while allowing for clock skew
	DomainValidityMinutes = 5

	// DomainValidityDuration is the validity period for domain certificates as a Duration
	DomainValidityDuration = DomainValidityMinutes * time.Minute

	// CertificateNotBeforeOffset handles clock skew between systems
	// Certificates are valid from 1 minute before creation time
	CertificateNotBeforeOffset = 1 * time.Minute

	// MaxDomainValidityDuration is the absolute maximum validity for domain certificates
	// This prevents bugs or attacks that might try to create long-lived certificates
	MaxDomainValidityDuration = 1 * time.Hour

	// CacheTTLBuffer is subtracted from certificate validity for cache TTL
	// This ensures cached certificates are refreshed before they expire
	CacheTTLBuffer = 30 * time.Second
)

// Certificate generation flags
const (
	// IncludeWildcardDomains controls whether wildcard domains are included
	// Required for efficiently blocking hundreds of thousands of domains
	IncludeWildcardDomains = true

	// MaxCertificatesPerDomain limits certificate generation rate per domain
	// Prevents resource exhaustion attacks
	MaxCertificatesPerDomain = 50 // per hour

	// CertificateKeyBits is the RSA key size for domain certificates
	// 2048 bits provides good security/performance balance for short-lived certs
	CertificateKeyBits = 2048

	// CAKeyBits is the RSA key size for the Certificate Authority
	// 4096 bits for longer-lived CA certificates
	CAKeyBits = 4096
)

// Security validation constants
const (
	// MinimumValidityMinutes is the shortest allowed certificate validity
	// Some TLS implementations may reject certificates shorter than this
	MinimumValidityMinutes = 1

	// RecommendedValidityMinutes is the recommended validity for production
	// Allows for reasonable clock skew tolerance
	RecommendedValidityMinutes = 5
)

// GetDomainCertificateValidity returns the duration for domain certificates
// with validation to ensure it's within acceptable bounds
func GetDomainCertificateValidity() time.Duration {
	validity := DomainValidityDuration

	// Ensure we never exceed maximum
	if validity > MaxDomainValidityDuration {
		validity = MaxDomainValidityDuration
	}

	// Ensure we meet minimum
	minValidity := MinimumValidityMinutes * time.Minute
	if validity < minValidity {
		validity = minValidity
	}

	return validity
}

// GetCacheTTL returns the appropriate cache TTL for certificates
// based on their validity period
func GetCacheTTL() time.Duration {
	certValidity := GetDomainCertificateValidity()
	ttl := certValidity - CacheTTLBuffer

	// Minimum cache TTL of 30 seconds
	if ttl < 30*time.Second {
		ttl = 30 * time.Second
	}

	return ttl
}
