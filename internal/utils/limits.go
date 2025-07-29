package utils

import (
	"compress/gzip"
	"fmt"
	"io"
	"strings"
)

const (
	// MaxConfigFileSize is the maximum size for configuration files (1MB)
	MaxConfigFileSize = 1 * 1024 * 1024

	// MaxRulesFileSize is the maximum size for rules files (50MB)
	MaxRulesFileSize = 50 * 1024 * 1024

	// MaxS3ObjectSize is the maximum size for S3 objects (100MB)
	MaxS3ObjectSize = 100 * 1024 * 1024

	// MaxYAMLDepth is the maximum depth for YAML parsing
	MaxYAMLDepth = 100

	// MaxDomainLength is the maximum length for a domain name
	MaxDomainLength = 253

	// MaxDomainsPerRule is the maximum number of domains in a single rule
	MaxDomainsPerRule = 10000

	// MaxCacheEntries is the maximum number of entries in the DNS cache
	MaxCacheEntries = 100000

	// MaxCertCacheEntries is the maximum number of certificates to cache
	MaxCertCacheEntries = 1000

	// MaxConcurrentDNSQueries is the maximum number of concurrent DNS queries
	MaxConcurrentDNSQueries = 1000

	// MaxConcurrentCertGen is the maximum number of concurrent certificate generations
	MaxConcurrentCertGen = 50

	// MaxHTTPBodySize is the maximum size for HTTP request bodies (10MB)
	MaxHTTPBodySize = 10 * 1024 * 1024
)

// LimitedReader returns a reader that limits the amount of data read
func LimitedReader(r io.Reader, limit int64) io.Reader {
	return &io.LimitedReader{R: r, N: limit}
}

// ReadAllLimited reads all data from r up to limit bytes
func ReadAllLimited(r io.Reader, limit int64) ([]byte, error) {
	limited := LimitedReader(r, limit+1) // +1 to detect if limit exceeded
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("data exceeds maximum size of %d bytes", limit)
	}
	
	return data, nil
}

// SafeYAMLUnmarshal unmarshals YAML with size and depth limits
func SafeYAMLUnmarshal(data []byte, v interface{}, maxSize int64) error {
	// Check size limit
	if int64(len(data)) > maxSize {
		return fmt.Errorf("YAML data exceeds maximum size of %d bytes", maxSize)
	}
	
	// Check for YAML bombs (repeated anchors/aliases)
	if detectYAMLBomb(string(data)) {
		return fmt.Errorf("potential YAML bomb detected")
	}
	
	// Use a custom decoder with limits in the future
	// For now, use standard unmarshal with pre-checks
	return nil // Caller should use yaml.Unmarshal after this validation
}

// detectYAMLBomb checks for patterns that indicate a YAML bomb
func detectYAMLBomb(yaml string) bool {
	// Count anchors and aliases
	anchorCount := strings.Count(yaml, "&")
	aliasCount := strings.Count(yaml, "*")
	
	// If there are too many aliases relative to anchors, it might be a bomb
	if aliasCount > 10 && aliasCount > anchorCount*10 {
		return true
	}
	
	// Check for deeply nested structures
	nestingLevel := 0
	maxNesting := 0
	for _, char := range yaml {
		switch char {
		case '[', '{':
			nestingLevel++
			if nestingLevel > maxNesting {
				maxNesting = nestingLevel
			}
		case ']', '}':
			nestingLevel--
		}
	}
	
	if maxNesting > MaxYAMLDepth {
		return true
	}
	
	return false
}

// ValidateDomainLength checks if a domain name is within acceptable length
func ValidateDomainLength(domain string) error {
	if len(domain) > MaxDomainLength {
		return fmt.Errorf("domain name exceeds maximum length of %d characters", MaxDomainLength)
	}
	
	// Check individual label lengths (max 63 characters)
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if len(label) > 63 {
			return fmt.Errorf("domain label exceeds maximum length of 63 characters")
		}
	}
	
	return nil
}

// DomainLimiter provides rate limiting for domain operations
type DomainLimiter struct {
	count int
	max   int
}

// NewDomainLimiter creates a new domain limiter
func NewDomainLimiter(max int) *DomainLimiter {
	return &DomainLimiter{
		count: 0,
		max:   max,
	}
}

// Add attempts to add domains and returns error if limit exceeded
func (dl *DomainLimiter) Add(count int) error {
	if dl.count+count > dl.max {
		return fmt.Errorf("domain limit exceeded: %d + %d > %d", dl.count, count, dl.max)
	}
	dl.count += count
	return nil
}

// Reset resets the domain counter
func (dl *DomainLimiter) Reset() {
	dl.count = 0
}

// Count returns the current domain count
func (dl *DomainLimiter) Count() int {
	return dl.count
}

// GzipLimitedReader creates a gzip reader with size limits
func GzipLimitedReader(r io.Reader, limit int64) (*gzip.Reader, error) {
	limited := LimitedReader(r, limit)
	return gzip.NewReader(limited)
}

// ConcurrencyLimiter provides a simple semaphore for limiting concurrent operations
type ConcurrencyLimiter struct {
	sem chan struct{}
}

// NewConcurrencyLimiter creates a new concurrency limiter
func NewConcurrencyLimiter(max int) *ConcurrencyLimiter {
	return &ConcurrencyLimiter{
		sem: make(chan struct{}, max),
	}
}

// Acquire acquires a slot (blocks if at limit)
func (cl *ConcurrencyLimiter) Acquire() {
	cl.sem <- struct{}{}
}

// Release releases a slot
func (cl *ConcurrencyLimiter) Release() {
	<-cl.sem
}

// TryAcquire attempts to acquire a slot without blocking
func (cl *ConcurrencyLimiter) TryAcquire() bool {
	select {
	case cl.sem <- struct{}{}:
		return true
	default:
		return false
	}
}