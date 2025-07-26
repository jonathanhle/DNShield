package dns

import (
	"sync"
	"time"
	
	"github.com/sirupsen/logrus"
	"dnshield/internal/config"
	"dnshield/internal/security"
)

// CaptivePortalDetector tracks requests to captive portal domains
// to detect when a device is trying to connect through a captive portal
type CaptivePortalDetector struct {
	mu                sync.RWMutex
	requestCounts     map[string]int
	lastRequestTime   map[string]time.Time
	bypassMode        bool
	bypassUntil       time.Time
	enabled           bool
	threshold         int
	timeWindow        time.Duration
	bypassDuration    time.Duration
	additionalDomains []string
}

// NewCaptivePortalDetector creates a new captive portal detector
func NewCaptivePortalDetector(cfg *config.CaptivePortalConfig) *CaptivePortalDetector {
	// If no config provided, use defaults
	if cfg == nil {
		cfg = &config.CaptivePortalConfig{
			Enabled:            true,
			DetectionThreshold: 3,
			DetectionWindow:    10 * time.Second,
			BypassDuration:     5 * time.Minute,
		}
	}
	
	return &CaptivePortalDetector{
		requestCounts:     make(map[string]int),
		lastRequestTime:   make(map[string]time.Time),
		enabled:           cfg.Enabled,
		threshold:         cfg.DetectionThreshold,
		timeWindow:        cfg.DetectionWindow,
		bypassDuration:    cfg.BypassDuration,
		additionalDomains: cfg.AdditionalDomains,
	}
}

// RecordRequest records a DNS request and checks if captive portal bypass should be activated
func (c *CaptivePortalDetector) RecordRequest(domain string) {
	// Skip if detection is disabled
	if !c.enabled {
		return
	}
	
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if this is a captive portal domain (including additional domains)
	if !security.IsCaptivePortalDomainWithAdditional(domain, c.additionalDomains) {
		return
	}

	now := time.Now()
	
	// Clean up old entries
	for d, lastTime := range c.lastRequestTime {
		if now.Sub(lastTime) > c.timeWindow {
			delete(c.requestCounts, d)
			delete(c.lastRequestTime, d)
		}
	}

	// Record this request
	c.requestCounts[domain]++
	c.lastRequestTime[domain] = now

	// Log captive portal domain access for diagnostics
	logrus.WithFields(logrus.Fields{
		"domain":       domain,
		"count":        c.requestCounts[domain],
		"unique_count": len(c.requestCounts),
		"threshold":    c.threshold,
	}).Debug("Captive portal domain accessed")

	// Check if we've hit the threshold
	uniqueDomains := len(c.requestCounts)
	if uniqueDomains >= c.threshold && !c.bypassMode {
		logrus.WithFields(logrus.Fields{
			"unique_domains": uniqueDomains,
			"threshold":      c.threshold,
			"duration":       c.bypassDuration,
		}).Info("Captive portal detected - enabling bypass mode")
		c.EnableBypass()
	}
}

// EnableBypass enables bypass mode for the configured duration
func (c *CaptivePortalDetector) EnableBypass() {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.bypassMode = true
	c.bypassUntil = time.Now().Add(c.bypassDuration)
	
	// Clear counters
	c.requestCounts = make(map[string]int)
	c.lastRequestTime = make(map[string]time.Time)
	
	logrus.WithField("until", c.bypassUntil.Format(time.RFC3339)).Info("DNS filtering bypass enabled")
}

// DisableBypass manually disables bypass mode
func (c *CaptivePortalDetector) DisableBypass() {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.bypassMode = false
	c.bypassUntil = time.Time{}
	
	logrus.Info("DNS filtering bypass disabled")
}

// IsInBypassMode checks if bypass mode is currently active
func (c *CaptivePortalDetector) IsInBypassMode() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	if !c.bypassMode {
		return false
	}
	
	// Check if bypass period has expired
	if time.Now().After(c.bypassUntil) {
		c.mu.RUnlock()
		c.DisableBypass()
		c.mu.RLock()
		return false
	}
	
	return true
}

// GetBypassStatus returns the current bypass status and remaining time
func (c *CaptivePortalDetector) GetBypassStatus() (bool, time.Duration) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	if !c.bypassMode {
		return false, 0
	}
	
	remaining := time.Until(c.bypassUntil)
	if remaining < 0 {
		return false, 0
	}
	
	return true, remaining
}