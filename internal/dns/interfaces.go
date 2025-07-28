package dns

import "time"

// DNSManager defines the interface for DNS management
type DNSManager interface {
	// Start begins monitoring for network changes
	Start() error
	
	// Stop stops monitoring
	Stop()
	
	// EnableDNSFiltering activates DNS filtering
	EnableDNSFiltering() error
	
	// DisableDNSFiltering deactivates DNS filtering
	DisableDNSFiltering() error
	
	// PauseDNSFiltering temporarily restores original DNS
	PauseDNSFiltering(duration time.Duration) error
	
	// ResumeDNSFiltering resumes filtering before timeout
	ResumeDNSFiltering() error
	
	// IsPaused returns whether filtering is paused
	IsPaused() bool
	
	// GetCurrentNetwork returns info about current network (optional)
	GetCurrentNetwork() *NetworkIdentity
	
	// GetNetworkDNS returns DNS config for current network (optional)
	GetNetworkDNS() *NetworkDNSConfig
}