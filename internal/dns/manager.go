package dns

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Manager handles DNS configuration for the system
type Manager struct {
	mu          sync.RWMutex
	configPath  string
	isManaging  bool
	isPaused    bool
	pauseTimer  *time.Timer
	originalDNS *DNSConfiguration
}

// DNSConfiguration stores DNS settings for all network interfaces
type DNSConfiguration struct {
	Version    int                        `json:"version"`
	CapturedAt time.Time                  `json:"captured_at"`
	CapturedBy string                     `json:"captured_by"`
	Interfaces map[string]InterfaceConfig `json:"interfaces"`
	Metadata   map[string]string          `json:"metadata"`
}

// InterfaceConfig stores DNS settings for a single interface
type InterfaceConfig struct {
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	DNSServers []string `json:"dns_servers"`
	IsDHCP     bool     `json:"is_dhcp"`
	IsActive   bool     `json:"is_active"`
}

// NewManager creates a new DNS configuration manager
func NewManager() *Manager {
	homeDir, _ := os.UserHomeDir()
	return &Manager{
		configPath: filepath.Join(homeDir, ".dnshield", "dns-config.json"),
	}
}

// CaptureOriginalDNS captures the current system DNS configuration
func (m *Manager) CaptureOriginalDNS() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	config, err := m.getCurrentDNSConfig()
	if err != nil {
		return fmt.Errorf("failed to capture DNS config: %w", err)
	}

	// Only save if we don't already have an original config
	if m.originalDNS == nil {
		m.originalDNS = config
		if err := m.saveDNSConfig(config); err != nil {
			return fmt.Errorf("failed to save DNS config: %w", err)
		}
		logrus.Info("Captured original DNS configuration")
	}

	return nil
}

// EnableDNSFiltering sets all interfaces to use DNShield (127.0.0.1)
func (m *Manager) EnableDNSFiltering() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Capture original DNS if not already done
	if m.originalDNS == nil {
		config, err := m.getCurrentDNSConfig()
		if err != nil {
			return err
		}
		// Only save if DNS is not already set to 127.0.0.1
		needsSave := false
		for _, iface := range config.Interfaces {
			for _, dns := range iface.DNSServers {
				if dns != "127.0.0.1" {
					needsSave = true
					break
				}
			}
		}
		if needsSave {
			m.originalDNS = config
			m.saveDNSConfig(config)
		} else {
			// Try to load saved config
			if savedConfig, err := m.loadDNSConfig(); err == nil {
				m.originalDNS = savedConfig
			}
		}
	}

	// Set all interfaces to use 127.0.0.1
	for _, iface := range m.originalDNS.Interfaces {
		if !iface.IsActive {
			continue
		}

		cmd := exec.Command("networksetup", "-setdnsservers", iface.Name, "127.0.0.1")
		if output, err := cmd.CombinedOutput(); err != nil {
			logrus.WithError(err).WithField("output", string(output)).
				Errorf("Failed to set DNS for interface %s", iface.Name)
			continue
		}

		logrus.WithField("interface", iface.Name).Info("Enabled DNS filtering")
	}

	m.isManaging = true
	m.isPaused = false
	return nil
}

// DisableDNSFiltering restores original DNS settings
func (m *Manager) DisableDNSFiltering() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.originalDNS == nil {
		// Try to load from disk
		config, err := m.loadDNSConfig()
		if err != nil {
			return fmt.Errorf("no original DNS configuration found")
		}
		m.originalDNS = config
	}

	return m.restoreDNSConfig(m.originalDNS)
}

// PauseDNSFiltering temporarily restores original DNS for specified duration
func (m *Manager) PauseDNSFiltering(duration time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.isPaused {
		return fmt.Errorf("DNS filtering is already paused")
	}

	if m.originalDNS == nil {
		return fmt.Errorf("no original DNS configuration found")
	}

	// Restore original DNS
	if err := m.restoreDNSConfig(m.originalDNS); err != nil {
		return fmt.Errorf("failed to restore DNS: %w", err)
	}

	m.isPaused = true

	// Set timer to re-enable
	if m.pauseTimer != nil {
		m.pauseTimer.Stop()
	}

	m.pauseTimer = time.AfterFunc(duration, func() {
		m.mu.Lock()
		defer m.mu.Unlock()

		if m.isPaused {
			m.EnableDNSFiltering()
			m.isPaused = false
			logrus.Info("DNS filtering resumed after pause timeout")
		}
	})

	logrus.WithField("duration", duration).Info("Paused DNS filtering")
	return nil
}

// ResumeDNSFiltering re-enables DNS filtering before pause timeout
func (m *Manager) ResumeDNSFiltering() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.isPaused {
		return fmt.Errorf("DNS filtering is not paused")
	}

	if m.pauseTimer != nil {
		m.pauseTimer.Stop()
		m.pauseTimer = nil
	}

	// Re-enable DNS filtering
	for _, iface := range m.originalDNS.Interfaces {
		if !iface.IsActive {
			continue
		}

		cmd := exec.Command("networksetup", "-setdnsservers", iface.Name, "127.0.0.1")
		cmd.CombinedOutput()
	}

	m.isPaused = false
	logrus.Info("Resumed DNS filtering")
	return nil
}

// IsPaused returns whether DNS filtering is currently paused
func (m *Manager) IsPaused() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.isPaused
}

// Private helper methods

func (m *Manager) getCurrentDNSConfig() (*DNSConfiguration, error) {
	// Get all network services
	cmd := exec.Command("networksetup", "-listallnetworkservices")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	config := &DNSConfiguration{
		Version:    1,
		CapturedAt: time.Now(),
		CapturedBy: "DNShield",
		Interfaces: make(map[string]InterfaceConfig),
		Metadata: map[string]string{
			"os":       "darwin",
			"hostname": getHostname(),
		},
	}

	lines := strings.Split(string(output), "\n")
	for i := 1; i < len(lines); i++ {
		service := strings.TrimSpace(lines[i])
		if service == "" || strings.HasPrefix(service, "*") {
			continue
		}

		// Get interface type
		typeCmd := exec.Command("networksetup", "-getnetworkserviceenabled", service)
		typeOutput, _ := typeCmd.Output()
		isActive := strings.TrimSpace(string(typeOutput)) != "Disabled"

		// Get current DNS
		dnsCmd := exec.Command("networksetup", "-getdnsservers", service)
		dnsOutput, _ := dnsCmd.Output()
		dnsStr := strings.TrimSpace(string(dnsOutput))

		var dnsServers []string
		isDHCP := false

		if strings.Contains(dnsStr, "There aren't any DNS Servers") {
			isDHCP = true
		} else {
			dnsServers = strings.Split(dnsStr, "\n")
		}

		config.Interfaces[service] = InterfaceConfig{
			Name:       service,
			Type:       detectInterfaceType(service),
			DNSServers: dnsServers,
			IsDHCP:     isDHCP,
			IsActive:   isActive,
		}
	}

	return config, nil
}

func (m *Manager) saveDNSConfig(config *DNSConfiguration) error {
	// Ensure directory exists
	dir := filepath.Dir(m.configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Save as JSON
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(m.configPath, data, 0600)
}

func (m *Manager) loadDNSConfig() (*DNSConfiguration, error) {
	data, err := os.ReadFile(m.configPath)
	if err != nil {
		return nil, err
	}

	var config DNSConfiguration
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

func (m *Manager) restoreDNSConfig(config *DNSConfiguration) error {
	for _, iface := range config.Interfaces {
		if !iface.IsActive {
			continue
		}

		var cmd *exec.Cmd
		if iface.IsDHCP {
			cmd = exec.Command("networksetup", "-setdnsservers", iface.Name, "Empty")
		} else if len(iface.DNSServers) > 0 {
			args := append([]string{"-setdnsservers", iface.Name}, iface.DNSServers...)
			cmd = exec.Command("networksetup", args...)
		} else {
			continue
		}

		if output, err := cmd.CombinedOutput(); err != nil {
			logrus.WithError(err).WithField("output", string(output)).
				Errorf("Failed to restore DNS for interface %s", iface.Name)
			continue
		}

		logrus.WithField("interface", iface.Name).Info("Restored original DNS")
	}

	return nil
}

func detectInterfaceType(name string) string {
	switch {
	case strings.Contains(strings.ToLower(name), "wi-fi"):
		return "wifi"
	case strings.Contains(strings.ToLower(name), "ethernet"):
		return "ethernet"
	case strings.Contains(strings.ToLower(name), "thunderbolt"):
		return "thunderbolt"
	case strings.Contains(strings.ToLower(name), "bluetooth"):
		return "bluetooth"
	default:
		return "other"
	}
}

func getHostname() string {
	hostname, _ := os.Hostname()
	return hostname
}

// Start does nothing for simple manager
func (m *Manager) Start() error {
	return nil
}

// Stop does nothing for simple manager
func (m *Manager) Stop() {
}

// GetCurrentNetwork returns nil for simple manager
func (m *Manager) GetCurrentNetwork() *NetworkIdentity {
	return nil
}

// GetNetworkDNS returns nil for simple manager
func (m *Manager) GetNetworkDNS() *NetworkDNSConfig {
	return nil
}
