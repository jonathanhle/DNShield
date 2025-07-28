package dns

import (
	"crypto/sha256"
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

// NetworkManager handles DNS configuration with network awareness
type NetworkManager struct {
	mu                sync.RWMutex
	configDir         string
	currentNetwork    *NetworkIdentity
	networkConfigs    map[string]*NetworkDNSConfig
	isActive          bool
	isPaused          bool
	pauseTimer        *time.Timer
	changeDetector    *NetworkChangeDetector
	captureInProgress bool
}

// Ensure NetworkManager implements DNSManager interface
var _ DNSManager = (*NetworkManager)(nil)

// NetworkIdentity uniquely identifies a network
type NetworkIdentity struct {
	ID              string    `json:"id"`               // Unique hash
	SSID            string    `json:"ssid,omitempty"`   // WiFi network name
	Interface       string    `json:"interface"`        // en0, en1, etc.
	InterfaceType   string    `json:"interface_type"`   // wifi, ethernet, etc.
	GatewayIP       string    `json:"gateway_ip"`       // Router IP
	GatewayMAC      string    `json:"gateway_mac"`      // Router MAC (more stable)
	Subnet          string    `json:"subnet"`           // 192.168.1.0/24
	LastSeen        time.Time `json:"last_seen"`
	IsVPN           bool      `json:"is_vpn"`
	VPNInterface    string    `json:"vpn_interface,omitempty"`
}

// NetworkDNSConfig stores DNS settings for a specific network
type NetworkDNSConfig struct {
	NetworkID       string           `json:"network_id"`
	NetworkIdentity NetworkIdentity  `json:"network_identity"`
	DNSServers      []string         `json:"dns_servers"`
	IsDHCP          bool             `json:"is_dhcp"`
	CapturedAt      time.Time        `json:"captured_at"`
	LastUpdated     time.Time        `json:"last_updated"`
	TimesConnected  int              `json:"times_connected"`
	Notes           string           `json:"notes,omitempty"`
}

// NetworkChangeDetector monitors for network changes
type NetworkChangeDetector struct {
	manager  *NetworkManager
	stopChan chan bool
	running  bool
}

// NewNetworkManager creates a network-aware DNS manager
func NewNetworkManager() *NetworkManager {
	homeDir, _ := os.UserHomeDir()
	configDir := filepath.Join(homeDir, ".dnshield", "network-dns")
	
	nm := &NetworkManager{
		configDir:      configDir,
		networkConfigs: make(map[string]*NetworkDNSConfig),
	}
	
	// Ensure config directory exists
	os.MkdirAll(configDir, 0755)
	
	// Load existing configs
	nm.loadAllConfigs()
	
	// Create network change detector
	nm.changeDetector = &NetworkChangeDetector{
		manager:  nm,
		stopChan: make(chan bool),
	}
	
	return nm
}

// Start begins monitoring network changes
func (nm *NetworkManager) Start() error {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	
	// Detect current network
	if err := nm.detectCurrentNetwork(); err != nil {
		logrus.WithError(err).Warn("Failed to detect current network")
	}
	
	// Start change detection
	go nm.changeDetector.Start()
	
	return nil
}

// Stop stops monitoring network changes
func (nm *NetworkManager) Stop() {
	nm.changeDetector.Stop()
}

// EnableDNSFiltering activates DNS filtering for current network
func (nm *NetworkManager) EnableDNSFiltering() error {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	
	// Capture current network's DNS if not already done
	if nm.currentNetwork != nil {
		if _, exists := nm.networkConfigs[nm.currentNetwork.ID]; !exists {
			nm.captureCurrentDNS()
		}
	}
	
	// Set DNS to 127.0.0.1
	if err := nm.setSystemDNS("127.0.0.1"); err != nil {
		return err
	}
	
	nm.isActive = true
	nm.isPaused = false
	
	logrus.WithField("network", nm.currentNetwork.SSID).Info("DNS filtering enabled")
	return nil
}

// DisableDNSFiltering restores original DNS for current network
func (nm *NetworkManager) DisableDNSFiltering() error {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	
	if nm.currentNetwork == nil {
		return fmt.Errorf("no current network detected")
	}
	
	config, exists := nm.networkConfigs[nm.currentNetwork.ID]
	if !exists {
		return fmt.Errorf("no DNS configuration for current network")
	}
	
	if err := nm.restoreNetworkDNS(config); err != nil {
		return err
	}
	
	nm.isActive = false
	logrus.WithField("network", nm.currentNetwork.SSID).Info("DNS filtering disabled")
	return nil
}

// PauseDNSFiltering temporarily restores original DNS
func (nm *NetworkManager) PauseDNSFiltering(duration time.Duration) error {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	
	if nm.isPaused {
		return fmt.Errorf("already paused")
	}
	
	if nm.currentNetwork == nil {
		return fmt.Errorf("no current network detected")
	}
	
	config, exists := nm.networkConfigs[nm.currentNetwork.ID]
	if !exists {
		// Try to capture current DNS first
		if err := nm.captureCurrentDNS(); err != nil {
			return fmt.Errorf("no DNS configuration available: %w", err)
		}
		config = nm.networkConfigs[nm.currentNetwork.ID]
	}
	
	// Restore original DNS
	if err := nm.restoreNetworkDNS(config); err != nil {
		return err
	}
	
	nm.isPaused = true
	
	// Set timer to resume
	if nm.pauseTimer != nil {
		nm.pauseTimer.Stop()
	}
	
	nm.pauseTimer = time.AfterFunc(duration, func() {
		nm.mu.Lock()
		defer nm.mu.Unlock()
		
		if nm.isPaused {
			nm.setSystemDNS("127.0.0.1")
			nm.isPaused = false
			logrus.Info("DNS filtering auto-resumed")
		}
	})
	
	logrus.WithFields(logrus.Fields{
		"duration": duration,
		"network":  nm.currentNetwork.SSID,
	}).Info("DNS filtering paused")
	
	return nil
}

// ResumeDNSFiltering resumes filtering before pause timeout
func (nm *NetworkManager) ResumeDNSFiltering() error {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	
	if !nm.isPaused {
		return fmt.Errorf("not paused")
	}
	
	if nm.pauseTimer != nil {
		nm.pauseTimer.Stop()
		nm.pauseTimer = nil
	}
	
	if err := nm.setSystemDNS("127.0.0.1"); err != nil {
		return err
	}
	
	nm.isPaused = false
	logrus.Info("DNS filtering resumed")
	return nil
}

// OnNetworkChange handles network change events
func (nm *NetworkManager) OnNetworkChange() {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	
	logrus.Info("Network change detected")
	
	// Detect new network
	oldNetwork := nm.currentNetwork
	if err := nm.detectCurrentNetwork(); err != nil {
		logrus.WithError(err).Error("Failed to detect new network")
		return
	}
	
	// If network changed
	if oldNetwork == nil || (nm.currentNetwork != nil && oldNetwork.ID != nm.currentNetwork.ID) {
		logrus.WithFields(logrus.Fields{
			"old_network": getNetworkName(oldNetwork),
			"new_network": getNetworkName(nm.currentNetwork),
		}).Info("Network switch detected")
		
		// If we're active, capture DNS of new network if needed
		if nm.isActive && !nm.isPaused {
			if _, exists := nm.networkConfigs[nm.currentNetwork.ID]; !exists {
				// Briefly restore DNS to capture original
				nm.captureCurrentDNS()
				// Re-enable filtering
				nm.setSystemDNS("127.0.0.1")
			}
		}
		
		// If paused, restore DNS for new network
		if nm.isPaused {
			if config, exists := nm.networkConfigs[nm.currentNetwork.ID]; exists {
				nm.restoreNetworkDNS(config)
			} else {
				// No config for this network, disable pause
				nm.isPaused = false
				if nm.pauseTimer != nil {
					nm.pauseTimer.Stop()
					nm.pauseTimer = nil
				}
				logrus.Warn("No DNS config for new network, resuming protection")
			}
		}
	}
}

// Private methods

func (nm *NetworkManager) detectCurrentNetwork() error {
	identity, err := getCurrentNetworkIdentity()
	if err != nil {
		return err
	}
	
	nm.currentNetwork = identity
	
	// Update last seen
	if config, exists := nm.networkConfigs[identity.ID]; exists {
		config.LastUpdated = time.Now()
		config.TimesConnected++
		nm.saveNetworkConfig(config)
	}
	
	return nil
}

func (nm *NetworkManager) captureCurrentDNS() error {
	if nm.currentNetwork == nil {
		return fmt.Errorf("no current network")
	}
	
	// Don't capture if we're already filtering
	currentDNS, err := getCurrentSystemDNS(nm.currentNetwork.Interface)
	if err != nil {
		return err
	}
	
	// Skip if DNS is already set to DNShield
	for _, dns := range currentDNS {
		if dns == "127.0.0.1" {
			logrus.Debug("Skipping DNS capture - already set to 127.0.0.1")
			return nil
		}
	}
	
	config := &NetworkDNSConfig{
		NetworkID:       nm.currentNetwork.ID,
		NetworkIdentity: *nm.currentNetwork,
		DNSServers:      currentDNS,
		IsDHCP:          len(currentDNS) == 0,
		CapturedAt:      time.Now(),
		LastUpdated:     time.Now(),
		TimesConnected:  1,
	}
	
	nm.networkConfigs[config.NetworkID] = config
	nm.saveNetworkConfig(config)
	
	logrus.WithFields(logrus.Fields{
		"network": nm.currentNetwork.SSID,
		"dns":     currentDNS,
	}).Info("Captured network DNS configuration")
	
	return nil
}

func (nm *NetworkManager) setSystemDNS(dns string) error {
	if nm.currentNetwork == nil {
		return fmt.Errorf("no current network")
	}
	
	cmd := exec.Command("networksetup", "-setdnsservers", nm.currentNetwork.Interface, dns)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set DNS: %s", output)
	}
	
	return nil
}

func (nm *NetworkManager) restoreNetworkDNS(config *NetworkDNSConfig) error {
	var cmd *exec.Cmd
	
	if config.IsDHCP || len(config.DNSServers) == 0 {
		cmd = exec.Command("networksetup", "-setdnsservers", config.NetworkIdentity.Interface, "Empty")
	} else {
		args := append([]string{"-setdnsservers", config.NetworkIdentity.Interface}, config.DNSServers...)
		cmd = exec.Command("networksetup", args...)
	}
	
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to restore DNS: %s", output)
	}
	
	logrus.WithFields(logrus.Fields{
		"network": config.NetworkIdentity.SSID,
		"dns":     config.DNSServers,
	}).Info("Restored network DNS")
	
	return nil
}

func (nm *NetworkManager) loadAllConfigs() {
	files, err := filepath.Glob(filepath.Join(nm.configDir, "network-*.json"))
	if err != nil {
		return
	}
	
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		
		var config NetworkDNSConfig
		if err := json.Unmarshal(data, &config); err != nil {
			continue
		}
		
		nm.networkConfigs[config.NetworkID] = &config
	}
	
	logrus.WithField("count", len(nm.networkConfigs)).Info("Loaded network DNS configurations")
}

func (nm *NetworkManager) saveNetworkConfig(config *NetworkDNSConfig) {
	filename := filepath.Join(nm.configDir, fmt.Sprintf("network-%s.json", config.NetworkID))
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return
	}
	
	os.WriteFile(filename, data, 0600)
}

// Network detection helpers

func getCurrentNetworkIdentity() (*NetworkIdentity, error) {
	// Get active interface
	cmd := exec.Command("route", "-n", "get", "default")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get default route: %w", err)
	}
	
	lines := strings.Split(string(output), "\n")
	var interfaceName, gateway string
	
	for _, line := range lines {
		if strings.Contains(line, "interface:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				interfaceName = parts[1]
			}
		}
		if strings.Contains(line, "gateway:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				gateway = parts[1]
			}
		}
	}
	
	if interfaceName == "" {
		return nil, fmt.Errorf("no active interface found")
	}
	
	identity := &NetworkIdentity{
		Interface:     interfaceName,
		InterfaceType: detectInterfaceType(interfaceName),
		GatewayIP:     gateway,
		LastSeen:      time.Now(),
	}
	
	// Get SSID for WiFi
	if identity.InterfaceType == "wifi" {
		if ssid, err := getWiFiSSID(); err == nil {
			identity.SSID = ssid
		}
	}
	
	// Get gateway MAC
	if gateway != "" {
		if mac, err := getGatewayMAC(gateway); err == nil {
			identity.GatewayMAC = mac
		}
	}
	
	// Check for VPN
	identity.IsVPN, identity.VPNInterface = detectVPN()
	
	// Generate unique ID
	identity.ID = generateNetworkID(identity)
	
	return identity, nil
}

func getWiFiSSID() (string, error) {
	cmd := exec.Command("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-I")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, " SSID:") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				return strings.TrimSpace(parts[1]), nil
			}
		}
	}
	
	return "", fmt.Errorf("no SSID found")
}

func getGatewayMAC(ip string) (string, error) {
	cmd := exec.Command("arp", "-n", ip)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, ip) {
			fields := strings.Fields(line)
			for _, field := range fields {
				if strings.Count(field, ":") == 5 {
					return field, nil
				}
			}
		}
	}
	
	return "", fmt.Errorf("MAC not found")
}

func getCurrentSystemDNS(interfaceName string) ([]string, error) {
	cmd := exec.Command("networksetup", "-getdnsservers", interfaceName)
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	
	outputStr := strings.TrimSpace(string(output))
	if strings.Contains(outputStr, "There aren't any DNS Servers") {
		return []string{}, nil // DHCP
	}
	
	return strings.Split(outputStr, "\n"), nil
}

func detectVPN() (bool, string) {
	cmd := exec.Command("ifconfig")
	output, _ := cmd.Output()
	
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "utun") || strings.HasPrefix(line, "ppp") {
			parts := strings.Split(line, ":")
			if len(parts) > 0 {
				return true, strings.TrimSpace(parts[0])
			}
		}
	}
	
	return false, ""
}

func generateNetworkID(identity *NetworkIdentity) string {
	// Create stable ID based on network characteristics
	data := fmt.Sprintf("%s|%s|%s|%s",
		identity.SSID,
		identity.GatewayMAC,
		identity.GatewayIP,
		identity.Interface,
	)
	
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash)[:16]
}

func getNetworkName(identity *NetworkIdentity) string {
	if identity == nil {
		return "unknown"
	}
	if identity.SSID != "" {
		return identity.SSID
	}
	return identity.Interface
}

// NetworkChangeDetector implementation

func (ncd *NetworkChangeDetector) Start() {
	if ncd.running {
		return
	}
	
	ncd.running = true
	logrus.Info("Starting network change detection")
	
	// Poll for changes every 5 seconds
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	
	lastNetworkID := ""
	if ncd.manager.currentNetwork != nil {
		lastNetworkID = ncd.manager.currentNetwork.ID
	}
	
	for {
		select {
		case <-ncd.stopChan:
			ncd.running = false
			return
			
		case <-ticker.C:
			// Check if network changed
			identity, err := getCurrentNetworkIdentity()
			if err != nil {
				continue
			}
			
			if identity.ID != lastNetworkID {
				lastNetworkID = identity.ID
				ncd.manager.OnNetworkChange()
			}
		}
	}
}

func (ncd *NetworkChangeDetector) Stop() {
	if ncd.running {
		ncd.stopChan <- true
	}
}

// IsPaused returns current pause state
func (nm *NetworkManager) IsPaused() bool {
	nm.mu.RLock()
	defer nm.mu.RUnlock()
	return nm.isPaused
}

// GetCurrentNetwork returns info about current network
func (nm *NetworkManager) GetCurrentNetwork() *NetworkIdentity {
	nm.mu.RLock()
	defer nm.mu.RUnlock()
	return nm.currentNetwork
}

// GetNetworkDNS returns DNS config for current network
func (nm *NetworkManager) GetNetworkDNS() *NetworkDNSConfig {
	nm.mu.RLock()
	defer nm.mu.RUnlock()
	
	if nm.currentNetwork == nil {
		return nil
	}
	
	return nm.networkConfigs[nm.currentNetwork.ID]
}