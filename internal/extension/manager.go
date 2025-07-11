// Package extension provides Network Extension management for macOS DNS filtering
package extension

import (
	"fmt"
	"sync"
	"time"

	"dnshield/internal/audit"
	"dnshield/internal/dns"

	"github.com/sirupsen/logrus"
)

// Manager handles the Network Extension lifecycle and domain updates
type Manager struct {
	bundleID       string
	isRunning      bool
	isInstalled    bool
	blockedDomains []string
	domainTrie     *DomainTrie
	blocker        *dns.Blocker
	mu             sync.RWMutex
}

// NewManager creates a new Network Extension manager
func NewManager(bundleID string, blocker *dns.Blocker) *Manager {
	return &Manager{
		bundleID:   bundleID,
		domainTrie: NewDomainTrie(),
		blocker:    blocker,
	}
}

// Install installs the system extension
func (m *Manager) Install() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check actual system state
	if isExtensionInstalled(m.bundleID) {
		m.isInstalled = true
		return fmt.Errorf("extension is already installed")
	}

	logrus.Info("Installing Network Extension...")
	
	// Call CGO bridge to install
	if err := installSystemExtension(m.bundleID); err != nil {
		return fmt.Errorf("failed to install system extension: %v", err)
	}

	m.isInstalled = true
	
	// Audit log
	audit.Log(audit.EventConfigChange, "info", "Network Extension installed", map[string]interface{}{
		"bundle_id": m.bundleID,
	})

	logrus.Info("Network Extension installed successfully")
	logrus.Info("Note: User approval may be required in System Preferences > Privacy & Security")
	
	return nil
}

// Uninstall removes the system extension
func (m *Manager) Uninstall() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check actual system state
	if !isExtensionInstalled(m.bundleID) {
		m.isInstalled = false
		return fmt.Errorf("extension is not installed")
	}

	if m.isRunning {
		// Stop it first
		if err := m.stop(); err != nil {
			return fmt.Errorf("failed to stop extension before uninstall: %v", err)
		}
	}

	logrus.Info("Uninstalling Network Extension...")

	// Call CGO bridge to uninstall
	if err := uninstallSystemExtension(m.bundleID); err != nil {
		return fmt.Errorf("failed to uninstall system extension: %v", err)
	}

	m.isInstalled = false

	// Audit log
	audit.Log(audit.EventConfigChange, "info", "Network Extension uninstalled", map[string]interface{}{
		"bundle_id": m.bundleID,
	})

	logrus.Info("Network Extension uninstalled successfully")
	
	return nil
}

// Start starts the DNS proxy with current blocked domains
func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.isRunning {
		return fmt.Errorf("extension is already running")
	}

	// Sync installed state with system
	m.isInstalled = isExtensionInstalled(m.bundleID)
	if !m.isInstalled {
		return fmt.Errorf("extension is not installed, run: sudo dnshield extension install")
	}

	// Get domains from blocker
	domains := m.blocker.GetBlockedDomains()
	if len(domains) == 0 {
		logrus.Warn("No domains to block, starting with empty list")
	}

	logrus.WithField("domain_count", len(domains)).Info("Starting Network Extension DNS proxy...")

	// Load domains into trie
	m.domainTrie.LoadDomains(domains)
	m.blockedDomains = domains

	// Call CGO bridge to start DNS proxy
	if err := startDNSProxy(m.bundleID, domains); err != nil {
		return fmt.Errorf("failed to start DNS proxy: %v", err)
	}

	m.isRunning = true

	// Audit log
	audit.Log(audit.EventServiceStart, "info", "Network Extension DNS proxy started", map[string]interface{}{
		"bundle_id":     m.bundleID,
		"domain_count":  len(domains),
	})

	logrus.WithField("domains", len(domains)).Info("Network Extension DNS proxy started successfully")
	
	return nil
}

// Stop stops the DNS proxy
func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.stop()
}

// stop is the internal stop method (must be called with lock held)
func (m *Manager) stop() error {
	if !m.isRunning {
		return fmt.Errorf("extension is not running")
	}

	logrus.Info("Stopping Network Extension DNS proxy...")

	// Call CGO bridge to stop
	if err := stopDNSProxy(); err != nil {
		return fmt.Errorf("failed to stop DNS proxy: %v", err)
	}

	m.isRunning = false

	// Audit log
	audit.Log(audit.EventServiceStop, "info", "Network Extension DNS proxy stopped", map[string]interface{}{
		"bundle_id": m.bundleID,
	})

	logrus.Info("Network Extension DNS proxy stopped")
	
	return nil
}

// UpdateDomains updates the blocked domains list without restarting
func (m *Manager) UpdateDomains() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.isRunning {
		return fmt.Errorf("extension is not running")
	}

	// Get updated domains from blocker
	newDomains := m.blocker.GetBlockedDomains()
	
	// Check if update is needed
	if len(newDomains) == len(m.blockedDomains) {
		// Quick check - might still have different domains
		same := true
		oldMap := make(map[string]bool)
		for _, d := range m.blockedDomains {
			oldMap[d] = true
		}
		for _, d := range newDomains {
			if !oldMap[d] {
				same = false
				break
			}
		}
		if same {
			logrus.Debug("No domain changes detected, skipping update")
			return nil
		}
	}

	logrus.WithFields(logrus.Fields{
		"old_count": len(m.blockedDomains),
		"new_count": len(newDomains),
	}).Info("Updating Network Extension blocked domains...")

	// Update trie
	m.domainTrie.LoadDomains(newDomains)
	
	// Call CGO bridge to update domains
	if err := updateDNSProxyDomains(newDomains); err != nil {
		return fmt.Errorf("failed to update DNS proxy domains: %v", err)
	}

	oldCount := len(m.blockedDomains)
	m.blockedDomains = newDomains

	// Audit log
	audit.Log(audit.EventConfigChange, "info", "Network Extension domains updated", map[string]interface{}{
		"old_count": oldCount,
		"new_count": len(newDomains),
	})

	logrus.WithField("domains", len(newDomains)).Info("Network Extension domains updated successfully")
	
	return nil
}

// IsRunning returns whether the extension is running
func (m *Manager) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.isRunning
}

// IsInstalled returns whether the extension is installed
func (m *Manager) IsInstalled() bool {
	// Check actual system state, not just internal state
	return isExtensionInstalled(m.bundleID)
}

// GetStatus returns the current status of the extension
func (m *Manager) GetStatus() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Check actual system state
	actuallyInstalled := isExtensionInstalled(m.bundleID)

	return map[string]interface{}{
		"bundle_id":      m.bundleID,
		"installed":      actuallyInstalled,
		"running":        m.isRunning,
		"domain_count":   len(m.blockedDomains),
		"trie_size":      m.domainTrie.Size(),
	}
}

// IsBlocked checks if a domain is blocked (for testing)
func (m *Manager) IsBlocked(domain string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.domainTrie.IsBlocked(domain)
}

// StartPeriodicUpdates starts a goroutine that periodically updates domains
func (m *Manager) StartPeriodicUpdates(interval time.Duration) chan struct{} {
	stop := make(chan struct{})
	
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := m.UpdateDomains(); err != nil {
					logrus.WithError(err).Error("Failed to update Network Extension domains")
				}
			case <-stop:
				return
			}
		}
	}()

	return stop
}