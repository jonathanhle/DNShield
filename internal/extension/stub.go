//go:build !extension

package extension

import "fmt"

// Stub implementations when extension support is not compiled

func installSystemExtension(bundleID string) error {
	return fmt.Errorf("Network Extension support is not compiled into this binary.\n\nTo use Network Extension mode:\n1. Rebuild with extension support: make build-with-extension\n2. Ensure you have macOS 10.15+ and admin privileges\n3. Have an Apple Developer ID for code signing (production)")
}

func uninstallSystemExtension(bundleID string) error {
	return fmt.Errorf("Network Extension support is not compiled into this binary.\n\nRebuild with: make build-with-extension")
}

func startDNSProxy(bundleID string, domains []string) error {
	return fmt.Errorf("Cannot start DNS proxy - Network Extension support not compiled.\n\nRebuild with: make build-with-extension")
}

func stopDNSProxy() error {
	return fmt.Errorf("Cannot stop DNS proxy - Network Extension support not compiled.\n\nRebuild with: make build-with-extension")
}

func updateDNSProxyDomains(domains []string) error {
	return fmt.Errorf("Cannot update domains - Network Extension support not compiled.\n\nRebuild with: make build-with-extension")
}

func isExtensionInstalled(bundleID string) bool {
	return false
}