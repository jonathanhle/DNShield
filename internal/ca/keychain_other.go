// +build !darwin

package ca

import "fmt"

// LoadOrCreateKeychainCA is not supported on non-Darwin platforms
func LoadOrCreateKeychainCA() (Manager, error) {
	return nil, fmt.Errorf("Keychain storage is only supported on macOS")
}

// UninstallKeychainCA is not supported on non-Darwin platforms
func UninstallKeychainCA() error {
	return fmt.Errorf("Keychain storage is only supported on macOS")
}

// SetKeychainACL is not supported on non-Darwin platforms
func SetKeychainACL(binaryPath string) error {
	return fmt.Errorf("Keychain ACL is only supported on macOS")
}