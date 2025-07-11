//go:build darwin && extension

package extension

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework Foundation -framework NetworkExtension -framework SystemExtensions

#include <stdlib.h>

// Forward declarations of C bridge functions
int installSystemExtensionBridge(const char* bundleID);
int uninstallSystemExtensionBridge(const char* bundleID);
int startDNSProxyBridge(const char* bundleID, char** domains, int domainCount);
int stopDNSProxyBridge(void);
int updateDNSProxyDomainsBridge(char** domains, int domainCount);
int isExtensionInstalledBridge(const char* bundleID);

// Include the implementation
#include "objc/bridge_darwin.m"
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// installSystemExtension installs the system extension
func installSystemExtension(bundleID string) error {
	cBundleID := C.CString(bundleID)
	defer C.free(unsafe.Pointer(cBundleID))

	result := C.installSystemExtensionBridge(cBundleID)
	if result != 0 {
		switch result {
		case -2:
			return fmt.Errorf("installation timed out. The system may be prompting for approval.\n\nCheck System Preferences > Privacy & Security")
		case 1:
			return fmt.Errorf("extension bundle not found.\n\nMake sure to:\n1. Build the app bundle: ./build-app-bundle.sh\n2. Run from the app bundle: DNShield.app/Contents/MacOS/dnshield")
		case 4:
			return fmt.Errorf("authorization required.\n\nApprove the extension in:\nSystem Preferences > Privacy & Security")
		case 8:
			return fmt.Errorf("invalid signature.\n\nThe extension needs to be signed with a valid Developer ID")
		default:
			return fmt.Errorf("installation failed (code: %d).\n\nCheck Console.app for detailed error messages", result)
		}
	}
	return nil
}

// uninstallSystemExtension removes the system extension
func uninstallSystemExtension(bundleID string) error {
	cBundleID := C.CString(bundleID)
	defer C.free(unsafe.Pointer(cBundleID))

	result := C.uninstallSystemExtensionBridge(cBundleID)
	if result != 0 {
		switch result {
		case -2:
			return fmt.Errorf("uninstallation timed out")
		default:
			return fmt.Errorf("uninstallation failed (code: %d).\n\nTry manually removing in System Preferences > Privacy & Security", result)
		}
	}
	return nil
}

// startDNSProxy starts the DNS proxy with blocked domains
func startDNSProxy(bundleID string, domains []string) error {
	cBundleID := C.CString(bundleID)
	defer C.free(unsafe.Pointer(cBundleID))

	// Convert Go string slice to C string array
	var cDomains **C.char
	if len(domains) > 0 {
		cDomains = (**C.char)(C.malloc(C.size_t(len(domains)) * C.size_t(unsafe.Sizeof(uintptr(0)))))
		defer C.free(unsafe.Pointer(cDomains))

		// Create a slice from the C array
		cDomainsSlice := (*[1 << 30]*C.char)(unsafe.Pointer(cDomains))[:len(domains):len(domains)]
		
		// Convert each domain
		for i, domain := range domains {
			cDomainsSlice[i] = C.CString(domain)
		}
		
		// Clean up strings after the call
		defer func() {
			for i := range domains {
				C.free(unsafe.Pointer(cDomainsSlice[i]))
			}
		}()
	}

	result := C.startDNSProxyBridge(cBundleID, cDomains, C.int(len(domains)))
	if result != 0 {
		return fmt.Errorf("failed to start DNS proxy (code: %d).\n\nEnsure:\n- Extension is installed and approved\n- No other DNS proxy is running\n- You have admin privileges", result)
	}
	return nil
}

// stopDNSProxy stops the DNS proxy
func stopDNSProxy() error {
	result := C.stopDNSProxyBridge()
	if result != 0 {
		return fmt.Errorf("failed to stop DNS proxy with code: %d", result)
	}
	return nil
}

// updateDNSProxyDomains updates the blocked domains without restart
func updateDNSProxyDomains(domains []string) error {
	// Convert Go string slice to C string array
	var cDomains **C.char
	if len(domains) > 0 {
		cDomains = (**C.char)(C.malloc(C.size_t(len(domains)) * C.size_t(unsafe.Sizeof(uintptr(0)))))
		defer C.free(unsafe.Pointer(cDomains))

		// Create a slice from the C array
		cDomainsSlice := (*[1 << 30]*C.char)(unsafe.Pointer(cDomains))[:len(domains):len(domains)]
		
		// Convert each domain
		for i, domain := range domains {
			cDomainsSlice[i] = C.CString(domain)
		}
		
		// Clean up strings after the call
		defer func() {
			for i := range domains {
				C.free(unsafe.Pointer(cDomainsSlice[i]))
			}
		}()
	}

	result := C.updateDNSProxyDomainsBridge(cDomains, C.int(len(domains)))
	if result != 0 {
		return fmt.Errorf("failed to update domains with code: %d", result)
	}
	return nil
}

// isExtensionInstalled checks if the extension is installed
func isExtensionInstalled(bundleID string) bool {
	cBundleID := C.CString(bundleID)
	defer C.free(unsafe.Pointer(cBundleID))

	result := C.isExtensionInstalledBridge(cBundleID)
	return result == 1
}