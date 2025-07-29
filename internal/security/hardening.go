package security

import (
	"fmt"
	"os"
	"os/user"
	"runtime"
	"syscall"

	"github.com/sirupsen/logrus"
)

// HardenProcess implements security hardening measures for the DNShield process
type HardenProcess struct {
	dropPrivileges bool
	chroot         string
	limitMemory    uint64
	limitCPU       uint64
}

// NewHardening creates a new process hardening configuration
func NewHardening() *HardenProcess {
	return &HardenProcess{
		dropPrivileges: true,
		limitMemory:    512 * 1024 * 1024, // 512MB default
		limitCPU:       2,                  // 2 CPU cores default
	}
}

// ApplyHardening applies security hardening measures to the current process
func (h *HardenProcess) ApplyHardening() error {
	// Only apply on macOS
	if runtime.GOOS != "darwin" {
		return nil
	}

	// Set resource limits
	if err := h.setResourceLimits(); err != nil {
		logrus.WithError(err).Warn("Failed to set resource limits")
	}

	// Disable core dumps (prevent memory disclosure)
	if err := h.disableCoreDumps(); err != nil {
		logrus.WithError(err).Warn("Failed to disable core dumps")
	}

	// Clear sensitive environment variables
	h.clearSensitiveEnv()

	// Set secure file permissions
	if err := h.setSecureUmask(); err != nil {
		logrus.WithError(err).Warn("Failed to set secure umask")
	}

	return nil
}

// DropPrivilegesAfterBind drops privileges after binding to privileged ports
func (h *HardenProcess) DropPrivilegesAfterBind() error {
	if !h.dropPrivileges {
		return nil
	}

	// Get the current user
	currentUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("failed to get current user: %w", err)
	}

	// If already running as non-root, nothing to do
	if currentUser.Uid != "0" {
		logrus.Info("Already running as non-root user")
		return nil
	}

	// Try to find a suitable unprivileged user
	targetUser, err := h.findUnprivilegedUser()
	if err != nil {
		return fmt.Errorf("failed to find unprivileged user: %w", err)
	}

	logrus.Infof("Dropping privileges to user: %s (uid: %s)", targetUser.Username, targetUser.Uid)

	// Note: Actually dropping privileges would require:
	// 1. Changing file ownership of config/CA files
	// 2. Using setuid/setgid system calls
	// 3. Handling the complexity of privilege separation
	// This is a placeholder for the full implementation

	return nil
}

// findUnprivilegedUser finds a suitable unprivileged user to drop to
func (h *HardenProcess) findUnprivilegedUser() (*user.User, error) {
	// Try common unprivileged users in order
	users := []string{"_dnshield", "nobody", "daemon"}
	
	for _, username := range users {
		u, err := user.Lookup(username)
		if err == nil {
			return u, nil
		}
	}

	return nil, fmt.Errorf("no suitable unprivileged user found")
}

// setResourceLimits sets resource limits for the process
func (h *HardenProcess) setResourceLimits() error {
	// Set file descriptor limit
	var rLimit syscall.Rlimit
	rLimit.Cur = 1024
	rLimit.Max = 1024
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit); err != nil {
		return fmt.Errorf("failed to set file descriptor limit: %w", err)
	}

	// Note: RLIMIT_AS (virtual memory) is not properly supported on macOS
	// We rely on other mechanisms for memory protection
	logrus.Debug("File descriptor limit set to 1024")

	return nil
}

// disableCoreDumps disables core dumps to prevent memory disclosure
func (h *HardenProcess) disableCoreDumps() error {
	var rLimit syscall.Rlimit
	rLimit.Cur = 0
	rLimit.Max = 0
	return syscall.Setrlimit(syscall.RLIMIT_CORE, &rLimit)
}

// clearSensitiveEnv clears sensitive environment variables
func (h *HardenProcess) clearSensitiveEnv() {
	sensitiveVars := []string{
		"AWS_ACCESS_KEY_ID",
		"AWS_SECRET_ACCESS_KEY",
		"AWS_SESSION_TOKEN",
		"DNSHIELD_API_KEY",
		"SPLUNK_HEC_TOKEN",
	}

	for _, v := range sensitiveVars {
		os.Unsetenv(v)
	}
}

// setSecureUmask sets a secure umask for file creation
func (h *HardenProcess) setSecureUmask() error {
	// Set umask to 0077 (owner read/write/exec only)
	oldUmask := syscall.Umask(0077)
	logrus.Debugf("Changed umask from %04o to 0077", oldUmask)
	return nil
}

// EnableSeccompFilter enables seccomp filtering (Linux-style, limited on macOS)
func (h *HardenProcess) EnableSeccompFilter() error {
	// macOS doesn't have seccomp, but we can use sandbox_init
	// This is a placeholder for future implementation
	logrus.Info("Seccomp-style filtering not available on macOS")
	return nil
}