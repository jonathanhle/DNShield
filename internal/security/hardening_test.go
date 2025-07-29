package security

import (
	"os"
	"runtime"
	"syscall"
	"testing"
)

func TestNewHardening(t *testing.T) {
	h := NewHardening()
	if h == nil {
		t.Fatal("Expected non-nil HardenProcess")
	}
	if !h.dropPrivileges {
		t.Error("Expected dropPrivileges to be true by default")
	}
	if h.limitMemory != 512*1024*1024 {
		t.Errorf("Expected default memory limit of 512MB, got %d", h.limitMemory)
	}
}

func TestClearSensitiveEnv(t *testing.T) {
	// Skip on non-Darwin platforms
	if runtime.GOOS != "darwin" {
		t.Skip("Skipping macOS-specific test")
	}

	// Set some sensitive environment variables
	testVars := map[string]string{
		"AWS_ACCESS_KEY_ID":     "test-key",
		"AWS_SECRET_ACCESS_KEY": "test-secret",
		"DNSHIELD_API_KEY":      "test-api-key",
	}

	for k, v := range testVars {
		os.Setenv(k, v)
	}

	// Apply hardening
	h := NewHardening()
	h.clearSensitiveEnv()

	// Verify they were cleared
	for k := range testVars {
		if val := os.Getenv(k); val != "" {
			t.Errorf("Expected %s to be cleared, but got: %s", k, val)
		}
	}
}

func TestSetSecureUmask(t *testing.T) {
	// Skip on non-Darwin platforms
	if runtime.GOOS != "darwin" {
		t.Skip("Skipping macOS-specific test")
	}

	h := NewHardening()
	
	// Save current umask
	oldUmask := syscall.Umask(0)
	syscall.Umask(oldUmask)

	// Set secure umask
	err := h.setSecureUmask()
	if err != nil {
		t.Fatalf("Failed to set secure umask: %v", err)
	}

	// Check new umask
	newUmask := syscall.Umask(0)
	syscall.Umask(newUmask)

	if newUmask != 0077 {
		t.Errorf("Expected umask 0077, got %04o", newUmask)
	}

	// Restore original umask
	syscall.Umask(oldUmask)
}

func TestDisableCoreDumps(t *testing.T) {
	// Skip on non-Darwin platforms
	if runtime.GOOS != "darwin" {
		t.Skip("Skipping macOS-specific test")
	}

	h := NewHardening()
	err := h.disableCoreDumps()
	if err != nil {
		t.Fatalf("Failed to disable core dumps: %v", err)
	}

	// Verify core dump limit is 0
	var rLimit syscall.Rlimit
	err = syscall.Getrlimit(syscall.RLIMIT_CORE, &rLimit)
	if err != nil {
		t.Fatalf("Failed to get RLIMIT_CORE: %v", err)
	}

	if rLimit.Cur != 0 || rLimit.Max != 0 {
		t.Errorf("Expected core dump limit to be 0, got cur=%d max=%d", rLimit.Cur, rLimit.Max)
	}
}

func TestFindUnprivilegedUser(t *testing.T) {
	// Skip on non-Darwin platforms
	if runtime.GOOS != "darwin" {
		t.Skip("Skipping macOS-specific test")
	}

	h := NewHardening()
	user, err := h.findUnprivilegedUser()

	// We expect to find at least one of the standard unprivileged users
	if err != nil {
		t.Logf("Warning: No unprivileged user found: %v", err)
	} else {
		validUsers := map[string]bool{
			"_dnshield": true,
			"nobody":    true,
			"daemon":    true,
		}
		if !validUsers[user.Username] {
			t.Errorf("Unexpected unprivileged user: %s", user.Username)
		}
	}
}

func TestApplyHardening(t *testing.T) {
	// Skip on non-Darwin platforms
	if runtime.GOOS != "darwin" {
		t.Skip("Skipping macOS-specific test")
	}

	// Set a test environment variable
	os.Setenv("AWS_ACCESS_KEY_ID", "test-key")

	h := NewHardening()
	err := h.ApplyHardening()
	if err != nil {
		t.Fatalf("Failed to apply hardening: %v", err)
	}

	// Verify environment was cleared
	if val := os.Getenv("AWS_ACCESS_KEY_ID"); val != "" {
		t.Error("Expected AWS_ACCESS_KEY_ID to be cleared")
	}

	// Verify core dumps are disabled
	var rLimit syscall.Rlimit
	syscall.Getrlimit(syscall.RLIMIT_CORE, &rLimit)
	if rLimit.Cur != 0 {
		t.Error("Expected core dumps to be disabled")
	}
}