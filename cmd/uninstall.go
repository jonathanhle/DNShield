package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"dnshield/internal/audit"
	"dnshield/internal/ca"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// UninstallOptions contains options for the uninstall command
type UninstallOptions struct {
	RemoveAll bool
}

// validateCertificateName validates certificate names to prevent command injection
func validateCertificateName(name string) error {
	// Certificate names should only contain alphanumeric characters, spaces, and basic punctuation
	validCertName := regexp.MustCompile(`^[a-zA-Z0-9\s\-\.]+$`)
	if !validCertName.MatchString(name) {
		return fmt.Errorf("invalid certificate name: %s", name)
	}
	
	// Additional check for suspicious patterns
	suspiciousPatterns := []string{
		"$", "`", ";", "&", "|", ">", "<", "\n", "\r", "\\",
		"$(", "${", "&&", "||", "`;", ";`", "../", "/..",
	}
	
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(name, pattern) {
			return fmt.Errorf("suspicious pattern in certificate name: %s", name)
		}
	}
	
	// Length check to prevent buffer overflow attempts
	if len(name) > 256 {
		return fmt.Errorf("certificate name too long: %d characters", len(name))
	}
	
	return nil
}

// validatePath validates file paths to prevent path traversal and command injection
func validatePath(path string) error {
	// Clean the path first
	cleanPath := filepath.Clean(path)
	
	// Ensure it's an absolute path
	if !filepath.IsAbs(cleanPath) {
		return fmt.Errorf("path must be absolute: %s", path)
	}
	
	// Check for path traversal attempts
	if strings.Contains(cleanPath, "..") {
		return fmt.Errorf("path traversal detected: %s", path)
	}
	
	// Validate allowed paths - should be in expected locations
	allowedPrefixes := []string{
		"/etc/dnshield",
		"/usr/local/etc/dnshield",
		"/Library/",
		"/System/Library/",
		filepath.Join(os.Getenv("HOME"), ".dnshield"),
	}
	
	validPath := false
	for _, prefix := range allowedPrefixes {
		if strings.HasPrefix(cleanPath, filepath.Clean(prefix)) {
			validPath = true
			break
		}
	}
	
	if !validPath {
		return fmt.Errorf("path not in allowed locations: %s", path)
	}
	
	return nil
}

// NewUninstallCmd creates the uninstall command
func NewUninstallCmd() *cobra.Command {
	opts := &UninstallOptions{}

	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Uninstall DNShield CA and configuration",
		Long: `Remove DNShield CA certificate from system keychain and optionally remove all configuration.

This command will:
- Remove the CA certificate from the system keychain
- Remove the CA private key from Keychain (on macOS with v2 security)
- Optionally remove all configuration and data with --all flag

You will be prompted for your password to remove the certificate.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUninstall(opts)
		},
	}

	cmd.Flags().BoolVar(&opts.RemoveAll, "all", false, "Remove all DNShield data and configuration")

	return cmd
}

func runUninstall(opts *UninstallOptions) error {
	fmt.Println("🗑️  DNShield Uninstall")
	fmt.Println("=========================")

	// Check platform
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("uninstall command is currently only supported on macOS")
	}

	// Uninstall based on security mode
	if ca.UseKeychain() {
		fmt.Println("📌 Removing CA from Keychain (v2.0 security mode)...")
		if err := ca.UninstallKeychainCA(); err != nil {
			logrus.WithError(err).Warn("Failed to uninstall Keychain CA")
		}
	} else {
		// Remove certificate from System keychain
		fmt.Println("📌 Removing CA certificate from system keychain...")
		fmt.Println("📌 You may be prompted for your password.")

		// Try multiple certificate names that might have been used
		certNames := []string{"DNShield Root CA", "DNShield", "DNShield Local CA", "DNS Guardian Root CA", "DNS Guardian"}

		for _, name := range certNames {
			// Validate certificate name to prevent command injection
			if err := validateCertificateName(name); err != nil {
				logrus.WithError(err).WithField("name", name).Error("Invalid certificate name")
				continue
			}
			
			cmd := exec.Command("sudo", "-p", "Touch ID or enter password: ",
				"security", "delete-certificate", "-c", name,
				"/Library/Keychains/System.keychain")

			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmd.Stdin = os.Stdin

			if err := cmd.Run(); err != nil {
				// Ignore errors as certificate might not exist with this name
				logrus.WithField("name", name).Debug("Certificate not found or already removed")
			} else {
				fmt.Printf("✅ Removed certificate: %s\n", name)
				// Audit log the certificate removal
				audit.Log(audit.EventCAUninstalled, "info", "Certificate removed from system keychain", map[string]interface{}{
					"certificate_name": name,
				})
			}
		}
	}

	// Remove configuration if requested
	if opts.RemoveAll {
		fmt.Println("\n🗑️  Removing all DNShield data...")

		// Remove CA directory
		caPath := ca.GetCAPath()
		// Validate the CA path before removal
		if err := validatePath(caPath); err != nil {
			logrus.WithError(err).WithField("path", caPath).Error("Invalid CA path")
		} else {
			if err := os.RemoveAll(caPath); err != nil {
				logrus.WithError(err).Warn("Failed to remove CA directory")
			} else {
				fmt.Printf("✅ Removed: %s\n", caPath)
				audit.Log(audit.EventConfigChange, "info", "CA directory removed", map[string]interface{}{
					"path": caPath,
				})
			}
		}

		// Remove config directory
		configPaths := []string{
			"/etc/dnshield",
			"/usr/local/etc/dnshield",
		}

		for _, path := range configPaths {
			if _, err := os.Stat(path); err == nil {
				// Validate path to prevent command injection
				if err := validatePath(path); err != nil {
					logrus.WithError(err).WithField("path", path).Error("Invalid config path")
					continue
				}
				
				cmd := exec.Command("sudo", "-p", "Touch ID or enter password: ",
					"rm", "-rf", path)
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				cmd.Stdin = os.Stdin

				if err := cmd.Run(); err != nil {
					logrus.WithError(err).Warnf("Failed to remove %s", path)
				} else {
					fmt.Printf("✅ Removed: %s\n", path)
					audit.Log(audit.EventConfigChange, "info", "Configuration directory removed", map[string]interface{}{
						"path": path,
					})
				}
			}
		}
	}

	fmt.Println("\n✅ DNShield uninstall complete!")

	if !opts.RemoveAll {
		fmt.Println("\nNote: Configuration files were preserved.")
		fmt.Println("Run with --all flag to remove everything.")
	}

	return nil
}
