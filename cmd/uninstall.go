package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"dns-guardian/internal/ca"
	
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// UninstallOptions contains options for the uninstall command
type UninstallOptions struct {
	RemoveAll bool
}

// NewUninstallCmd creates the uninstall command
func NewUninstallCmd() *cobra.Command {
	opts := &UninstallOptions{}
	
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Uninstall DNS Guardian CA and configuration",
		Long: `Remove DNS Guardian CA certificate from system keychain and optionally remove all configuration.

This command will:
- Remove the CA certificate from the system keychain
- Remove the CA private key from Keychain (on macOS with v2 security)
- Optionally remove all configuration and data with --all flag

You will be prompted for your password to remove the certificate.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUninstall(opts)
		},
	}
	
	cmd.Flags().BoolVar(&opts.RemoveAll, "all", false, "Remove all DNS Guardian data and configuration")
	
	return cmd
}

func runUninstall(opts *UninstallOptions) error {
	fmt.Println("🗑️  DNS Guardian Uninstall")
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
		certNames := []string{"DNS Guardian Root CA", "DNS Guardian", "DNS Guardian Local CA"}
		
		for _, name := range certNames {
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
			}
		}
	}
	
	// Remove configuration if requested
	if opts.RemoveAll {
		fmt.Println("\n🗑️  Removing all DNS Guardian data...")
		
		// Remove CA directory
		caPath := ca.GetCAPath()
		if err := os.RemoveAll(caPath); err != nil {
			logrus.WithError(err).Warn("Failed to remove CA directory")
		} else {
			fmt.Printf("✅ Removed: %s\n", caPath)
		}
		
		// Remove config directory
		configPaths := []string{
			"/etc/dns-guardian",
			"/usr/local/etc/dns-guardian",
		}
		
		for _, path := range configPaths {
			if _, err := os.Stat(path); err == nil {
				cmd := exec.Command("sudo", "-p", "Touch ID or enter password: ",
					"rm", "-rf", path)
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				cmd.Stdin = os.Stdin
				
				if err := cmd.Run(); err != nil {
					logrus.WithError(err).Warnf("Failed to remove %s", path)
				} else {
					fmt.Printf("✅ Removed: %s\n", path)
				}
			}
		}
	}
	
	fmt.Println("\n✅ DNS Guardian uninstall complete!")
	
	if !opts.RemoveAll {
		fmt.Println("\nNote: Configuration files were preserved.")
		fmt.Println("Run with --all flag to remove everything.")
	}
	
	return nil
}