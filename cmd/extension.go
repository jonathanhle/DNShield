package cmd

import (
	"fmt"
	"os"

	"dnshield/internal/config"
	"dnshield/internal/dns"
	"dnshield/internal/extension"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// NewExtensionCmd creates the extension management command
func NewExtensionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "extension",
		Short: "Manage Network Extension for system-level DNS filtering",
		Long: `Install, uninstall, and check status of the DNShield Network Extension.

The Network Extension provides kernel-level DNS filtering that cannot be bypassed
by applications. It requires admin privileges and user approval to install.`,
	}

	cmd.AddCommand(
		newExtensionInstallCmd(),
		newExtensionUninstallCmd(),
		newExtensionStatusCmd(),
	)

	return cmd
}

// newExtensionInstallCmd creates the install subcommand
func newExtensionInstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "install",
		Short: "Install the DNShield Network Extension",
		Long: `Install the system extension for kernel-level DNS filtering.

This requires:
- Administrator privileges (sudo)
- User approval in System Preferences > Privacy & Security
- Code signing with a valid Developer ID`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Check if running as root
			if os.Geteuid() != 0 {
				return fmt.Errorf("extension install must be run as root (use sudo)")
			}

			// Load configuration to get bundle ID
			cfg, err := config.LoadConfig("")
			if err != nil {
				// Use default if no config
				cfg = &config.Config{
					Extension: config.ExtensionConfig{
						BundleID: "com.dnshield.network-extension",
					},
				}
			}

			// Check if extension bundle exists
			bundlePath := fmt.Sprintf("network-extension/%s.systemextension", "DNShieldExtension")
			if _, err := os.Stat(bundlePath); os.IsNotExist(err) {
				return fmt.Errorf("Network Extension bundle not found at %s\n\nBuild it first with:\n  make build-extension\n\nOr for development:\n  cd network-extension && ./build.sh", bundlePath)
			}

			logrus.Info("Installing DNShield Network Extension...")

			// Create a dummy blocker for the manager
			blocker := dns.NewBlocker()
			
			// Create extension manager
			mgr := extension.NewManager(cfg.Extension.BundleID, blocker)

			// Install the extension
			if err := mgr.Install(); err != nil {
				return fmt.Errorf("installation failed: %v", err)
			}

			fmt.Println("\n✅ Network Extension installed successfully!")
			fmt.Println("\n⚠️  IMPORTANT: You must approve the extension in:")
			fmt.Println("   System Preferences > Privacy & Security")
			fmt.Println("\nAfter approval, run:")
			fmt.Println("   sudo dnshield run --mode=extension")

			return nil
		},
	}
}

// newExtensionUninstallCmd creates the uninstall subcommand
func newExtensionUninstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "uninstall",
		Short: "Uninstall the DNShield Network Extension",
		Long:  `Remove the system extension and restore normal DNS operation.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Check if running as root
			if os.Geteuid() != 0 {
				return fmt.Errorf("extension uninstall must be run as root (use sudo)")
			}

			// Load configuration
			cfg, err := config.LoadConfig("")
			if err != nil {
				cfg = &config.Config{
					Extension: config.ExtensionConfig{
						BundleID: "com.dnshield.network-extension",
					},
				}
			}

			logrus.Info("Uninstalling DNShield Network Extension...")

			// Create a dummy blocker for the manager
			blocker := dns.NewBlocker()
			
			// Create extension manager
			mgr := extension.NewManager(cfg.Extension.BundleID, blocker)

			// Uninstall the extension
			if err := mgr.Uninstall(); err != nil {
				return fmt.Errorf("uninstall failed: %v", err)
			}

			fmt.Println("\n✅ Network Extension uninstalled successfully!")
			fmt.Println("   DNS filtering has been disabled.")

			return nil
		},
	}
}

// newExtensionStatusCmd creates the status subcommand
func newExtensionStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Check Network Extension status",
		Long:  `Display the current status of the DNShield Network Extension.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Load configuration
			cfg, err := config.LoadConfig("")
			if err != nil {
				cfg = &config.Config{
					Extension: config.ExtensionConfig{
						BundleID: "com.dnshield.network-extension",
					},
				}
			}

			// Create a dummy blocker for the manager
			blocker := dns.NewBlocker()
			
			// Create extension manager
			mgr := extension.NewManager(cfg.Extension.BundleID, blocker)

			// Get status
			status := mgr.GetStatus()

			fmt.Println("DNShield Network Extension Status")
			fmt.Println("=================================")
			fmt.Printf("Bundle ID:      %s\n", status["bundle_id"])
			fmt.Printf("Installed:      %v\n", status["installed"])
			fmt.Printf("Running:        %v\n", status["running"])
			
			if status["running"].(bool) {
				fmt.Printf("Domain Count:   %d\n", status["domain_count"])
			}

			// Check if approved
			if !status["installed"].(bool) {
				fmt.Println("\n⚠️  Extension is not installed.")
				fmt.Println("Run: sudo dnshield extension install")
			} else if !status["running"].(bool) {
				fmt.Println("\n⚠️  Extension is installed but not running.")
				fmt.Println("Check System Preferences > Privacy & Security for approval")
				fmt.Println("Then run: sudo dnshield run --mode=extension")
			} else {
				fmt.Println("\n✅ Extension is active and filtering DNS queries")
			}

			return nil
		},
	}
}