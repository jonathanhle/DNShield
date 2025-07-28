package cmd

import (
	"fmt"
	"os"

	"dnshield/internal/ca"
	"dnshield/internal/dns"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func NewInstallCACmd() *cobra.Command {
	return &cobra.Command{
		Use:   "install-ca",
		Short: "Generate and install the CA certificate",
		Long: `Generate a local Certificate Authority and install it in the system keychain.
This is required for HTTPS interception without certificate warnings.

The CA certificate will be stored in ~/.dnshield/ and installed in the system keychain.
You will be prompted for your password to install the certificate.`,
		RunE: runInstallCA,
	}
}

func runInstallCA(cmd *cobra.Command, args []string) error {
	fmt.Println("🔐 DNShield CA Installation")
	fmt.Println("================================")

	// Check security mode
	if ca.UseKeychain() {
		fmt.Println("🔒 V2.0 Security Mode: Keychain storage enabled")
		fmt.Println("   CA private key will be stored in macOS Keychain")
		fmt.Println("   Key will be non-extractable and process-restricted")
		fmt.Println()
	}

	// Check if running as root (not recommended for CA installation)
	if os.Geteuid() == 0 {
		fmt.Println("⚠️  Warning: Running as root. The CA will be installed system-wide.")
	}

	// Load or create CA
	fmt.Println("📝 Loading or creating CA certificate...")
	caManager, err := ca.LoadOrCreateManager()
	if err != nil {
		return fmt.Errorf("failed to load/create CA: %v", err)
	}

	// Get CA info
	cert := caManager.Certificate()
	fmt.Printf("✅ CA Subject: %s\n", cert.Subject)
	fmt.Printf("✅ Valid until: %s\n", cert.NotAfter.Format("2006-01-02"))
	fmt.Printf("✅ CA Path: %s\n", ca.GetCAPath())

	// Install CA
	fmt.Println("\n🔧 Installing CA in system keychain...")
	fmt.Println("📌 You may be prompted for your password.")

	if err := caManager.InstallCA(); err != nil {
		logrus.WithError(err).Error("Failed to install CA")
		fmt.Println("\n❌ Failed to install CA certificate")
		fmt.Println("\nManual installation instructions:")
		fmt.Printf("1. Open Keychain Access\n")
		fmt.Printf("2. Go to System keychain\n")
		fmt.Printf("3. Drag and drop: %s/ca.crt\n", ca.GetCAPath())
		fmt.Printf("4. Trust the certificate for SSL\n")
		return err
	}

	fmt.Println("\n✅ CA certificate installed successfully!")

	// Initialize network-aware DNS manager to capture configurations
	fmt.Println("\n📸 Initializing network-aware DNS management...")
	dnsManager := dns.NewNetworkManager()
	if err := dnsManager.Start(); err != nil {
		logrus.WithError(err).Warn("Failed to initialize DNS manager")
		fmt.Println("⚠️  Warning: Could not initialize DNS manager. Pause functionality may not work correctly.")
	} else {
		fmt.Println("✅ Network DNS management initialized")
		fmt.Println("   DNS configurations will be captured automatically for each network")
		dnsManager.Stop() // Just needed for initialization
	}

	fmt.Println("\n🎉 Setup complete! DNShield can now intercept HTTPS traffic.")
	fmt.Println("\nNext steps:")
	fmt.Println("1. Run the agent: sudo ./dnshield run")
	fmt.Println("2. Set your DNS to 127.0.0.1")
	fmt.Println("3. Test by visiting a blocked domain")

	return nil
}
