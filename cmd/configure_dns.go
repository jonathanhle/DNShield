package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"dnshield/internal/audit"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// ConfigureDNSOptions contains options for the configure-dns command
type ConfigureDNSOptions struct {
	Restore bool
	Force   bool
}

// NewConfigureDNSCmd creates the configure-dns command
func NewConfigureDNSCmd() *cobra.Command {
	opts := &ConfigureDNSOptions{}

	cmd := &cobra.Command{
		Use:   "configure-dns",
		Short: "Configure DNS to 127.0.0.1 on all network interfaces",
		Long: `Automatically configure all network interfaces to use 127.0.0.1 as the DNS server.
This ensures DNShield filters all DNS traffic on the system.

This command will:
- List all network interfaces
- Set DNS to 127.0.0.1 for each active interface
- Save current DNS settings for restoration`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.Restore {
				return restoreDNS()
			}
			return configureDNS(opts)
		},
	}

	cmd.Flags().BoolVarP(&opts.Restore, "restore", "r", false, "Restore DNS settings to previous values")
	cmd.Flags().BoolVarP(&opts.Force, "force", "f", false, "Force configuration without prompting")

	return cmd
}

// NetworkInterface represents a network interface
type NetworkInterface struct {
	Name    string
	Type    string
	Current []string // Current DNS servers
}

// getDNSConfigPath returns the path to store DNS configuration backup
func getDNSConfigPath() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ".dnshield-dns-backup"
	}
	return fmt.Sprintf("%s/.dnshield/dns-backup.conf", homeDir)
}

// getNetworkInterfaces returns all network interfaces
func getNetworkInterfaces() ([]NetworkInterface, error) {
	// Get list of network services
	cmd := exec.Command("networksetup", "-listallnetworkservices")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list network services: %v", err)
	}

	logrus.WithField("raw_output", string(output)).Debug("Network services list")

	lines := strings.Split(string(output), "\n")
	var interfaces []NetworkInterface
	logrus.WithField("service_count", len(lines)-1).Debug("Found network services")

	// Skip first line (header) and process each service
	for i := 1; i < len(lines); i++ {
		service := strings.TrimSpace(lines[i])
		if service == "" {
			continue
		}
		if strings.HasPrefix(service, "*") {
			logrus.WithField("service", service).Debug("Skipping disabled service")
			continue // Skip disabled services
		}

		logrus.WithField("service", service).Debug("Processing network service")

		// Get current DNS servers
		dnsCmd := exec.Command("networksetup", "-getdnsservers", service)
		dnsOutput, err := dnsCmd.Output()
		if err != nil {
			logrus.WithError(err).WithField("service", service).Debug("Failed to get DNS servers")
			continue
		}

		var currentDNS []string
		dnsLines := strings.Split(strings.TrimSpace(string(dnsOutput)), "\n")
		logrus.WithFields(logrus.Fields{
			"service":    service,
			"dns_output": strings.TrimSpace(string(dnsOutput)),
		}).Debug("DNS servers output")

		for _, dns := range dnsLines {
			dns = strings.TrimSpace(dns)
			if dns != "" && !strings.Contains(dns, "There aren't any DNS Servers") {
				currentDNS = append(currentDNS, dns)
			}
		}

		iface := NetworkInterface{
			Name:    service,
			Type:    determineInterfaceType(service),
			Current: currentDNS,
		}
		interfaces = append(interfaces, iface)

		logrus.WithFields(logrus.Fields{
			"interface": iface.Name,
			"type":      iface.Type,
			"dns":       iface.Current,
		}).Debug("Added interface to list")
	}

	logrus.WithField("interface_count", len(interfaces)).Info("Network interfaces discovered")
	return interfaces, nil
}

// determineInterfaceType attempts to determine the interface type from its name
func determineInterfaceType(name string) string {
	lowerName := strings.ToLower(name)
	switch {
	case strings.Contains(lowerName, "wi-fi") || strings.Contains(lowerName, "airport"):
		return "Wi-Fi"
	case strings.Contains(lowerName, "ethernet"):
		return "Ethernet"
	case strings.Contains(lowerName, "thunderbolt"):
		return "Thunderbolt"
	case strings.Contains(lowerName, "usb"):
		return "USB"
	case strings.Contains(lowerName, "bluetooth"):
		return "Bluetooth"
	case strings.Contains(lowerName, "vpn"):
		return "VPN"
	default:
		return "Other"
	}
}

// saveDNSConfiguration saves current DNS configuration for restoration
func saveDNSConfiguration(interfaces []NetworkInterface) error {
	configPath := getDNSConfigPath()

	// Ensure directory exists
	dir := strings.TrimSuffix(configPath, "/dns-backup.conf")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
	}

	// Create backup file
	file, err := os.Create(configPath)
	if err != nil {
		return fmt.Errorf("failed to create backup file: %v", err)
	}
	defer file.Close()

	// Write configuration
	for _, iface := range interfaces {
		if len(iface.Current) == 0 {
			fmt.Fprintf(file, "%s=DHCP\n", iface.Name)
		} else {
			fmt.Fprintf(file, "%s=%s\n", iface.Name, strings.Join(iface.Current, ","))
		}
	}

	logrus.WithField("path", configPath).Info("Saved DNS configuration backup")
	return nil
}

// configureDNS configures DNS on all interfaces
func configureDNS(opts *ConfigureDNSOptions) error {
	// Check if running as root
	if os.Geteuid() != 0 {
		return fmt.Errorf("configure-dns must be run as root (use sudo)")
	}

	logrus.Info("Discovering network interfaces...")

	// Get all network interfaces
	interfaces, err := getNetworkInterfaces()
	if err != nil {
		return err
	}

	if len(interfaces) == 0 {
		return fmt.Errorf("no network interfaces found")
	}

	// Log current configuration
	logrus.Info("Current DNS Configuration:")
	for _, iface := range interfaces {
		if len(iface.Current) == 0 {
			logrus.WithFields(logrus.Fields{
				"interface": iface.Name,
				"type":      iface.Type,
				"dns":       "DHCP (automatic)",
			}).Info("Interface DNS status")
		} else {
			logrus.WithFields(logrus.Fields{
				"interface": iface.Name,
				"type":      iface.Type,
				"dns":       iface.Current,
			}).Info("Interface DNS status")
		}
	}

	// Display to stdout only when not forced (interactive mode)
	if !opts.Force {
		fmt.Println("\n🔍 Current DNS Configuration:")
		fmt.Println("─────────────────────────────")
		for _, iface := range interfaces {
			fmt.Printf("%-20s [%s]\n", iface.Name, iface.Type)
			if len(iface.Current) == 0 {
				fmt.Println("  DNS: DHCP (automatic)")
			} else {
				for _, dns := range iface.Current {
					fmt.Printf("  DNS: %s\n", dns)
				}
			}
		}
	}

	// Confirm with user unless force flag is set
	if !opts.Force {
		fmt.Printf("\n⚠️  This will change DNS to 127.0.0.1 on ALL interfaces above.\n")
		fmt.Printf("Continue? [y/N]: ")

		var response string
		fmt.Scanln(&response)
		if strings.ToLower(response) != "y" {
			fmt.Println("Operation cancelled.")
			return nil
		}
	}

	// Save current configuration
	if err := saveDNSConfiguration(interfaces); err != nil {
		logrus.WithError(err).Warn("Failed to save DNS backup")
	}

	// Configure each interface
	logrus.Info("Configuring DNS on all interfaces...")
	if !opts.Force {
		fmt.Println("\n🔧 Configuring DNS...")
	}
	successCount := 0
	failureCount := 0

	for _, iface := range interfaces {
		logrus.WithFields(logrus.Fields{
			"interface":    iface.Name,
			"type":         iface.Type,
			"previous_dns": iface.Current,
		}).Info("Configuring DNS on interface")

		if !opts.Force {
			fmt.Printf("  %-20s ", iface.Name)
		}

		// Set DNS to 127.0.0.1
		cmd := exec.Command("networksetup", "-setdnsservers", iface.Name, "127.0.0.1")
		logrus.WithFields(logrus.Fields{
			"command":   "networksetup",
			"args":      []string{"-setdnsservers", iface.Name, "127.0.0.1"},
			"interface": iface.Name,
		}).Debug("Executing networksetup command")

		output, err := cmd.CombinedOutput()
		if err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{
				"interface": iface.Name,
				"output":    strings.TrimSpace(string(output)),
			}).Error("Failed to set DNS")
			if !opts.Force {
				fmt.Printf("❌ Failed: %s\n", strings.TrimSpace(string(output)))
			}
			failureCount++
			continue
		}

		logrus.WithFields(logrus.Fields{
			"interface": iface.Name,
			"output":    strings.TrimSpace(string(output)),
		}).Info("Successfully configured DNS on interface")
		if !opts.Force {
			fmt.Println("✅ Configured")
		}
		successCount++

		// Audit log
		audit.Log(audit.EventConfigChange, "info", "DNS configured on interface", map[string]interface{}{
			"interface":    iface.Name,
			"type":         iface.Type,
			"previous_dns": iface.Current,
			"new_dns":      []string{"127.0.0.1"},
		})
	}

	// Log summary
	logrus.WithFields(logrus.Fields{
		"configured": successCount,
		"failed":     failureCount,
		"total":      len(interfaces),
	}).Info("DNS configuration completed")

	// Verify configuration was applied
	if successCount > 0 {
		logrus.Info("Verifying DNS configuration...")
		verifiedInterfaces, err := getNetworkInterfaces()
		if err != nil {
			logrus.WithError(err).Warn("Failed to verify DNS configuration")
		} else {
			verifiedCount := 0
			for _, iface := range verifiedInterfaces {
				for _, dns := range iface.Current {
					if dns == "127.0.0.1" {
						verifiedCount++
						logrus.WithFields(logrus.Fields{
							"interface": iface.Name,
							"dns":       iface.Current,
						}).Debug("Verified DNS configuration")
						break
					}
				}
			}
			logrus.WithFields(logrus.Fields{
				"verified":   verifiedCount,
				"configured": successCount,
			}).Info("DNS configuration verification complete")
		}
	}

	// Display summary to stdout only when not forced
	if !opts.Force {
		fmt.Printf("\n📊 Summary:\n")
		fmt.Printf("  ✅ Configured: %d interfaces\n", successCount)
		if failureCount > 0 {
			fmt.Printf("  ❌ Failed: %d interfaces\n", failureCount)
		}

		if successCount > 0 {
			fmt.Println("\n✨ DNS configuration complete!")
			fmt.Println("   All DNS queries will now be filtered by DNShield.")
			fmt.Println("\n💡 To restore previous settings, run:")
			fmt.Println("   sudo ./dnshield configure-dns --restore")
		}
	}

	return nil
}

// restoreDNS restores DNS configuration from backup
func restoreDNS() error {
	// Check if running as root
	if os.Geteuid() != 0 {
		return fmt.Errorf("configure-dns must be run as root (use sudo)")
	}

	configPath := getDNSConfigPath()

	// Check file size first
	info, err := os.Stat(configPath)
	if os.IsNotExist(err) {
		return fmt.Errorf("no DNS backup found. Run 'configure-dns' first to create a backup")
	}
	if err != nil {
		return fmt.Errorf("failed to stat backup: %v", err)
	}
	
	// Use a smaller limit for DNS backup files (100KB should be more than enough)
	const maxDNSBackupSize = 100 * 1024
	if info.Size() > maxDNSBackupSize {
		return fmt.Errorf("DNS backup file exceeds maximum size of %d bytes", maxDNSBackupSize)
	}

	// Read backup file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read backup: %v", err)
	}

	fmt.Println("\n🔄 Restoring DNS Configuration...")
	fmt.Println("─────────────────────────────────")

	// Parse and restore each interface
	lines := strings.Split(string(data), "\n")
	successCount := 0
	failureCount := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		interfaceName := parts[0]
		dnsServers := parts[1]

		fmt.Printf("  %-20s ", interfaceName)

		var cmd *exec.Cmd
		if dnsServers == "DHCP" {
			// Restore to DHCP
			cmd = exec.Command("networksetup", "-setdnsservers", interfaceName, "Empty")
		} else {
			// Restore specific DNS servers
			servers := strings.Split(dnsServers, ",")
			args := append([]string{"-setdnsservers", interfaceName}, servers...)
			cmd = exec.Command("networksetup", args...)
		}

		output, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Printf("❌ Failed: %s\n", strings.TrimSpace(string(output)))
			logrus.WithError(err).WithField("interface", interfaceName).Error("Failed to restore DNS")
			failureCount++
			continue
		}

		if dnsServers == "DHCP" {
			fmt.Println("✅ Restored to DHCP")
		} else {
			fmt.Printf("✅ Restored to %s\n", dnsServers)
		}
		successCount++

		// Audit log
		audit.Log(audit.EventConfigChange, "info", "DNS restored on interface", map[string]interface{}{
			"interface":    interfaceName,
			"restored_dns": dnsServers,
		})
	}

	// Summary
	fmt.Printf("\n📊 Summary:\n")
	fmt.Printf("  ✅ Restored: %d interfaces\n", successCount)
	if failureCount > 0 {
		fmt.Printf("  ❌ Failed: %d interfaces\n", failureCount)
	}

	if successCount > 0 {
		fmt.Println("\n✨ DNS configuration restored!")
	}

	return nil
}

// verifyDNSConfiguration checks if DNS is set to 127.0.0.1 on all interfaces
func VerifyDNSConfiguration() error {
	interfaces, err := getNetworkInterfaces()
	if err != nil {
		return err
	}

	notConfigured := []string{}
	for _, iface := range interfaces {
		isConfigured := false
		for _, dns := range iface.Current {
			if dns == "127.0.0.1" {
				isConfigured = true
				break
			}
		}
		if !isConfigured && len(iface.Current) > 0 {
			notConfigured = append(notConfigured, iface.Name)
		}
	}

	if len(notConfigured) > 0 {
		return fmt.Errorf("DNS not configured on interfaces: %s", strings.Join(notConfigured, ", "))
	}

	return nil
}
