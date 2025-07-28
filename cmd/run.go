// Package cmd implements the command-line interface for DNShield.
// It provides subcommands for running the service, managing certificates,
// checking status, and updating rules.
package cmd

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"dnshield/internal/audit"
	"dnshield/internal/ca"
	"dnshield/internal/config"
	"dnshield/internal/dns"
	"dnshield/internal/proxy"
	"dnshield/internal/rules"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// RunOptions contains options for the run command
type RunOptions struct {
	ConfigFile    string
	AutoConfigure bool
}

// NewRunCmd creates the run command
func NewRunCmd() *cobra.Command {
	opts := &RunOptions{}

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the DNShield agent service",
		Long:  `Start the DNS server and HTTPS proxy to filter network traffic.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAgent(opts)
		},
	}

	cmd.Flags().StringVarP(&opts.ConfigFile, "config", "c", "", "config file path")
	cmd.Flags().BoolVar(&opts.AutoConfigure, "auto-configure-dns", false, "automatically configure DNS on all interfaces to 127.0.0.1")

	return cmd
}

func runAgent(opts *RunOptions) error {
	// Check if running as root
	if os.Geteuid() != 0 {
		return fmt.Errorf("dnshield must be run as root to bind to ports 53, 80, and 443")
	}

	// Auto-configure DNS if requested
	if opts.AutoConfigure {
		logrus.Info("Auto-configuring DNS on all interfaces...")
		configOpts := &ConfigureDNSOptions{Force: true}
		if err := configureDNS(configOpts); err != nil {
			logrus.WithError(err).Error("Failed to auto-configure DNS")
			// Continue anyway - user can manually configure
		} else {
			logrus.Info("DNS auto-configuration complete")
		}
	}

	// Load configuration
	cfg, err := config.LoadConfig(opts.ConfigFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %v", err)
	}

	// Set up logging
	logLevel := cfg.Agent.LogLevel
	// Allow environment variable override
	if envLogLevel := os.Getenv("DNSHIELD_LOG_LEVEL"); envLogLevel != "" {
		logLevel = envLogLevel
	}
	
	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		level = logrus.InfoLevel
	}
	logrus.SetLevel(level)
	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	logrus.Info("Starting DNShield")

	// Initialize audit logging
	if err := audit.Initialize(); err != nil {
		logrus.WithError(err).Warn("Failed to initialize audit logging")
	}
	defer audit.Close()

	// Log binary integrity information
	logBinaryIntegrity()

	// Load CA
	logrus.Info("Loading CA certificate...")
	caManager, err := ca.LoadOrCreateManager()
	if err != nil {
		return fmt.Errorf("failed to load CA: %v", err)
	}

	// Create components
	blocker := dns.NewBlocker()

	// Load initial test domains
	if len(cfg.TestDomains) > 0 {
		logrus.WithField("count", len(cfg.TestDomains)).Info("Loading test domains")
		blocker.UpdateDomains(cfg.TestDomains)
	}

	// Create DNS handler and server
	handler := dns.NewHandler(blocker, cfg.DNS.Upstreams, "127.0.0.1", &cfg.CaptivePortal)
	dnsServer := dns.NewServer(handler)

	// Create certificate generator and HTTPS proxy
	certGen := proxy.NewCertGenerator(caManager)
	httpsProxy, err := proxy.NewHTTPSProxy(certGen)
	if err != nil {
		return fmt.Errorf("failed to create HTTPS proxy: %v", err)
	}

	// Start DNS server
	if err := dnsServer.Start(cfg.Agent.DNSPort); err != nil {
		return fmt.Errorf("failed to start DNS server: %v", err)
	}

	// Start HTTPS proxy
	if err := httpsProxy.Start(); err != nil {
		return fmt.Errorf("failed to start HTTPS proxy: %v", err)
	}

	// Set up S3 rule fetching if configured
	if cfg.S3.Bucket != "" {
		go startRuleUpdater(cfg, blocker)
	}

	logrus.Info("DNShield is running")
	logrus.Info("DNS server listening on port 53")
	logrus.Info("HTTP server listening on port 80")
	logrus.Info("HTTPS server listening on port 443")
	logrus.WithField("domains", blocker.GetBlockedCount()).Info("Blocked domains loaded")

	// Start DNS configuration monitor if auto-configure is enabled
	if opts.AutoConfigure {
		go monitorDNSConfiguration()
	}

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	logrus.Info("Shutting down...")

	// Stop servers
	if err := dnsServer.Stop(); err != nil {
		logrus.WithError(err).Warn("Error stopping DNS server")
	}
	if err := httpsProxy.Stop(); err != nil {
		logrus.WithError(err).Warn("Error stopping HTTPS proxy")
	}

	logrus.Info("DNShield stopped")
	return nil
}

func startRuleUpdater(cfg *config.Config, blocker *dns.Blocker) {
	// Create S3 fetcher
	fetcher, err := rules.NewFetcher(&cfg.S3)
	if err != nil {
		logrus.WithError(err).Error("Failed to create S3 fetcher")
		return
	}

	parser := rules.NewParser()

	// Update rules immediately
	updateRules(fetcher, parser, blocker)

	// Then update periodically
	ticker := time.NewTicker(cfg.S3.UpdateInterval)
	defer ticker.Stop()

	for range ticker.C {
		updateRules(fetcher, parser, blocker)
	}
}

func updateRules(fetcher *rules.Fetcher, parser *rules.Parser, blocker *dns.Blocker) {
	logrus.Info("Updating blocking rules...")

	// Fetch rules from S3
	ruleSet, err := fetcher.FetchRulesWithFallback("")
	if err != nil {
		logrus.WithError(err).Error("Failed to fetch rules")
		return
	}

	// Collect all domains
	var allDomains []string

	// Add direct domains
	allDomains = append(allDomains, ruleSet.Domains...)

	// Fetch and parse external sources
	for _, source := range ruleSet.Sources {
		domains, err := parser.FetchAndParseURL(source)
		if err != nil {
			logrus.WithError(err).WithField("source", source).Warn("Failed to fetch source")
			continue
		}
		allDomains = append(allDomains, domains...)
	}

	// Merge and deduplicate
	finalDomains := rules.MergeDomains(allDomains)

	// Update blocker
	blocker.UpdateDomains(finalDomains)
	if len(ruleSet.Whitelist) > 0 {
		blocker.UpdateWhitelist(ruleSet.Whitelist)
	}

	logrus.WithField("domains", len(finalDomains)).Info("Rules updated")
}

// logBinaryIntegrity logs information about the binary for tamper detection
func logBinaryIntegrity() {
	// Get binary path
	binaryPath, err := os.Executable()
	if err != nil {
		logrus.WithError(err).Warn("Failed to get binary path")
		return
	}

	// Calculate SHA256 checksum
	file, err := os.Open(binaryPath)
	if err != nil {
		logrus.WithError(err).Warn("Failed to open binary for checksum")
		return
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		logrus.WithError(err).Warn("Failed to calculate binary checksum")
		return
	}

	checksum := fmt.Sprintf("%x", hasher.Sum(nil))

	// Check code signature (macOS only)
	var signatureStatus string
	if cmd := exec.Command("codesign", "--verify", "--verbose", binaryPath); cmd != nil {
		output, err := cmd.CombinedOutput()
		if err != nil {
			signatureStatus = "unsigned or invalid"
			if ca.UseKeychain() {
				logrus.Warn("Running unsigned binary in v2.0 security mode")
				audit.LogSecurityViolation("Unsigned binary in v2 mode", map[string]interface{}{
					"binary": binaryPath,
					"error":  string(output),
				})
			}
		} else {
			signatureStatus = "valid"
		}
	}

	// Log integrity information
	logrus.WithFields(logrus.Fields{
		"binary":    binaryPath,
		"checksum":  checksum,
		"signature": signatureStatus,
		"mode":      getSecurityMode(),
	}).Info("Binary integrity check")

	// Audit log
	audit.Log(audit.EventServiceStart, "info", "Service started with integrity check", map[string]interface{}{
		"binary_path":      binaryPath,
		"sha256_checksum":  checksum,
		"signature_status": signatureStatus,
		"security_mode":    getSecurityMode(),
	})
}

// getSecurityMode returns the current security mode
func getSecurityMode() string {
	if ca.UseKeychain() {
		return "v2.0 (Keychain)"
	}
	return "v1.0 (File-based)"
}

// monitorDNSConfiguration periodically checks and fixes DNS configuration
func monitorDNSConfiguration() {
	logrus.Info("Starting DNS configuration monitor")
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	checkCount := 0
	for range ticker.C {
		checkCount++
		logrus.WithField("check_count", checkCount).Debug("Performing DNS configuration check")
		
		if err := VerifyDNSConfiguration(); err != nil {
			logrus.WithError(err).Warn("DNS configuration drift detected, reconfiguring...")

			// Reconfigure DNS
			configOpts := &ConfigureDNSOptions{Force: true}
			if err := configureDNS(configOpts); err != nil {
				logrus.WithError(err).Error("Failed to reconfigure DNS")
			} else {
				logrus.Info("DNS configuration restored")
				audit.Log(audit.EventConfigChange, "warning", "DNS configuration drift corrected", nil)
			}
		} else {
			logrus.WithField("check_count", checkCount).Debug("DNS configuration verified - no drift detected")
		}
	}
}
