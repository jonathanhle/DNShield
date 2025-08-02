// Package cmd implements the command-line interface for DNShield.
// It provides subcommands for running the service, managing certificates,
// checking status, and updating rules.
package cmd

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"dnshield/internal/api"
	"dnshield/internal/audit"
	"dnshield/internal/ca"
	"dnshield/internal/config"
	"dnshield/internal/dns"
	"dnshield/internal/logging"
	"dnshield/internal/proxy"
	"dnshield/internal/rules"
	"dnshield/internal/security"

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

	// Check for security warnings
	securityWarnings := config.ValidateCredentialSecurity(cfg)
	for _, warning := range securityWarnings {
		logrus.Warnf("SECURITY WARNING: %s", warning)
	}
	
	// Log sanitized config (credentials removed)
	sanitizedCfg := config.SanitizeConfig(cfg)
	logrus.Debugf("Loaded configuration: %+v", sanitizedCfg)

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

	// Install sanitizing hook to prevent sensitive data leakage
	enablePII := cfg.Agent.LogLevel == "debug" && os.Getenv("DNSHIELD_ENABLE_PII_LOGGING") == "true"
	logging.InstallSanitizingHook(enablePII)

	logrus.Info("Starting DNShield")

	// Validate configuration
	if err := config.ValidateConfig(cfg); err != nil {
		return fmt.Errorf("invalid configuration: %v", err)
	}

	// Check for security issues in configuration
	config.ValidateCredentialSecurity(cfg)

	// Log sanitized configuration
	sanitizedConfig := config.SanitizeConfigForLogging(cfg)
	logrus.WithFields(logrus.Fields(sanitizedConfig)).Info("Configuration loaded")

	// Apply security hardening before doing anything else
	hardening := security.NewHardening()
	if err := hardening.ApplyHardening(); err != nil {
		logrus.WithError(err).Warn("Failed to apply security hardening")
	}

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
		if err := blocker.UpdateDomains(cfg.TestDomains); err != nil {
			logrus.WithError(err).Error("Failed to load test domains")
		}
	}

	// Create network-aware DNS manager for handling pause/resume
	dnsManager := dns.NewNetworkManager()

	// Start network monitoring
	if err := dnsManager.Start(); err != nil {
		logrus.WithError(err).Warn("Failed to start network monitoring")
	}
	defer dnsManager.Stop()

	// Enable DNS filtering if auto-configure is set
	if opts.AutoConfigure {
		if err := dnsManager.EnableDNSFiltering(); err != nil {
			logrus.WithError(err).Warn("Failed to enable DNS filtering via network manager")
		}
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create API server for menu bar app
	apiServer := api.NewServer(dnsManager)

	// Wait group for tracking goroutines
	var wg sync.WaitGroup

	// Start API server
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := apiServer.Start(5353); err != nil {
			logrus.WithError(err).Error("API server failed")
		}
	}()

	// Create DNS handler and server with API integration and captive portal support
	handler := dns.NewHandler(blocker, &cfg.DNS, "127.0.0.1", &cfg.CaptivePortal)
	handler.SetStatsCallback(func(query bool, blocked bool, cached bool) {
		if query {
			apiServer.IncrementQueries()
		}
		if blocked {
			apiServer.IncrementBlocked()
		}
		if cached {
			apiServer.IncrementCacheHit()
		} else if query {
			apiServer.IncrementCacheMiss()
		}
	})
	handler.SetBlockedCallback(func(domain, rule, clientIP string) {
		apiServer.AddBlockedDomain(domain, rule, clientIP)
	})
	dnsServer := dns.NewServer(handler)

	// Create certificate generator and HTTPS proxy
	certGen := proxy.NewCertGenerator(caManager, blocker)
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

	// All privileged ports are now bound, drop privileges if running as root
	if err := hardening.DropPrivilegesAfterBind(); err != nil {
		logrus.WithError(err).Warn("Failed to drop privileges")
		// Continue running even if privilege drop fails
	}

	// Set up S3 rule fetching if configured
	if cfg.S3.Bucket != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			startRuleUpdater(ctx, cfg, blocker)
		}()
	}

	logrus.Info("DNShield is running")
	logrus.Info("DNS server listening on port 53")
	logrus.Info("HTTP server listening on port 80")
	logrus.Info("HTTPS server listening on port 443")
	logrus.Info("API server listening on port 5353")
	logrus.WithField("domains", blocker.GetBlockedCount()).Info("Blocked domains loaded")

	// Register status callback for API
	startTime := time.Now()
	apiServer.RegisterStatusCallback(func() api.Status {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)

		return api.Status{
			Running:          true,
			Protected:        true,
			DNSConfigured:    true,
			CurrentDNS:       []string{"127.0.0.1"},
			UpstreamDNS:      cfg.DNS.Upstreams,
			Mode:             getSecurityMode(),
			PolicyEnforced:   !cfg.Agent.AllowDisable,
			PolicySource:     "local",
			LastHealthCheck:  time.Now(),
			Version:          "1.0.0",
			CertificateValid: true,
		}
	})

	// Load API keys
	if err := apiServer.LoadAPIKeys(); err != nil {
		logrus.WithError(err).Warn("Failed to load API keys")
	}

	// Update API server configuration
	apiServer.UpdateConfig(&api.Config{
		AllowPause:     cfg.Agent.AllowDisable,
		AllowQuit:      cfg.Agent.AllowDisable,
		UpdateInterval: int(cfg.S3.UpdateInterval / time.Minute),
	})

	// Start periodic stats update
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				var m runtime.MemStats
				runtime.ReadMemStats(&m)

				stats := apiServer.GetStats()
				stats.MemoryUsageMB = float64(m.Alloc) / 1024 / 1024
				stats.Uptime = time.Since(startTime).String()
				apiServer.UpdateStats(stats)
			}
		}
	}()

	// Start DNS configuration monitor if auto-configure is enabled
	if opts.AutoConfigure {
		wg.Add(1)
		go func() {
			defer wg.Done()
			monitorDNSConfiguration(ctx)
		}()
	}

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	logrus.Info("Shutting down...")

	// Cancel context to signal all goroutines to stop
	cancel()

	// Stop servers with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := apiServer.Stop(shutdownCtx); err != nil {
		logrus.WithError(err).Warn("Error stopping API server")
	}
	if err := dnsServer.Stop(); err != nil {
		logrus.WithError(err).Warn("Error stopping DNS server")
	}
	if err := httpsProxy.Stop(); err != nil {
		logrus.WithError(err).Warn("Error stopping HTTPS proxy")
	}

	// Wait for all goroutines to finish
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logrus.Info("All goroutines stopped cleanly")
	case <-time.After(5 * time.Second):
		logrus.Warn("Timeout waiting for goroutines to stop")
	}

	logrus.Info("DNShield stopped")
	return nil
}

func startRuleUpdater(ctx context.Context, cfg *config.Config, blocker *dns.Blocker) {
	// Create enterprise S3 fetcher
	fetcher, err := rules.NewEnterpriseFetcher(&cfg.S3)
	if err != nil {
		logrus.WithError(err).Error("Failed to create enterprise S3 fetcher")
		return
	}

	parser := rules.NewParser()

	// Update rules immediately
	updateEnterpriseRules(fetcher, parser, blocker)

	// Add jitter to prevent thundering herd
	if cfg.S3.UpdateJitter > 0 {
		jitter := time.Duration(rand.Int63n(int64(cfg.S3.UpdateJitter)))
		time.Sleep(jitter)
	}

	// Then update periodically
	ticker := time.NewTicker(cfg.S3.UpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logrus.Info("Rule updater shutting down")
			return
		case <-ticker.C:
			updateEnterpriseRules(fetcher, parser, blocker)
		}
	}
}

func updateEnterpriseRules(fetcher *rules.EnterpriseFetcher, parser *rules.Parser, blocker *dns.Blocker) {
	logrus.Info("Updating enterprise blocking rules...")

	// Fetch all applicable rules for this device
	enterpriseRules, err := fetcher.FetchEnterpriseRules()
	if err != nil {
		logrus.WithError(err).Error("Failed to fetch enterprise rules")
		return
	}

	// Log device identity
	logrus.WithFields(logrus.Fields{
		"device": enterpriseRules.DeviceName,
		"user":   enterpriseRules.UserEmail,
		"group":  enterpriseRules.GroupName,
	}).Info("Device identity resolved")

	// Update blocker metadata for logging
	blocker.UpdateMetadata(enterpriseRules.UserEmail, enterpriseRules.GroupName)

	// Merge rules according to precedence
	blockDomains, allowDomains, allowOnlyMode := enterpriseRules.MergeRules()

	// Get external block sources
	blockSources := enterpriseRules.GetBlockSources()

	// Fetch and parse external sources (only if not in allow-only mode)
	if !allowOnlyMode {
		for _, source := range blockSources {
			domains, err := parser.FetchAndParseURL(source)
			if err != nil {
				logrus.WithError(err).WithField("source", source).Warn("Failed to fetch source")
				continue
			}
			blockDomains = append(blockDomains, domains...)
		}
	}

	// Deduplicate block domains
	finalBlockDomains := rules.MergeDomains(blockDomains)

	// Update blocker
	if err := blocker.UpdateDomains(finalBlockDomains); err != nil {
		logrus.WithError(err).Error("Failed to update blocked domains")
		return
	}
	if err := blocker.UpdateAllowlist(allowDomains); err != nil {
		logrus.WithError(err).Error("Failed to update allowlist")
		return
	}
	blocker.SetAllowOnlyMode(allowOnlyMode)

	logFields := logrus.Fields{
		"blocked": len(finalBlockDomains),
		"allowed": len(allowDomains),
		"user":    enterpriseRules.UserEmail,
		"group":   enterpriseRules.GroupName,
	}

	if allowOnlyMode {
		logFields["mode"] = "allow-only"
	}

	logrus.WithFields(logFields).Info("Enterprise rules updated")
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
func monitorDNSConfiguration(ctx context.Context) {
	logrus.Info("Starting DNS configuration monitor")
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	checkCount := 0
	for {
		select {
		case <-ctx.Done():
			logrus.Info("DNS configuration monitor shutting down")
			return
		case <-ticker.C:
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
}
