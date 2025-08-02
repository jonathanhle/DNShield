package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"dnshield/internal/dns"
	"dnshield/internal/utils"
	"github.com/sirupsen/logrus"
)

type Server struct {
	mu              sync.RWMutex
	stats           *Statistics
	recentBlocked   []BlockedDomain
	config          *Config
	statusCallbacks []func() Status
	server          *http.Server
	dnsManager      dns.DNSManager
	rbacManager     *RBACManager
	rateLimiter     *RateLimiter
}

type Statistics struct {
	QueriesTotal    int64     `json:"queries_total"`
	QueriesBlocked  int64     `json:"queries_blocked"`
	CacheHits       int64     `json:"cache_hits"`
	CacheMisses     int64     `json:"cache_misses"`
	CertificatesGen int64     `json:"certificates_generated"`
	Uptime          string    `json:"uptime"`
	LastRuleUpdate  time.Time `json:"last_rule_update"`
	BlockedToday    int64     `json:"blocked_today"`
	QueriesToday    int64     `json:"queries_today"`
	CacheHitRate    float64   `json:"cache_hit_rate"`
	MemoryUsageMB   float64   `json:"memory_usage_mb"`
	CPUUsagePercent float64   `json:"cpu_usage_percent"`
}

type BlockedDomain struct {
	Domain    string    `json:"domain"`
	Timestamp time.Time `json:"timestamp"`
	Rule      string    `json:"rule"`
	ClientIP  string    `json:"client_ip"`
}

type Status struct {
	Running          bool      `json:"running"`
	Protected        bool      `json:"protected"`
	DNSConfigured    bool      `json:"dns_configured"`
	CurrentDNS       []string  `json:"current_dns"`
	UpstreamDNS      []string  `json:"upstream_dns"`
	Mode             string    `json:"mode"` // "standard" or "secure"
	PolicyEnforced   bool      `json:"policy_enforced"`
	PolicySource     string    `json:"policy_source"`
	LastHealthCheck  time.Time `json:"last_health_check"`
	Version          string    `json:"version"`
	CertificateValid bool      `json:"certificate_valid"`
	CurrentNetwork   string    `json:"current_network,omitempty"`
	NetworkInterface string    `json:"network_interface,omitempty"`
	OriginalDNS      []string  `json:"original_dns,omitempty"`
}

type Config struct {
	AllowPause     bool   `json:"allow_pause"`
	AllowQuit      bool   `json:"allow_quit"`
	PolicyURL      string `json:"policy_url"`
	ReportingURL   string `json:"reporting_url"`
	UpdateInterval int    `json:"update_interval"`
}

type PauseRequest struct {
	Duration string `json:"duration"` // "5m", "30m", "1h"
}

func NewServer(dnsManager dns.DNSManager) *Server {
	return &Server{
		stats:         &Statistics{},
		recentBlocked: make([]BlockedDomain, 0, 100),
		config: &Config{
			AllowPause: true,
			AllowQuit:  true,
		},
		dnsManager:  dnsManager,
		rbacManager: NewRBACManager(),
		rateLimiter: NewRateLimiter(100, time.Minute), // 100 requests per minute per IP
	}
}

func (s *Server) Start(port int) error {
	mux := http.NewServeMux()

	// Apply rate limiting to all endpoints
	rl := s.rateLimiter.RateLimitMiddleware

	// Public endpoints (no authentication required)
	mux.HandleFunc("/api/health", rl(s.PublicEndpoint(s.handleHealth)))

	// Core endpoints (viewer access)
	mux.HandleFunc("/api/status", rl(s.RBACMiddleware(PermissionViewStatus, s.handleStatus)))
	mux.HandleFunc("/api/statistics", rl(s.RBACMiddleware(PermissionViewStats, s.handleStatistics)))
	mux.HandleFunc("/api/recent-blocked", rl(s.RBACMiddleware(PermissionViewStats, s.handleRecentBlocked)))
	mux.HandleFunc("/api/config", rl(s.RBACMiddleware(PermissionViewConfig, s.handleConfig)))

	// Configuration modification endpoint (admin only)
	mux.HandleFunc("/api/config/update", rl(s.RBACMiddleware(PermissionModifyConfig, s.handleConfigUpdate)))

	// Control endpoints (operator access)
	mux.HandleFunc("/api/pause", rl(s.RBACMiddleware(PermissionPauseProtection, s.handlePause)))
	mux.HandleFunc("/api/resume", rl(s.RBACMiddleware(PermissionResumeProtection, s.handleResume)))
	mux.HandleFunc("/api/refresh-rules", rl(s.RBACMiddleware(PermissionRefreshRules, s.handleRefreshRules)))
	mux.HandleFunc("/api/clear-cache", rl(s.RBACMiddleware(PermissionClearCache, s.handleClearCache)))

	// WebSocket for real-time updates (viewer access)
	mux.HandleFunc("/api/ws", rl(s.RBACMiddleware(PermissionViewStatus, s.handleWebSocket)))

	s.server = &http.Server{
		Addr:         fmt.Sprintf("127.0.0.1:%d", port),
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	logrus.Infof("Starting API server on port %d", port)
	return s.server.ListenAndServe()
}

func (s *Server) Stop(ctx context.Context) error {
	if s.server != nil {
		return s.server.Shutdown(ctx)
	}
	return nil
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check if DNS is paused
	isPaused := false
	if s.dnsManager != nil {
		isPaused = s.dnsManager.IsPaused()
	}

	status := Status{
		Running:       true,
		Protected:     !isPaused,
		DNSConfigured: true,
		CurrentDNS:    []string{"127.0.0.1"},
		UpstreamDNS:   []string{"1.1.1.1", "8.8.8.8"},
		Mode:          "standard",
		Version:       "1.0.0",
	}

	// Add network information if available
	if s.dnsManager != nil {
		if currentNetwork := s.dnsManager.GetCurrentNetwork(); currentNetwork != nil {
			if currentNetwork.SSID != "" {
				status.CurrentNetwork = currentNetwork.SSID
			} else {
				status.CurrentNetwork = currentNetwork.Interface
			}
			status.NetworkInterface = currentNetwork.Interface
		}
		
		if networkDNS := s.dnsManager.GetNetworkDNS(); networkDNS != nil && len(networkDNS.DNSServers) > 0 {
			status.OriginalDNS = networkDNS.DNSServers
		}
	}

	// Call registered status callbacks
	for _, cb := range s.statusCallbacks {
		if cbStatus := cb(); cbStatus.Running {
			status = cbStatus
			// Override protection status based on pause state
			status.Protected = !isPaused
			// Preserve network info
			if s.dnsManager != nil {
				if currentNetwork := s.dnsManager.GetCurrentNetwork(); currentNetwork != nil {
					if currentNetwork.SSID != "" {
						status.CurrentNetwork = currentNetwork.SSID
					} else {
						status.CurrentNetwork = currentNetwork.Interface
					}
					status.NetworkInterface = currentNetwork.Interface
				}
				if networkDNS := s.dnsManager.GetNetworkDNS(); networkDNS != nil && len(networkDNS.DNSServers) > 0 {
					status.OriginalDNS = networkDNS.DNSServers
				}
			}
			break
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (s *Server) handleStatistics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	stats := *s.stats
	s.mu.RUnlock()

	// Calculate cache hit rate
	if stats.CacheHits+stats.CacheMisses > 0 {
		stats.CacheHitRate = float64(stats.CacheHits) / float64(stats.CacheHits+stats.CacheMisses) * 100
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (s *Server) handleRecentBlocked(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	recent := make([]BlockedDomain, len(s.recentBlocked))
	copy(recent, s.recentBlocked)
	s.mu.RUnlock()

	// Return last 20 entries
	if len(recent) > 20 {
		recent = recent[len(recent)-20:]
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(recent)
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	config := *s.config
	s.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

func (s *Server) handlePause(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	if !s.config.AllowPause {
		s.mu.RUnlock()
		http.Error(w, "Pause not allowed by policy", http.StatusForbidden)
		return
	}
	s.mu.RUnlock()

	var req PauseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Parse duration
	duration, err := time.ParseDuration(req.Duration)
	if err != nil {
		http.Error(w, "Invalid duration format", http.StatusBadRequest)
		return
	}

	// Pause DNS filtering
	if s.dnsManager != nil {
		if err := s.dnsManager.PauseDNSFiltering(duration); err != nil {
			logrus.WithError(err).Error("Failed to pause DNS filtering")
			http.Error(w, "Failed to pause protection", http.StatusInternalServerError)
			return
		}
	}

	logrus.Infof("Paused protection for %s", req.Duration)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "paused", "duration": req.Duration})
}

func (s *Server) handleResume(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Resume DNS filtering
	if s.dnsManager != nil {
		if err := s.dnsManager.ResumeDNSFiltering(); err != nil {
			logrus.WithError(err).Error("Failed to resume DNS filtering")
			http.Error(w, "Failed to resume protection", http.StatusInternalServerError)
			return
		}
	}

	logrus.Info("Resumed protection")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "resumed"})
}

func (s *Server) handleRefreshRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// TODO: Trigger rule refresh
	logrus.Info("Refreshing blocking rules")

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "refreshing"})
}

func (s *Server) handleClearCache(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// TODO: Clear DNS cache
	logrus.Info("Clearing DNS cache")

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "cache_cleared"})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"healthy": true})
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement WebSocket for real-time updates
	http.Error(w, "WebSocket not implemented", http.StatusNotImplemented)
}

// Public methods for updating statistics

func (s *Server) IncrementQueries() {
	s.mu.Lock()
	s.stats.QueriesTotal++
	s.stats.QueriesToday++
	s.mu.Unlock()
}

func (s *Server) IncrementBlocked() {
	s.mu.Lock()
	s.stats.QueriesBlocked++
	s.stats.BlockedToday++
	s.mu.Unlock()
}

func (s *Server) IncrementCacheHit() {
	s.mu.Lock()
	s.stats.CacheHits++
	s.mu.Unlock()
}

func (s *Server) IncrementCacheMiss() {
	s.mu.Lock()
	s.stats.CacheMisses++
	s.mu.Unlock()
}

func (s *Server) AddBlockedDomain(domain, rule, clientIP string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	blocked := BlockedDomain{
		Domain:    domain,
		Timestamp: time.Now(),
		Rule:      rule,
		ClientIP:  clientIP,
	}

	s.recentBlocked = append(s.recentBlocked, blocked)

	// Keep only last 100 entries
	if len(s.recentBlocked) > 100 {
		s.recentBlocked = s.recentBlocked[1:]
	}
}

func (s *Server) RegisterStatusCallback(cb func() Status) {
	s.statusCallbacks = append(s.statusCallbacks, cb)
}

func (s *Server) UpdateConfig(config *Config) {
	s.mu.Lock()
	s.config = config
	s.mu.Unlock()
}

func (s *Server) GetStats() *Statistics {
	s.mu.RLock()
	defer s.mu.RUnlock()
	stats := *s.stats
	return &stats
}

func (s *Server) UpdateStats(stats *Statistics) {
	s.mu.Lock()
	s.stats = stats
	s.mu.Unlock()
}

// LoadAPIKeys loads API keys from the persistent store
func (s *Server) LoadAPIKeys() error {
	homeDir, _ := os.UserHomeDir()
	storePath := filepath.Join(homeDir, ".dnshield", "api_keys.json")
	
	// If file doesn't exist, skip loading
	info, err := os.Stat(storePath)
	if os.IsNotExist(err) {
		logrus.Info("No API keys file found, starting with empty key store")
		return nil
	}
	if err != nil {
		return err
	}
	
	// Check file size
	if info.Size() > utils.MaxConfigFileSize {
		return fmt.Errorf("API key store file exceeds maximum size of %d bytes", utils.MaxConfigFileSize)
	}
	
	data, err := os.ReadFile(storePath)
	if err != nil {
		return fmt.Errorf("failed to read API keys: %w", err)
	}
	
	var store struct {
		Keys map[string]struct {
			Key       string    `json:"key"`
			Role      string    `json:"role"`
			CreatedAt time.Time `json:"created_at"`
			ExpiresAt time.Time `json:"expires_at,omitempty"`
			Disabled  bool      `json:"disabled"`
		} `json:"keys"`
	}
	
	if err := json.Unmarshal(data, &store); err != nil {
		return fmt.Errorf("failed to parse API keys: %w", err)
	}
	
	// Load keys into RBAC manager
	for _, info := range store.Keys {
		if info.Disabled {
			continue
		}
		
		var expiration time.Duration
		if !info.ExpiresAt.IsZero() {
			expiration = time.Until(info.ExpiresAt)
			if expiration < 0 {
				continue // Skip expired keys
			}
		}
		
		s.rbacManager.AddAPIKey(info.Key, Role(info.Role), expiration)
	}
	
	logrus.Infof("Loaded %d active API keys", len(s.rbacManager.apiKeys))
	return nil
}
