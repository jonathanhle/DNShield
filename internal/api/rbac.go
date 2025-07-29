package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// Role represents an access role
type Role string

const (
	RoleAdmin    Role = "admin"
	RoleOperator Role = "operator"
	RoleViewer   Role = "viewer"
)

// Permission represents an API permission
type Permission string

const (
	PermissionViewStatus       Permission = "status:view"
	PermissionViewStats        Permission = "stats:view"
	PermissionViewConfig       Permission = "config:view"
	PermissionModifyConfig     Permission = "config:modify"
	PermissionPauseProtection  Permission = "protection:pause"
	PermissionResumeProtection Permission = "protection:resume"
	PermissionRefreshRules     Permission = "rules:refresh"
	PermissionClearCache       Permission = "cache:clear"
)

// RolePermissions maps roles to their permissions
var RolePermissions = map[Role][]Permission{
	RoleAdmin: {
		PermissionViewStatus,
		PermissionViewStats,
		PermissionViewConfig,
		PermissionModifyConfig,
		PermissionPauseProtection,
		PermissionResumeProtection,
		PermissionRefreshRules,
		PermissionClearCache,
	},
	RoleOperator: {
		PermissionViewStatus,
		PermissionViewStats,
		PermissionViewConfig,
		PermissionPauseProtection,
		PermissionResumeProtection,
		PermissionRefreshRules,
		PermissionClearCache,
	},
	RoleViewer: {
		PermissionViewStatus,
		PermissionViewStats,
		PermissionViewConfig,
	},
}

// APIKey represents an API key with associated role
type APIKey struct {
	Key       string    `json:"key"`
	Role      Role      `json:"role"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	Disabled  bool      `json:"disabled"`
}

// RBACManager manages role-based access control
type RBACManager struct {
	apiKeys map[string]*APIKey
}

// NewRBACManager creates a new RBAC manager
func NewRBACManager() *RBACManager {
	return &RBACManager{
		apiKeys: make(map[string]*APIKey),
	}
}

// AddAPIKey adds a new API key with the specified role
func (r *RBACManager) AddAPIKey(key string, role Role, expiration time.Duration) {
	apiKey := &APIKey{
		Key:       key,
		Role:      role,
		CreatedAt: time.Now(),
		Disabled:  false,
	}
	
	if expiration > 0 {
		apiKey.ExpiresAt = time.Now().Add(expiration)
	}
	
	r.apiKeys[key] = apiKey
	logrus.WithFields(logrus.Fields{
		"role":       role,
		"expires_at": apiKey.ExpiresAt,
	}).Info("Added API key")
}

// ValidateAPIKey validates an API key and returns its role
func (r *RBACManager) ValidateAPIKey(key string) (Role, bool) {
	apiKey, exists := r.apiKeys[key]
	if !exists {
		return "", false
	}
	
	if apiKey.Disabled {
		return "", false
	}
	
	if !apiKey.ExpiresAt.IsZero() && time.Now().After(apiKey.ExpiresAt) {
		return "", false
	}
	
	return apiKey.Role, true
}

// HasPermission checks if a role has a specific permission
func (r *RBACManager) HasPermission(role Role, permission Permission) bool {
	permissions, exists := RolePermissions[role]
	if !exists {
		return false
	}
	
	for _, p := range permissions {
		if p == permission {
			return true
		}
	}
	
	return false
}

// RBACMiddleware provides role-based access control for API endpoints
func (s *Server) RBACMiddleware(permission Permission, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract API key from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Missing authorization header", http.StatusUnauthorized)
			return
		}
		
		// Expected format: "Bearer <api-key>"
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
			return
		}
		
		apiKey := parts[1]
		
		// Validate API key and get role
		role, valid := s.rbacManager.ValidateAPIKey(apiKey)
		if !valid {
			http.Error(w, "Invalid or expired API key", http.StatusUnauthorized)
			return
		}
		
		// Check if role has required permission
		if !s.rbacManager.HasPermission(role, permission) {
			logrus.WithFields(logrus.Fields{
				"role":       role,
				"permission": permission,
				"ip":         r.RemoteAddr,
			}).Warn("Access denied - insufficient permissions")
			http.Error(w, "Insufficient permissions", http.StatusForbidden)
			return
		}
		
		// Add role to request context
		ctx := context.WithValue(r.Context(), "role", role)
		handler(w, r.WithContext(ctx))
	}
}

// PublicEndpoint wraps endpoints that don't require authentication
func (s *Server) PublicEndpoint(handler http.HandlerFunc) http.HandlerFunc {
	return handler
}

// ConfigUpdate represents a configuration update request
type ConfigUpdate struct {
	AllowPause     *bool   `json:"allow_pause,omitempty"`
	AllowQuit      *bool   `json:"allow_quit,omitempty"`
	PolicyURL      *string `json:"policy_url,omitempty"`
	ReportingURL   *string `json:"reporting_url,omitempty"`
	UpdateInterval *int    `json:"update_interval,omitempty"`
}

// handleConfigUpdate handles configuration updates (requires admin role)
func (s *Server) handleConfigUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPatch {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	var update ConfigUpdate
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	
	// Get current config
	s.mu.Lock()
	defer s.mu.Unlock()
	
	// Apply updates
	if update.AllowPause != nil {
		s.config.AllowPause = *update.AllowPause
	}
	if update.AllowQuit != nil {
		s.config.AllowQuit = *update.AllowQuit
	}
	if update.PolicyURL != nil {
		s.config.PolicyURL = *update.PolicyURL
	}
	if update.ReportingURL != nil {
		s.config.ReportingURL = *update.ReportingURL
	}
	if update.UpdateInterval != nil {
		s.config.UpdateInterval = *update.UpdateInterval
	}
	
	// Log configuration change
	role := r.Context().Value("role").(Role)
	logrus.WithFields(logrus.Fields{
		"role":   role,
		"ip":     r.RemoteAddr,
		"update": update,
	}).Info("Configuration updated")
	
	// Return updated config
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.config)
}