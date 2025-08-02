package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRBACManager_AddAPIKey(t *testing.T) {
	rbac := NewRBACManager()
	
	// Test adding keys with different roles
	rbac.AddAPIKey("admin-key", RoleAdmin, 0)
	rbac.AddAPIKey("operator-key", RoleOperator, 24*time.Hour)
	rbac.AddAPIKey("viewer-key", RoleViewer, 0)
	
	// Verify keys were added
	if len(rbac.apiKeys) != 3 {
		t.Errorf("Expected 3 API keys, got %d", len(rbac.apiKeys))
	}
}

func TestRBACManager_ValidateAPIKey(t *testing.T) {
	rbac := NewRBACManager()
	rbac.AddAPIKey("valid-key", RoleAdmin, 0)
	
	// Add an expired key manually
	rbac.apiKeys["expired-key"] = &APIKey{
		Key:       "expired-key",
		Role:      RoleOperator,
		CreatedAt: time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Already expired
		Disabled:  false,
	}
	
	// Disable a key
	rbac.apiKeys["valid-key-disabled"] = &APIKey{
		Key:      "valid-key-disabled",
		Role:     RoleViewer,
		Disabled: true,
	}
	
	tests := []struct {
		name     string
		key      string
		wantRole Role
		wantOK   bool
	}{
		{"Valid key", "valid-key", RoleAdmin, true},
		{"Invalid key", "invalid-key", "", false},
		{"Expired key", "expired-key", "", false},
		{"Disabled key", "valid-key-disabled", "", false},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			role, ok := rbac.ValidateAPIKey(tt.key)
			if ok != tt.wantOK {
				t.Errorf("ValidateAPIKey() ok = %v, want %v", ok, tt.wantOK)
			}
			if role != tt.wantRole {
				t.Errorf("ValidateAPIKey() role = %v, want %v", role, tt.wantRole)
			}
		})
	}
}

func TestRBACManager_HasPermission(t *testing.T) {
	rbac := NewRBACManager()
	
	tests := []struct {
		name       string
		role       Role
		permission Permission
		want       bool
	}{
		// Admin should have all permissions
		{"Admin can modify config", RoleAdmin, PermissionModifyConfig, true},
		{"Admin can pause", RoleAdmin, PermissionPauseProtection, true},
		{"Admin can view", RoleAdmin, PermissionViewStatus, true},
		
		// Operator should have most permissions except config modification
		{"Operator can pause", RoleOperator, PermissionPauseProtection, true},
		{"Operator can clear cache", RoleOperator, PermissionClearCache, true},
		{"Operator cannot modify config", RoleOperator, PermissionModifyConfig, false},
		
		// Viewer should only have view permissions
		{"Viewer can view status", RoleViewer, PermissionViewStatus, true},
		{"Viewer cannot pause", RoleViewer, PermissionPauseProtection, false},
		{"Viewer cannot modify config", RoleViewer, PermissionModifyConfig, false},
		
		// Invalid role
		{"Invalid role", Role("invalid"), PermissionViewStatus, false},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rbac.HasPermission(tt.role, tt.permission); got != tt.want {
				t.Errorf("HasPermission() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRBACMiddleware(t *testing.T) {
	// Create server with RBAC
	server := &Server{
		rbacManager: NewRBACManager(),
		config:      &Config{},
	}
	server.rbacManager.AddAPIKey("admin-key", RoleAdmin, 0)
	server.rbacManager.AddAPIKey("viewer-key", RoleViewer, 0)
	
	// Create a test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		role := r.Context().Value("role").(Role)
		w.Write([]byte(string(role)))
	})
	
	tests := []struct {
		name           string
		permission     Permission
		authHeader     string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Valid admin key",
			permission:     PermissionModifyConfig,
			authHeader:     "Bearer admin-key",
			expectedStatus: http.StatusOK,
			expectedBody:   "admin",
		},
		{
			name:           "Valid viewer key with insufficient permissions",
			permission:     PermissionModifyConfig,
			authHeader:     "Bearer viewer-key",
			expectedStatus: http.StatusForbidden,
			expectedBody:   "Insufficient permissions\n",
		},
		{
			name:           "Missing auth header",
			permission:     PermissionViewStatus,
			authHeader:     "",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Missing authorization header\n",
		},
		{
			name:           "Invalid auth header format",
			permission:     PermissionViewStatus,
			authHeader:     "InvalidFormat",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Invalid authorization header format\n",
		},
		{
			name:           "Invalid API key",
			permission:     PermissionViewStatus,
			authHeader:     "Bearer invalid-key",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Invalid or expired API key\n",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request with auth header
			req := httptest.NewRequest("GET", "/test", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			
			// Create response recorder
			rr := httptest.NewRecorder()
			
			// Wrap handler with RBAC middleware
			handler := server.RBACMiddleware(tt.permission, testHandler)
			handler.ServeHTTP(rr, req)
			
			// Check status code
			if status := rr.Code; status != tt.expectedStatus {
				t.Errorf("handler returned wrong status code: got %v want %v",
					status, tt.expectedStatus)
			}
			
			// Check response body
			if body := rr.Body.String(); body != tt.expectedBody {
				t.Errorf("handler returned unexpected body: got %v want %v",
					body, tt.expectedBody)
			}
		})
	}
}

func TestHandleConfigUpdate(t *testing.T) {
	// Create server with RBAC
	server := &Server{
		rbacManager: NewRBACManager(),
		config: &Config{
			AllowPause: true,
			AllowQuit:  false,
		},
	}
	
	// Test updating configuration
	updateJSON := `{
		"allow_pause": false,
		"allow_quit": true,
		"policy_url": "https://example.com/policy"
	}`
	
	req := httptest.NewRequest("PUT", "/api/config/update", strings.NewReader(updateJSON))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), "role", RoleAdmin))
	
	rr := httptest.NewRecorder()
	server.handleConfigUpdate(rr, req)
	
	// Check status
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
	
	// Verify configuration was updated
	if server.config.AllowPause != false {
		t.Error("Expected AllowPause to be false")
	}
	if server.config.AllowQuit != true {
		t.Error("Expected AllowQuit to be true")
	}
	if server.config.PolicyURL != "https://example.com/policy" {
		t.Errorf("Expected PolicyURL to be 'https://example.com/policy', got '%s'", server.config.PolicyURL)
	}
}