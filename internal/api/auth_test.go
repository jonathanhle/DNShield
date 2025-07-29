package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAPITokenManager(t *testing.T) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()
	tokenPath := filepath.Join(tempDir, ".dnshield", ".dnshield_api_token")
	
	atm := &APITokenManager{
		tokenPath: tokenPath,
	}
	
	t.Run("GenerateToken", func(t *testing.T) {
		token, err := atm.GenerateToken()
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}
		
		if len(token) != apiTokenLength*2 { // Hex encoding doubles the length
			t.Errorf("Token length incorrect: got %d, want %d", len(token), apiTokenLength*2)
		}
		
		// Check file permissions
		info, err := os.Stat(tokenPath)
		if err != nil {
			t.Fatalf("Failed to stat token file: %v", err)
		}
		
		if info.Mode().Perm() != 0600 {
			t.Errorf("Token file has incorrect permissions: %v", info.Mode().Perm())
		}
		
		// Verify token is loaded
		if !atm.loaded || atm.token != token {
			t.Error("Token not properly loaded after generation")
		}
	})
	
	t.Run("LoadToken", func(t *testing.T) {
		// Create a new manager instance
		atm2 := &APITokenManager{
			tokenPath: tokenPath,
		}
		
		if err := atm2.LoadToken(); err != nil {
			t.Fatalf("Failed to load token: %v", err)
		}
		
		if !atm2.loaded {
			t.Error("Token not marked as loaded")
		}
		
		if atm2.token == "" {
			t.Error("Token is empty after loading")
		}
	})
	
	t.Run("ValidateToken", func(t *testing.T) {
		// Generate a token
		token, err := atm.GenerateToken()
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}
		
		// Test valid token
		if !atm.ValidateToken(token) {
			t.Error("Valid token rejected")
		}
		
		// Test invalid token
		if atm.ValidateToken("invalid-token") {
			t.Error("Invalid token accepted")
		}
		
		// Test empty token
		if atm.ValidateToken("") {
			t.Error("Empty token accepted")
		}
	})
}

func TestAuthMiddleware(t *testing.T) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()
	tokenPath := filepath.Join(tempDir, ".dnshield", ".dnshield_api_token")
	
	atm := &APITokenManager{
		tokenPath: tokenPath,
	}
	
	// Generate a token
	token, err := atm.GenerateToken()
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}
	
	// Create a test handler
	testHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Success"))
	}
	
	// Wrap with auth middleware
	protectedHandler := atm.AuthMiddleware(testHandler)
	
	t.Run("NoAuthHeader", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/test", nil)
		rec := httptest.NewRecorder()
		
		protectedHandler(rec, req)
		
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, rec.Code)
		}
		
		if rec.Header().Get("WWW-Authenticate") != "Bearer" {
			t.Error("Missing WWW-Authenticate header")
		}
	})
	
	t.Run("InvalidAuthFormat", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/test", nil)
		req.Header.Set("Authorization", "Basic dGVzdDp0ZXN0") // Basic auth instead of Bearer
		rec := httptest.NewRecorder()
		
		protectedHandler(rec, req)
		
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, rec.Code)
		}
	})
	
	t.Run("InvalidToken", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/test", nil)
		req.Header.Set("Authorization", "Bearer invalid-token")
		rec := httptest.NewRecorder()
		
		protectedHandler(rec, req)
		
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, rec.Code)
		}
	})
	
	t.Run("ValidToken", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/test", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		
		protectedHandler(rec, req)
		
		if rec.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, rec.Code)
		}
		
		if string(rec.Body.Bytes()) != "Success" {
			t.Errorf("Expected body 'Success', got '%s'", rec.Body.String())
		}
	})
}

func TestRateLimiter(t *testing.T) {
	rl := NewRateLimiter(3, time.Second) // 3 requests per second
	
	// Create a test handler
	testHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}
	
	// Wrap with rate limit middleware
	limitedHandler := rl.RateLimitMiddleware(testHandler)
	
	t.Run("WithinLimit", func(t *testing.T) {
		// Make 3 requests (within limit)
		for i := 0; i < 3; i++ {
			req := httptest.NewRequest("GET", "/api/test", nil)
			req.RemoteAddr = "192.168.1.1:12345"
			rec := httptest.NewRecorder()
			
			limitedHandler(rec, req)
			
			if rec.Code != http.StatusOK {
				t.Errorf("Request %d: Expected status %d, got %d", i+1, http.StatusOK, rec.Code)
			}
		}
	})
	
	t.Run("ExceedsLimit", func(t *testing.T) {
		// Make 4th request (exceeds limit)
		req := httptest.NewRequest("GET", "/api/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		
		limitedHandler(rec, req)
		
		if rec.Code != http.StatusTooManyRequests {
			t.Errorf("Expected status %d, got %d", http.StatusTooManyRequests, rec.Code)
		}
	})
	
	t.Run("DifferentIP", func(t *testing.T) {
		// Different IP should have its own limit
		req := httptest.NewRequest("GET", "/api/test", nil)
		req.RemoteAddr = "192.168.1.2:12345"
		rec := httptest.NewRecorder()
		
		limitedHandler(rec, req)
		
		if rec.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, rec.Code)
		}
	})
	
	t.Run("XForwardedFor", func(t *testing.T) {
		// Test X-Forwarded-For header
		req := httptest.NewRequest("GET", "/api/test", nil)
		req.Header.Set("X-Forwarded-For", "10.0.0.1, 192.168.1.1")
		req.RemoteAddr = "192.168.1.100:12345"
		rec := httptest.NewRecorder()
		
		limitedHandler(rec, req)
		
		// Should use the first IP from X-Forwarded-For
		if rec.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, rec.Code)
		}
	})
}