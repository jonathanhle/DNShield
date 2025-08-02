package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	apiTokenFileName = ".dnshield_api_token"
	apiTokenLength   = 32 // 256 bits
	bearerPrefix     = "Bearer "
)

// APITokenManager manages API authentication tokens
type APITokenManager struct {
	mu        sync.RWMutex
	tokenPath string
	token     string
	loaded    bool
}

// NewAPITokenManager creates a new API token manager
func NewAPITokenManager() *APITokenManager {
	homeDir, _ := os.UserHomeDir()
	return &APITokenManager{
		tokenPath: filepath.Join(homeDir, ".dnshield", apiTokenFileName),
	}
}

// GenerateToken creates a new API authentication token
func (atm *APITokenManager) GenerateToken() (string, error) {
	// Create directory if it doesn't exist
	dir := filepath.Dir(atm.tokenPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("failed to create token directory: %w", err)
	}

	// Generate random token
	tokenBytes := make([]byte, apiTokenLength)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}

	token := hex.EncodeToString(tokenBytes)

	// Write token to file with restricted permissions
	if err := os.WriteFile(atm.tokenPath, []byte(token), 0600); err != nil {
		return "", fmt.Errorf("failed to write token: %w", err)
	}

	// Update in-memory token
	atm.mu.Lock()
	atm.token = token
	atm.loaded = true
	atm.mu.Unlock()

	return token, nil
}

// LoadToken loads the token from disk
func (atm *APITokenManager) LoadToken() error {
	atm.mu.Lock()
	defer atm.mu.Unlock()

	if atm.loaded {
		return nil
	}

	tokenBytes, err := os.ReadFile(atm.tokenPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no API token found. Generate one with 'dnshield auth generate-api-token'")
		}
		return fmt.Errorf("failed to read token: %w", err)
	}

	atm.token = strings.TrimSpace(string(tokenBytes))
	atm.loaded = true
	return nil
}

// ValidateToken checks if the provided token is valid
func (atm *APITokenManager) ValidateToken(providedToken string) bool {
	atm.mu.RLock()
	defer atm.mu.RUnlock()

	if !atm.loaded || atm.token == "" || providedToken == "" {
		return false
	}

	// Constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare([]byte(providedToken), []byte(atm.token)) == 1
}

// AuthMiddleware creates HTTP middleware for API authentication
func (atm *APITokenManager) AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Load token if not already loaded
		if err := atm.LoadToken(); err != nil {
			http.Error(w, "Authentication not configured", http.StatusInternalServerError)
			return
		}

		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
			return
		}

		// Check for Bearer prefix
		if !strings.HasPrefix(authHeader, bearerPrefix) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "Invalid Authorization format", http.StatusUnauthorized)
			return
		}

		// Extract and validate token
		token := strings.TrimPrefix(authHeader, bearerPrefix)
		if !atm.ValidateToken(token) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Token is valid, proceed to next handler
		next(w, r)
	}
}

// PublicEndpoint wraps handlers that don't require authentication
func PublicEndpoint(next http.HandlerFunc) http.HandlerFunc {
	return next
}

// RateLimiter provides basic rate limiting for API endpoints
type RateLimiter struct {
	mu       sync.Mutex
	requests map[string][]time.Time
	limit    int
	window   time.Duration
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
}

// RateLimitMiddleware creates HTTP middleware for rate limiting
func (rl *RateLimiter) RateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientIP := r.RemoteAddr
		if xForwardedFor := r.Header.Get("X-Forwarded-For"); xForwardedFor != "" {
			clientIP = strings.Split(xForwardedFor, ",")[0]
		}

		rl.mu.Lock()
		now := time.Now()
		
		// Clean up old requests
		if requests, exists := rl.requests[clientIP]; exists {
			var validRequests []time.Time
			for _, reqTime := range requests {
				if now.Sub(reqTime) < rl.window {
					validRequests = append(validRequests, reqTime)
				}
			}
			rl.requests[clientIP] = validRequests
		}

		// Check rate limit
		if len(rl.requests[clientIP]) >= rl.limit {
			rl.mu.Unlock()
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		// Add current request
		rl.requests[clientIP] = append(rl.requests[clientIP], now)
		rl.mu.Unlock()

		next(w, r)
	}
}