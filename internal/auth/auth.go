package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	tokenFileName = ".dnshield_auth_token"
	tokenLength   = 32 // 256 bits
)

// TokenManager handles authentication tokens for DNShield commands
type TokenManager struct {
	tokenPath string
}

// NewTokenManager creates a new token manager
func NewTokenManager() *TokenManager {
	homeDir, _ := os.UserHomeDir()
	return &TokenManager{
		tokenPath: filepath.Join(homeDir, ".dnshield", tokenFileName),
	}
}

// GenerateToken creates a new authentication token
func (tm *TokenManager) GenerateToken() (string, error) {
	// Create directory if it doesn't exist
	dir := filepath.Dir(tm.tokenPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("failed to create token directory: %w", err)
	}

	// Generate random token
	tokenBytes := make([]byte, tokenLength)
	if _, err := io.ReadFull(rand.Reader, tokenBytes); err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}

	token := hex.EncodeToString(tokenBytes)

	// Write token to file with restricted permissions
	if err := os.WriteFile(tm.tokenPath, []byte(token), 0600); err != nil {
		return "", fmt.Errorf("failed to write token: %w", err)
	}

	return token, nil
}

// ValidateToken checks if the provided token is valid
func (tm *TokenManager) ValidateToken(providedToken string) error {
	if providedToken == "" {
		return fmt.Errorf("no token provided")
	}

	// Read stored token
	storedTokenBytes, err := os.ReadFile(tm.tokenPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no authentication token found. Run 'dnshield auth generate' first")
		}
		return fmt.Errorf("failed to read token: %w", err)
	}

	storedToken := strings.TrimSpace(string(storedTokenBytes))

	// Constant-time comparison to prevent timing attacks
	if subtle.ConstantTimeCompare([]byte(providedToken), []byte(storedToken)) != 1 {
		return fmt.Errorf("invalid token")
	}

	return nil
}

// GetToken reads the current token (for display purposes)
func (tm *TokenManager) GetToken() (string, error) {
	tokenBytes, err := os.ReadFile(tm.tokenPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("no authentication token found")
		}
		return "", fmt.Errorf("failed to read token: %w", err)
	}

	return strings.TrimSpace(string(tokenBytes)), nil
}

// DeleteToken removes the authentication token
func (tm *TokenManager) DeleteToken() error {
	if err := os.Remove(tm.tokenPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete token: %w", err)
	}
	return nil
}

// CheckPermissions verifies the token file has correct permissions
func (tm *TokenManager) CheckPermissions() error {
	info, err := os.Stat(tm.tokenPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // File doesn't exist yet, which is fine
		}
		return fmt.Errorf("failed to stat token file: %w", err)
	}

	// Check that file is only readable by owner
	mode := info.Mode()
	if mode&0077 != 0 {
		return fmt.Errorf("token file has insecure permissions %v (should be 0600)", mode.Perm())
	}

	return nil
}