package auth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTokenManager(t *testing.T) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()
	tokenPath := filepath.Join(tempDir, ".dnshield", ".dnshield_auth_token")
	
	tm := &TokenManager{
		tokenPath: tokenPath,
	}
	
	t.Run("GenerateToken", func(t *testing.T) {
		token, err := tm.GenerateToken()
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}
		
		if len(token) != tokenLength*2 { // Hex encoding doubles the length
			t.Errorf("Token length incorrect: got %d, want %d", len(token), tokenLength*2)
		}
		
		// Check file permissions
		info, err := os.Stat(tokenPath)
		if err != nil {
			t.Fatalf("Failed to stat token file: %v", err)
		}
		
		if info.Mode().Perm() != 0600 {
			t.Errorf("Token file has incorrect permissions: %v", info.Mode().Perm())
		}
	})
	
	t.Run("ValidateToken", func(t *testing.T) {
		// Generate a token first
		token, err := tm.GenerateToken()
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}
		
		// Test valid token
		if err := tm.ValidateToken(token); err != nil {
			t.Errorf("Valid token rejected: %v", err)
		}
		
		// Test invalid token
		if err := tm.ValidateToken("invalid-token"); err == nil {
			t.Error("Invalid token accepted")
		}
		
		// Test empty token
		if err := tm.ValidateToken(""); err == nil {
			t.Error("Empty token accepted")
		}
	})
	
	t.Run("GetToken", func(t *testing.T) {
		// Generate a token first
		expectedToken, err := tm.GenerateToken()
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}
		
		// Get the token
		token, err := tm.GetToken()
		if err != nil {
			t.Fatalf("Failed to get token: %v", err)
		}
		
		if token != expectedToken {
			t.Errorf("Token mismatch: got %s, want %s", token, expectedToken)
		}
	})
	
	t.Run("DeleteToken", func(t *testing.T) {
		// Generate a token first
		_, err := tm.GenerateToken()
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}
		
		// Delete the token
		if err := tm.DeleteToken(); err != nil {
			t.Fatalf("Failed to delete token: %v", err)
		}
		
		// Verify file is gone
		if _, err := os.Stat(tokenPath); !os.IsNotExist(err) {
			t.Error("Token file still exists after deletion")
		}
		
		// Delete non-existent token should not error
		if err := tm.DeleteToken(); err != nil {
			t.Errorf("Deleting non-existent token returned error: %v", err)
		}
	})
	
	t.Run("CheckPermissions", func(t *testing.T) {
		// Generate a token
		_, err := tm.GenerateToken()
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}
		
		// Permissions should be correct
		if err := tm.CheckPermissions(); err != nil {
			t.Errorf("CheckPermissions failed on correctly permissioned file: %v", err)
		}
		
		// Change permissions to be insecure
		if err := os.Chmod(tokenPath, 0644); err != nil {
			t.Fatalf("Failed to change permissions: %v", err)
		}
		
		// Should now fail
		if err := tm.CheckPermissions(); err == nil {
			t.Error("CheckPermissions did not detect insecure permissions")
		}
	})
}