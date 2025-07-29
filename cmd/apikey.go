package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var apikeyCmd = &cobra.Command{
	Use:   "apikey",
	Short: "Manage API keys for role-based access control",
	Long:  `Generate and manage API keys with different roles (admin, operator, viewer) for secure API access.`,
}

var generateAPIKeyCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a new API key",
	RunE:  runGenerateAPIKey,
}

var listAPIKeysCmd = &cobra.Command{
	Use:   "list",
	Short: "List all API keys",
	RunE:  runListAPIKeys,
}

var revokeAPIKeyCmd = &cobra.Command{
	Use:   "revoke [key]",
	Short: "Revoke an API key",
	Args:  cobra.ExactArgs(1),
	RunE:  runRevokeAPIKey,
}

var (
	apiKeyRole       string
	apiKeyExpiration string
)

func init() {
	rootCmd.AddCommand(apikeyCmd)
	apikeyCmd.AddCommand(generateAPIKeyCmd)
	apikeyCmd.AddCommand(listAPIKeysCmd)
	apikeyCmd.AddCommand(revokeAPIKeyCmd)

	generateAPIKeyCmd.Flags().StringVarP(&apiKeyRole, "role", "r", "viewer", "Role for the API key (admin, operator, viewer)")
	generateAPIKeyCmd.Flags().StringVarP(&apiKeyExpiration, "expires", "e", "", "Expiration duration (e.g., 24h, 7d, 30d)")
}

// APIKeyStore manages persistent storage of API keys
type APIKeyStore struct {
	Keys map[string]*APIKeyInfo `json:"keys"`
}

type APIKeyInfo struct {
	Key         string    `json:"key"`
	Role        string    `json:"role"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
	Disabled    bool      `json:"disabled"`
	Description string    `json:"description,omitempty"`
}

func getAPIKeyStorePath() string {
	homeDir, _ := os.UserHomeDir()
	return filepath.Join(homeDir, ".dnshield", "api_keys.json")
}

func loadAPIKeyStore() (*APIKeyStore, error) {
	storePath := getAPIKeyStorePath()
	
	// Create directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(storePath), 0700); err != nil {
		return nil, fmt.Errorf("failed to create directory: %w", err)
	}
	
	// If file doesn't exist, return empty store
	if _, err := os.Stat(storePath); os.IsNotExist(err) {
		return &APIKeyStore{Keys: make(map[string]*APIKeyInfo)}, nil
	}
	
	data, err := os.ReadFile(storePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read API key store: %w", err)
	}
	
	var store APIKeyStore
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, fmt.Errorf("failed to parse API key store: %w", err)
	}
	
	if store.Keys == nil {
		store.Keys = make(map[string]*APIKeyInfo)
	}
	
	return &store, nil
}

func saveAPIKeyStore(store *APIKeyStore) error {
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal API key store: %w", err)
	}
	
	storePath := getAPIKeyStorePath()
	if err := os.WriteFile(storePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write API key store: %w", err)
	}
	
	return nil
}

func generateAPIKey() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		panic(err)
	}
	return hex.EncodeToString(bytes)
}

func runGenerateAPIKey(cmd *cobra.Command, args []string) error {
	// Validate role
	if apiKeyRole != "admin" && apiKeyRole != "operator" && apiKeyRole != "viewer" {
		return fmt.Errorf("invalid role: %s (must be admin, operator, or viewer)", apiKeyRole)
	}
	
	// Parse expiration
	var expiresAt time.Time
	if apiKeyExpiration != "" {
		duration, err := parseDuration(apiKeyExpiration)
		if err != nil {
			return fmt.Errorf("invalid expiration duration: %w", err)
		}
		expiresAt = time.Now().Add(duration)
	}
	
	// Generate new API key
	key := generateAPIKey()
	
	// Load store
	store, err := loadAPIKeyStore()
	if err != nil {
		return err
	}
	
	// Add key to store
	info := &APIKeyInfo{
		Key:       key,
		Role:      apiKeyRole,
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
		Disabled:  false,
	}
	store.Keys[key] = info
	
	// Save store
	if err := saveAPIKeyStore(store); err != nil {
		return err
	}
	
	// Display the key
	fmt.Printf("API Key generated successfully:\n\n")
	fmt.Printf("Key:  %s\n", key)
	fmt.Printf("Role: %s\n", apiKeyRole)
	if !expiresAt.IsZero() {
		fmt.Printf("Expires: %s\n", expiresAt.Format(time.RFC3339))
	}
	fmt.Printf("\nUse this key in the Authorization header:\n")
	fmt.Printf("Authorization: Bearer %s\n", key)
	fmt.Printf("\n⚠️  Save this key securely - it won't be displayed again\n")
	
	return nil
}

func runListAPIKeys(cmd *cobra.Command, args []string) error {
	store, err := loadAPIKeyStore()
	if err != nil {
		return err
	}
	
	if len(store.Keys) == 0 {
		fmt.Println("No API keys found")
		return nil
	}
	
	fmt.Printf("%-16s %-8s %-20s %-20s %-8s\n", "Key (first 16)", "Role", "Created", "Expires", "Status")
	fmt.Println(strings.Repeat("-", 80))
	
	for key, info := range store.Keys {
		keyPrefix := key[:16] + "..."
		status := "Active"
		if info.Disabled {
			status = "Disabled"
		} else if !info.ExpiresAt.IsZero() && time.Now().After(info.ExpiresAt) {
			status = "Expired"
		}
		
		expires := "Never"
		if !info.ExpiresAt.IsZero() {
			expires = info.ExpiresAt.Format("2006-01-02 15:04")
		}
		
		fmt.Printf("%-16s %-8s %-20s %-20s %-8s\n",
			keyPrefix,
			info.Role,
			info.CreatedAt.Format("2006-01-02 15:04"),
			expires,
			status,
		)
	}
	
	return nil
}

func runRevokeAPIKey(cmd *cobra.Command, args []string) error {
	keyToRevoke := args[0]
	
	store, err := loadAPIKeyStore()
	if err != nil {
		return err
	}
	
	// Find the key (allow partial match)
	var foundKey string
	for key := range store.Keys {
		if key == keyToRevoke || strings.HasPrefix(key, keyToRevoke) {
			if foundKey != "" {
				return fmt.Errorf("multiple keys match the prefix: %s", keyToRevoke)
			}
			foundKey = key
		}
	}
	
	if foundKey == "" {
		return fmt.Errorf("API key not found: %s", keyToRevoke)
	}
	
	// Mark as disabled instead of deleting
	store.Keys[foundKey].Disabled = true
	
	if err := saveAPIKeyStore(store); err != nil {
		return err
	}
	
	fmt.Printf("API key revoked: %s...\n", foundKey[:16])
	return nil
}

// parseDuration parses duration strings like "24h", "7d", "30d"
func parseDuration(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		days := s[:len(s)-1]
		var d int
		if _, err := fmt.Sscanf(days, "%d", &d); err != nil {
			return 0, err
		}
		return time.Duration(d) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}