package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	
	"github.com/spf13/cobra"
	"dnshield/internal/api"
)

// NewAPITokenCmd creates the api-token command
func NewAPITokenCmd() *cobra.Command {
	apiTokenCmd := &cobra.Command{
		Use:   "api-token",
		Short: "Manage API authentication tokens",
		Long:  `Generate and manage authentication tokens for the DNShield API.`,
	}

	generateCmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate a new API authentication token",
		Long: `Generate a new authentication token for the DNShield API.
This token is required for accessing protected API endpoints.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			tm := api.NewAPITokenManager()
			
			token, err := tm.GenerateToken()
			if err != nil {
				return fmt.Errorf("failed to generate API token: %w", err)
			}
			
			fmt.Println("API authentication token generated successfully:")
			fmt.Printf("Token: %s\n", token)
			fmt.Println("\nUse this token in the Authorization header:")
			fmt.Printf("Authorization: Bearer %s\n", token)
			fmt.Println("\nThe token is saved in ~/.dnshield/.dnshield_api_token")
			
			return nil
		},
	}

	showCmd := &cobra.Command{
		Use:   "show",
		Short: "Display the current API authentication token",
		Long:  `Show the current API authentication token if one exists.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			tm := api.NewAPITokenManager()
			
			if err := tm.LoadToken(); err != nil {
				return fmt.Errorf("failed to load token: %w", err)
			}
			
			// Get the token from the file directly since we don't expose it from the manager
			token, err := readTokenFromFile()
			if err != nil {
				return fmt.Errorf("failed to read token: %w", err)
			}
			
			fmt.Printf("Current API token: %s\n", token)
			fmt.Println("\nUse this token in the Authorization header:")
			fmt.Printf("Authorization: Bearer %s\n", token)
			
			return nil
		},
	}

	apiTokenCmd.AddCommand(generateCmd)
	apiTokenCmd.AddCommand(showCmd)
	
	return apiTokenCmd
}

// Helper function to read token from file
func readTokenFromFile() (string, error) {
	// Read directly from the known token location
	homeDir, _ := os.UserHomeDir()
	tokenPath := filepath.Join(homeDir, ".dnshield", ".dnshield_api_token")
	
	tokenBytes, err := os.ReadFile(tokenPath)
	if err != nil {
		return "", err
	}
	
	return strings.TrimSpace(string(tokenBytes)), nil
}