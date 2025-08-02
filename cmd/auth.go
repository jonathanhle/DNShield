package cmd

import (
	"fmt"
	
	"github.com/spf13/cobra"
	"dnshield/internal/auth"
)

// NewAuthCmd creates the auth command
func NewAuthCmd() *cobra.Command {
	authCmd := &cobra.Command{
		Use:   "auth",
		Short: "Manage authentication for DNShield commands",
		Long:  `Generate and manage authentication tokens for sensitive DNShield operations.`,
	}

	authGenerateCmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate a new authentication token",
		Long:  `Generate a new authentication token for DNShield commands that require authentication.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			tm := auth.NewTokenManager()
			
			// Check permissions first
			if err := tm.CheckPermissions(); err != nil {
				return fmt.Errorf("security check failed: %w", err)
			}
			
			token, err := tm.GenerateToken()
			if err != nil {
				return fmt.Errorf("failed to generate token: %w", err)
			}
			
			fmt.Println("Authentication token generated successfully:")
			fmt.Printf("Token: %s\n", token)
			fmt.Println("\nStore this token securely. You'll need it for privileged operations.")
			fmt.Println("The token is also saved in ~/.dnshield/.dnshield_auth_token")
			
			return nil
		},
	}

	authShowCmd := &cobra.Command{
		Use:   "show",
		Short: "Display the current authentication token",
		Long:  `Show the current authentication token if one exists.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			tm := auth.NewTokenManager()
			
			token, err := tm.GetToken()
			if err != nil {
				return fmt.Errorf("failed to read token: %w", err)
			}
			
			fmt.Printf("Current token: %s\n", token)
			
			return nil
		},
	}

	authRevokeCmd := &cobra.Command{
		Use:   "revoke",
		Short: "Revoke the current authentication token",
		Long:  `Delete the current authentication token, requiring generation of a new one.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			tm := auth.NewTokenManager()
			
			if err := tm.DeleteToken(); err != nil {
				return fmt.Errorf("failed to revoke token: %w", err)
			}
			
			fmt.Println("Authentication token revoked successfully.")
			
			return nil
		},
	}

	authCmd.AddCommand(authGenerateCmd)
	authCmd.AddCommand(authShowCmd)
	authCmd.AddCommand(authRevokeCmd)
	
	return authCmd
}