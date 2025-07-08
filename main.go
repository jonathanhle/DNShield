package main

import (
	"fmt"
	"os"

	"dns-guardian/cmd"
	
	"github.com/spf13/cobra"
)

var (
	version = "1.0.0"
	cfgFile string
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "dns-guardian",
		Short: "Enterprise DNS filtering agent with HTTPS interception",
		Long: `DNS Guardian is a native macOS DNS filtering solution that combines
DNS blocking with dynamic HTTPS certificate generation to show custom
block pages without certificate warnings.`,
	}

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is ./config.yaml)")

	// Add subcommands
	rootCmd.AddCommand(
		newRunCmd(),
		newInstallCACmd(),
		newUninstallCmd(),
		newStatusCmd(),
		newUpdateRulesCmd(),
		newVersionCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func newRunCmd() *cobra.Command {
	return cmd.NewRunCmd()
}

func newInstallCACmd() *cobra.Command {
	return cmd.NewInstallCACmd()
}

func newUninstallCmd() *cobra.Command {
	return cmd.NewUninstallCmd()
}

func newStatusCmd() *cobra.Command {
	return cmd.NewStatusCmd()
}

func newUpdateRulesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "update-rules",
		Short: "Force update blocking rules from S3",
		Long:  `Manually trigger an update of blocking rules from the configured S3 bucket.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// We need to create a separate implementation for this
			// For now, return a helpful message
			fmt.Println("📥 Updating rules from S3...")
			fmt.Println()
			fmt.Println("Note: In the current version, rules are updated automatically")
			fmt.Println("when the service starts and at the configured interval.")
			fmt.Println()
			fmt.Println("To force an update:")
			fmt.Println("1. Restart the service: sudo ./dns-guardian run")
			fmt.Println("2. Or wait for the next automatic update")
			fmt.Println()
			fmt.Println("Manual rule updates will be implemented in v1.1.0")
			return nil
		},
	}
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("DNS Guardian v%s\n", version)
		},
	}
}