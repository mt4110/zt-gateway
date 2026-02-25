package main

import (
	"fmt"
	"os"

	"github.com/algo-artis/secure-pack/internal/config"
	"github.com/algo-artis/secure-pack/internal/ui"
	"github.com/algo-artis/secure-pack/internal/workflows"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
)

var (
	rootCmd = &cobra.Command{
		Use:   "secure-pack",
		Short: "Secure Pack: Secure file transfer tool",
		Long: `Secure Pack is a tool to securely encryption, sign, and package files 
for transfer over insecure channels like Slack.`,
		Run: func(cmd *cobra.Command, args []string) {
			// If no subcommands, run interactive UI
			runInteractive()
		},
	}
)

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		if code := workflows.ErrorCode(err); code != "" {
			fmt.Fprintf(os.Stderr, "SECURE_PACK_ERROR_CODE=%s\n", code)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runInteractive() {
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting CWD: %v\n", err)
		os.Exit(1)
	}

	cfg := config.NewConfig(cwd)
	p := tea.NewProgram(ui.InitialModel(cfg))
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
