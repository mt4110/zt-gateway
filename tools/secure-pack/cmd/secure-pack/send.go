package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/algo-artis/secure-pack/internal/config"
	"github.com/algo-artis/secure-pack/internal/workflows"
	"github.com/spf13/cobra"
)

var (
	clientName     string
	sendBaseDir    string
	sendOutDir     string
	sendRecipients string
	sendToolsLock  string
	sendRootPubKey string
)

func init() {
	sendCmd.Flags().StringVarP(&clientName, "client", "c", "", "Client name (recipient)")
	sendCmd.Flags().StringVar(&sendBaseDir, "base-dir", "", "Base directory for secure-pack assets (default: current working directory)")
	sendCmd.Flags().StringVar(&sendOutDir, "out-dir", "", "Override output directory for generated packets")
	sendCmd.Flags().StringVar(&sendRecipients, "recipients-dir", "", "Override recipients directory")
	sendCmd.Flags().StringVar(&sendToolsLock, "tools-lock", "", "Override tools.lock path")
	sendCmd.Flags().StringVar(&sendRootPubKey, "root-pubkey", "", "Override ROOT_PUBKEY.asc path")
	sendCmd.MarkFlagRequired("client")
	rootCmd.AddCommand(sendCmd)
}

var sendCmd = &cobra.Command{
	Use:   "send",
	Short: "Encrypt and sign files",
	RunE: func(cmd *cobra.Command, args []string) error {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("resolve working directory: %w", err)
		}
		cfg, err := buildSendConfig(cwd)
		if err != nil {
			return err
		}

		path, err := workflows.SenderWorkflow(cfg, clientName)
		if err != nil {
			return err
		}
		fmt.Printf("Success: %s\n", path)
		return nil
	},
}

func buildSendConfig(cwd string) (*config.Config, error) {
	baseDir := strings.TrimSpace(cwd)
	if strings.TrimSpace(sendBaseDir) != "" {
		baseDir = strings.TrimSpace(sendBaseDir)
	}
	if strings.TrimSpace(baseDir) == "" {
		return nil, fmt.Errorf("base directory is empty")
	}
	absBaseDir, err := filepath.Abs(baseDir)
	if err != nil {
		return nil, fmt.Errorf("resolve base directory: %w", err)
	}
	cfg := config.NewConfig(absBaseDir)

	if strings.TrimSpace(sendRecipients) != "" {
		cfg.RecipientsDir = resolveSendPath(absBaseDir, sendRecipients)
	}
	if strings.TrimSpace(sendOutDir) != "" {
		cfg.OutDir = resolveSendPath(absBaseDir, sendOutDir)
	}
	if strings.TrimSpace(sendToolsLock) != "" {
		cfg.ToolsLock = resolveSendPath(absBaseDir, sendToolsLock)
	}
	if strings.TrimSpace(sendRootPubKey) != "" {
		cfg.RootPubKey = resolveSendPath(absBaseDir, sendRootPubKey)
	}
	return cfg, nil
}

func resolveSendPath(baseDir, raw string) string {
	v := strings.TrimSpace(raw)
	if v == "" {
		return ""
	}
	if filepath.IsAbs(v) {
		return filepath.Clean(v)
	}
	return filepath.Clean(filepath.Join(baseDir, v))
}
