package main

import (
	"fmt"
	"os"

	"github.com/algo-artis/secure-pack/internal/config"
	"github.com/algo-artis/secure-pack/internal/workflows"
	"github.com/spf13/cobra"
)

var (
	clientName string
)

func init() {
	sendCmd.Flags().StringVarP(&clientName, "client", "c", "", "Client name (recipient)")
	sendCmd.MarkFlagRequired("client")
	rootCmd.AddCommand(sendCmd)
}

var sendCmd = &cobra.Command{
	Use:   "send",
	Short: "Encrypt and sign files",
	RunE: func(cmd *cobra.Command, args []string) error {
		cwd, _ := os.Getwd()
		cfg := config.NewConfig(cwd) // TODO: Allow config via flags?

		path, err := workflows.SenderWorkflow(cfg, clientName)
		if err != nil {
			return err
		}
		fmt.Printf("Success: %s\n", path)
		return nil
	},
}
