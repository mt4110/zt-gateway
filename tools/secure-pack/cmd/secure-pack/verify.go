package main

import (
	"fmt"

	"github.com/algo-artis/secure-pack/internal/workflows"
	"github.com/spf13/cobra"
)

var verifyInputPath string

func init() {
	verifyCmd.Flags().StringVarP(&verifyInputPath, "in", "i", "", "Input packet path (*.spkg.tgz)")
	verifyCmd.MarkFlagRequired("in")
	rootCmd.AddCommand(verifyCmd)
}

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify signature and integrity only",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := workflows.VerifyWorkflow(verifyInputPath); err != nil {
			return err
		}
		fmt.Println("OK: Signature and checksum verified.")
		return nil
	},
}
