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
		signerFingerprint, err := workflows.VerifyWorkflowWithSigner(verifyInputPath)
		if err != nil {
			return err
		}
		fmt.Printf("SIGNER_FINGERPRINT=%s\n", signerFingerprint)
		fmt.Println("OK: Signature and checksum verified.")
		return nil
	},
}
