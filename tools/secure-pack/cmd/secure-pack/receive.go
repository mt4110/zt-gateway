package main

import (
	"fmt"
	"os"

	"github.com/algo-artis/secure-pack/internal/config"
	"github.com/algo-artis/secure-pack/internal/workflows"
	"github.com/spf13/cobra"
)

var (
	inputPath string
	outDir    string
)

func init() {
	receiveCmd.Flags().StringVarP(&inputPath, "in", "i", "", "Input packet path (*.spkg.tgz)")
	receiveCmd.Flags().StringVarP(&outDir, "out", "o", "", "Output directory")
	receiveCmd.MarkFlagRequired("in")
	rootCmd.AddCommand(receiveCmd)
}

var receiveCmd = &cobra.Command{
	Use:   "receive",
	Short: "Verify and extract files",
	RunE: func(cmd *cobra.Command, args []string) error {
		cwd, _ := os.Getwd()
		cfg := config.NewConfig(cwd)

		path, err := workflows.ReceiverWorkflow(cfg, inputPath, outDir)
		if err != nil {
			return err
		}
		fmt.Printf("Success: Extracted to %s\n", path)
		return nil
	},
}
