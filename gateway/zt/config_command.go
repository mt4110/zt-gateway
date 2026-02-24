package main

import "fmt"

func runConfigCommand(repoRoot string, args []string) error {
	if len(args) == 0 {
		printZTErrorCode(ztErrorCodeConfigUsage)
		return fmt.Errorf("Usage: zt config doctor")
	}
	switch args[0] {
	case "doctor":
		return runConfigDoctor(repoRoot, args[1:])
	default:
		printZTErrorCode(ztErrorCodeConfigUnknownSubcmd)
		return fmt.Errorf("Unknown config subcommand: %s\nUsage: zt config doctor", args[0])
	}
}
