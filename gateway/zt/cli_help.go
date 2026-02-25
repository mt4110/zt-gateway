package main

import (
	"fmt"
)

func printUsage() {
	fmt.Println(cliUsageRoot)
	fmt.Println("")
	fmt.Println("Start here:")
	fmt.Println("  setup                       - Check local config/tools/key env/control-plane reachability")
	fmt.Println("  send --client <name> <file> - Scan -> sanitize -> pack")
	fmt.Println("  verify <packet.spkg.tgz>    - Verify received packet")
	fmt.Println("  doctor                      - Validate local config resolution")
	fmt.Println("")
	fmt.Println("Help:")
	fmt.Println("  zt --help-advanced          - Show all commands/flags")
}

func printAdvancedUsage() {
	fmt.Println(cliUsageRoot)
	fmt.Println("Commands:")
	fmt.Printf("  %s - One-command local setup checks\n", cliSetupSignature)
	fmt.Printf("  %s - Scan, sanitize and package a file\n", cliSendSignature)
	fmt.Printf("  %s - Risk assessment\n", cliScanSignature)
	fmt.Printf("  %s - Verify artifact or packet\n", cliVerifySignature)
	fmt.Printf("  %s - Retry sending locally spooled events\n", cliSyncSignature)
	fmt.Printf("  %s - Validate zt client config/env resolution\n", cliConfigSignature)
	fmt.Printf("  %s - Alias of `zt config doctor`\n", cliDoctorSignature)
	fmt.Printf("  %s - Show help\n", cliHelpSignature)
	fmt.Println("")
	fmt.Println("Notes:")
	fmt.Println("  - Add `--copy-command` to copy the receiver `zt verify ...` command to clipboard.")
	fmt.Println("  - `--share-format` defaults to `auto` (Japanese locale -> ja, otherwise en).")
	fmt.Println("  - Add `--share-format en` (or `ja`) to force receiver share text language.")
	fmt.Println("  - Add `--share-route none` to suppress the default stdout share hint.")
	fmt.Println("  - Add `--share-route file:/tmp/share.txt` or `command-file:/tmp/verify.sh` (repeatable) to fan out share output.")
	fmt.Println("  - Add `--share-json` to emit structured share payload JSON (stdout/file routes).")
	fmt.Println("  - Add `--profile` to select trust posture presets (`internal` by default).")
	fmt.Println("  - `zt send` uses strict scan mode by default; add `--allow-degraded-scan` only for explicit local/degraded runs.")
	fmt.Println("  - `send --client <name>` uses the new secure-pack adapter (spkg.tgz output).")
	fmt.Println("  - Legacy `artifact.zp` send/verify path has been removed; use `*.spkg.tgz` only.")
}

func shouldPrintHelp(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "-h", "--help":
		return true
	default:
		return false
	}
}

func shouldPrintAdvancedHelp(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "--help-advanced":
		return true
	default:
		return false
	}
}
