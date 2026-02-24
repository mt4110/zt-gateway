package main

import (
	"fmt"
)

func printUsage() {
	fmt.Println("Usage: zt <command> [args]")
	fmt.Println("")
	fmt.Println("Start here:")
	fmt.Println("  setup                       - Check local config/tools/key env/control-plane reachability")
	fmt.Println("  send <file>                 - Scan -> sanitize -> pack")
	fmt.Println("  verify <artifact|packet>    - Verify received artifact/packet")
	fmt.Println("  doctor                      - Validate local config resolution")
	fmt.Println("")
	fmt.Println("Help:")
	fmt.Println("  zt --help-advanced          - Show all commands/flags")
}

func printAdvancedUsage() {
	fmt.Println("Usage: zt <command> [args]")
	fmt.Println("Commands:")
	fmt.Println("  setup [--json]                                      - One-command local setup checks")
	fmt.Println("  send [--client <name>] [--strict] [--force-public] [--update] [--sync-now] [--no-auto-sync] [--copy-command] [--share-format auto|ja|en] <file>")
	fmt.Println("                                                     - Scan, sanitize and package a file")
	fmt.Println("  scan [--tui] [--force-public] [--update] [--strict] [--no-auto-sync] <path>")
	fmt.Println("                                                     - Risk assessment")
	fmt.Println("  verify [--sync-now] [--no-auto-sync] <artifact_dir|packet.spkg.tgz>")
	fmt.Println("                                                     - Verify artifact or packet")
	fmt.Println("  sync [--force]                                     - Retry sending locally spooled events")
	fmt.Println("  config doctor [--json]                             - Validate zt client config/env resolution")
	fmt.Println("  doctor [--json]                                    - Alias of `zt config doctor`")
	fmt.Println("  help [advanced]                                    - Show help")
	fmt.Println("")
	fmt.Println("Notes:")
	fmt.Println("  - Add `--copy-command` to copy the receiver `zt verify ...` command to clipboard.")
	fmt.Println("  - Add `--share-format en` (or `auto`) to switch receiver share text language.")
	fmt.Println("  - `send --client <name>` uses the new secure-pack adapter (spkg.tgz output).")
	fmt.Println("  - `send` without --client falls back to the archived PoC secure-pack (artifact.zp output).")
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
