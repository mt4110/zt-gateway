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
	fmt.Println("  verify <packet>             - Verify received packet")
	fmt.Println("  doctor                      - Validate local config resolution")
	fmt.Println("")
	fmt.Println("Help:")
	fmt.Println("  zt --help-advanced          - Show all commands/flags")
}

func printAdvancedUsage() {
	fmt.Println("Usage: zt <command> [args]")
	fmt.Println("Commands:")
	fmt.Println("  setup [--json] [--profile public|internal|confidential|regulated] - One-command local setup checks")
	fmt.Println("  send --client <name> [--profile public|internal|confidential|regulated] [--strict | --allow-degraded-scan] [--force-public] [--update] [--sync-now] [--no-auto-sync] [--copy-command] [--share-json] [--share-format auto|ja|en] [--share-route none|stdout|clipboard|file:<path>|command-file:<path>] <file>")
	fmt.Println("                                                     - Scan, sanitize and package a file")
	fmt.Println("  scan [--tui] [--force-public] [--update] [--strict] [--no-auto-sync] <path>")
	fmt.Println("                                                     - Risk assessment")
	fmt.Println("  verify [--receipt-out <path>] [--sync-now] [--no-auto-sync] <packet.spkg.tgz>")
	fmt.Println("                                                     - Verify artifact or packet")
	fmt.Println("  sync [--force]                                     - Retry sending locally spooled events")
	fmt.Println("  config doctor [--json]                             - Validate zt client config/env resolution")
	fmt.Println("  doctor [--json]                                    - Alias of `zt config doctor`")
	fmt.Println("  help [advanced]                                    - Show help")
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
