package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

func parseSendArgs(args []string) (sendOptions, error) {
	fs := flag.NewFlagSet("send", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var client string
	var strict bool
	var forcePublic bool
	var autoUpdate bool
	var syncNow bool
	var noAutoSync bool
	var copyCommand bool
	var shareFormat string
	fs.StringVar(&client, "client", "", "Recipient client name for modern secure-pack adapter")
	fs.BoolVar(&strict, "strict", false, "Deny if no scanners are available in secure-scan JSON mode")
	fs.BoolVar(&forcePublic, "force-public", false, "Pass through secure-scan public repo guard")
	fs.BoolVar(&autoUpdate, "update", false, "Auto-update secure-scan definitions before scan")
	fs.BoolVar(&syncNow, "sync-now", false, "Force-sync local event spool to control plane after command")
	fs.BoolVar(&noAutoSync, "no-auto-sync", false, "Disable background auto-sync to control plane (events are only spooled locally unless sync is triggered)")
	fs.BoolVar(&copyCommand, "copy-command", false, "Copy receiver verify command to clipboard (macOS pbcopy preferred)")
	fs.StringVar(&shareFormat, "share-format", "ja", "Share text language for receiver hint: auto|ja|en")

	if err := fs.Parse(args); err != nil {
		return sendOptions{}, err
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return sendOptions{}, fmt.Errorf("Usage: zt send [--client <name>] [--strict] [--force-public] [--update] [--sync-now] [--no-auto-sync] [--copy-command] [--share-format auto|ja|en] <file>")
	}
	shareFormat = strings.ToLower(strings.TrimSpace(shareFormat))
	if shareFormat == "" {
		shareFormat = "ja"
	}
	if shareFormat != "auto" && shareFormat != "ja" && shareFormat != "en" {
		return sendOptions{}, fmt.Errorf("invalid --share-format: %q (expected auto, ja or en)", shareFormat)
	}
	return sendOptions{
		InputFile:   rest[0],
		Client:      client,
		Strict:      strict,
		ForcePublic: forcePublic,
		AutoUpdate:  autoUpdate,
		SyncNow:     syncNow,
		NoAutoSync:  noAutoSync,
		CopyCommand: copyCommand,
		ShareFormat: shareFormat,
	}, nil
}

func parseSetupArgs(args []string) (setupOptions, error) {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var opts setupOptions
	fs.BoolVar(&opts.JSON, "json", false, "Emit machine-readable JSON output")
	if err := fs.Parse(args); err != nil {
		return setupOptions{}, err
	}
	if len(fs.Args()) != 0 {
		return setupOptions{}, fmt.Errorf("Usage: zt setup [--json]")
	}
	return opts, nil
}

func parseScanArgs(args []string) (scanOptions, error) {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var opts scanOptions
	fs.BoolVar(&opts.TUI, "tui", false, "Force interactive scan (new secure-scan adapter)")
	fs.BoolVar(&opts.ForcePublic, "force-public", false, "Pass through secure-scan public repo guard")
	fs.BoolVar(&opts.AutoUpdate, "update", false, "Auto-update secure-scan definitions before scan")
	fs.BoolVar(&opts.Strict, "strict", false, "Deny if no scanners are available in secure-scan JSON mode")
	fs.BoolVar(&opts.NoAutoSync, "no-auto-sync", false, "Disable background auto-sync to control plane (events are only spooled locally unless sync is triggered)")

	if err := fs.Parse(args); err != nil {
		return scanOptions{}, err
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return scanOptions{}, fmt.Errorf("Usage: zt scan [--tui] [--force-public] [--update] [--strict] [--no-auto-sync] <path>")
	}
	opts.Target = rest[0]
	return opts, nil
}

func parseSyncArgs(args []string) (syncOptions, error) {
	fs := flag.NewFlagSet("sync", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var opts syncOptions
	fs.BoolVar(&opts.Force, "force", false, "Ignore next_retry_at and retry all pending events now")
	if err := fs.Parse(args); err != nil {
		return syncOptions{}, err
	}
	if len(fs.Args()) != 0 {
		return syncOptions{}, fmt.Errorf("Usage: zt sync [--force]")
	}
	return opts, nil
}

func parseVerifyArgs(args []string) (verifyOptions, error) {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var opts verifyOptions
	fs.BoolVar(&opts.SyncNow, "sync-now", false, "Force-sync local event spool to control plane after command")
	fs.BoolVar(&opts.NoAutoSync, "no-auto-sync", false, "Disable background auto-sync to control plane (events are only spooled locally unless sync is triggered)")
	if err := fs.Parse(args); err != nil {
		return verifyOptions{}, err
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return verifyOptions{}, fmt.Errorf("Usage: zt verify [--sync-now] [--no-auto-sync] <artifact_dir|packet.spkg.tgz>")
	}
	opts.ArtifactPath = rest[0]
	return opts, nil
}
