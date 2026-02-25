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
	var profile string
	var allowDegradedScan bool
	var strict bool
	var forcePublic bool
	var autoUpdate bool
	var syncNow bool
	var noAutoSync bool
	var copyCommand bool
	var shareJSON bool
	var shareFormat string
	var shareRoutes multiStringFlag
	fs.StringVar(&client, "client", "", "Recipient client name for modern secure-pack adapter")
	fs.StringVar(&profile, "profile", trustProfileInternal, "Trust profile: public|internal|confidential|regulated")
	fs.BoolVar(&allowDegradedScan, "allow-degraded-scan", false, "Allow degraded scan mode in zt send (unsafe): permit no-scanner-available allow result")
	fs.BoolVar(&strict, "strict", false, "Enable strict scan mode (default for zt send; kept for explicit/compat usage)")
	fs.BoolVar(&forcePublic, "force-public", false, "Pass through secure-scan public repo guard")
	fs.BoolVar(&autoUpdate, "update", false, "Auto-update secure-scan definitions before scan")
	fs.BoolVar(&syncNow, "sync-now", false, "Force-sync local event spool to control plane after command")
	fs.BoolVar(&noAutoSync, "no-auto-sync", false, "Disable background auto-sync to control plane (events are only spooled locally unless sync is triggered)")
	fs.BoolVar(&copyCommand, "copy-command", false, "Copy receiver verify command to clipboard (macOS pbcopy preferred)")
	fs.BoolVar(&shareJSON, "share-json", false, "Emit receiver share payload as JSON for share routes that support structured output")
	fs.StringVar(&shareFormat, "share-format", "auto", "Share text language for receiver hint: auto|ja|en (default: auto)")
	fs.Var(&shareRoutes, "share-route", "Additional share transport route: none | stdout | clipboard | file:<path> | command-file:<path> (repeatable)")

	if err := fs.Parse(args); err != nil {
		return sendOptions{}, err
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return sendOptions{}, fmt.Errorf("Usage: zt send --client <name> [--profile public|internal|confidential|regulated] [--strict | --allow-degraded-scan] [--force-public] [--update] [--sync-now] [--no-auto-sync] [--copy-command] [--share-json] [--share-format auto|ja|en] <file>")
	}
	if strings.TrimSpace(client) == "" {
		return sendOptions{}, fmt.Errorf("zt send requires --client <name> (legacy artifact.zp path was removed)")
	}
	profile, err := validateTrustProfile(profile)
	if err != nil {
		return sendOptions{}, err
	}
	if strict && allowDegradedScan {
		return sendOptions{}, fmt.Errorf("--strict and --allow-degraded-scan cannot be used together")
	}
	if isStrictTrustProfile(profile) && allowDegradedScan {
		return sendOptions{}, fmt.Errorf("--allow-degraded-scan is not allowed with --profile %s", profile)
	}
	shareFormat = strings.ToLower(strings.TrimSpace(shareFormat))
	if shareFormat == "" {
		shareFormat = "auto"
	}
	if shareFormat != "auto" && shareFormat != "ja" && shareFormat != "en" {
		return sendOptions{}, fmt.Errorf("invalid --share-format: %q (expected auto, ja or en)", shareFormat)
	}
	for _, raw := range shareRoutes.Values {
		if _, err := parseShareRoute(raw); err != nil {
			return sendOptions{}, fmt.Errorf("invalid --share-route %q: %w", raw, err)
		}
	}
	return sendOptions{
		InputFile:         rest[0],
		Client:            client,
		Profile:           profile,
		AllowDegradedScan: allowDegradedScan,
		Strict:            strict,
		ForcePublic:       forcePublic,
		AutoUpdate:        autoUpdate,
		SyncNow:           syncNow,
		NoAutoSync:        noAutoSync,
		CopyCommand:       copyCommand,
		ShareJSON:         shareJSON,
		ShareFormat:       shareFormat,
		ShareRoutes:       append([]string(nil), shareRoutes.Values...),
	}, nil
}

func parseSetupArgs(args []string) (setupOptions, error) {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var opts setupOptions
	fs.BoolVar(&opts.JSON, "json", false, "Emit machine-readable JSON output")
	fs.StringVar(&opts.Profile, "profile", trustProfileInternal, "Trust profile: public|internal|confidential|regulated")
	if err := fs.Parse(args); err != nil {
		return setupOptions{}, err
	}
	profile, err := validateTrustProfile(opts.Profile)
	if err != nil {
		return setupOptions{}, err
	}
	opts.Profile = profile
	if len(fs.Args()) != 0 {
		return setupOptions{}, fmt.Errorf("Usage: zt setup [--json] [--profile public|internal|confidential|regulated]")
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
	fs.StringVar(&opts.ReceiptOut, "receipt-out", "", "Write verification receipt JSON to file path")
	fs.BoolVar(&opts.SyncNow, "sync-now", false, "Force-sync local event spool to control plane after command")
	fs.BoolVar(&opts.NoAutoSync, "no-auto-sync", false, "Disable background auto-sync to control plane (events are only spooled locally unless sync is triggered)")
	if err := fs.Parse(args); err != nil {
		return verifyOptions{}, err
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return verifyOptions{}, fmt.Errorf("Usage: zt verify [--receipt-out <path>] [--sync-now] [--no-auto-sync] <packet.spkg.tgz>")
	}
	opts.ArtifactPath = rest[0]
	return opts, nil
}
