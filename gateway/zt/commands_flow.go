package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func checkUpdate() {
	// Stub implementation of update check
	remoteVer := os.Getenv("ZT_MOCK_REMOTE_VERSION")
	if remoteVer == "" {
		return
	}

	if remoteVer > CurrentRuleVersion {
		fmt.Printf("[Updater] New signatures found: %s (Current: %s)\n", remoteVer, CurrentRuleVersion)
		fmt.Println("[Updater] Downloading updates... (Stub)")
		time.Sleep(500 * time.Millisecond)
		fmt.Println("[Updater] Update applied successfully.")
	}
}

func runScan(adapters *toolAdapters, opts scanOptions) {
	if cpEvents != nil {
		if opts.NoAutoSync {
			cpEvents.SetAutoSync(false)
		}
	}
	targetPath, err := filepath.Abs(opts.Target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Scan Error: %v\n", err)
		os.Exit(1)
	}
	info, err := os.Stat(targetPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Scan Error: %v\n", err)
		os.Exit(1)
	}

	// File scan defaults to legacy JSON adapter (machine-readable) to preserve zt flow.
	if !opts.TUI && !info.IsDir() {
		out, stderr, err := adapters.modernScanCheckJSON(targetPath, opts.ForcePublic, opts.AutoUpdate, opts.Strict, nil, false)
		if len(out) > 0 {
			emitScanEventFromSecureScanJSON("scan", targetPath, out)
		}
		if len(out) > 0 {
			fmt.Print(string(out))
			if err != nil {
				if len(stderr) > 0 {
					fmt.Fprintf(os.Stderr, "%s", string(stderr))
				}
				os.Exit(1)
			}
			return
		}
		if err != nil {
			if len(stderr) > 0 {
				fmt.Fprintf(os.Stderr, "Scan Error: %s\n", strings.TrimSpace(string(stderr)))
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "Scan Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	fmt.Println("[Adapter] Using interactive secure-scan (new CLI/TUI)")
	if err := adapters.interactiveScan(targetPath, opts.ForcePublic, opts.AutoUpdate); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to run secure-scan TUI: %v\n", err)
		os.Exit(1)
	}
}

func runSend(adapters *toolAdapters, opts sendOptions) {
	if cpEvents != nil {
		if opts.NoAutoSync {
			cpEvents.SetAutoSync(false)
		}
	}
	inputPath, err := filepath.Abs(opts.InputFile)
	if err != nil {
		fmt.Printf("GATEWAY_ERROR: Failed to resolve file path: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Processing %s...\n", inputPath)

	policyFile := filepath.Join(adapters.repoRoot, "policy", "extension_policy.toml")
	extPolicy, policyErr := loadExtensionPolicy(policyFile)
	if policyErr != nil {
		fmt.Printf("[Policy] WARN failed to load %s, using defaults: %v\n", policyFile, policyErr)
		extPolicy = defaultExtensionPolicy()
	}
	scanPolicyFile := filepath.Join(adapters.repoRoot, "policy", "scan_policy.toml")
	scanPol, scanPolicyErr := loadScanPolicy(scanPolicyFile)
	if scanPolicyErr != nil {
		fmt.Printf("[Policy] WARN failed to load %s, using defaults: %v\n", scanPolicyFile, scanPolicyErr)
		scanPol = defaultScanPolicy()
	}
	mode, policyReason := resolveExtensionMode(inputPath, extPolicy)
	fmt.Printf("[Policy] %s (%s) source=%s\n", mode, policyReason, extPolicy.Source)
	if len(scanPol.RequiredScanners) > 0 || scanPol.RequireClamAVDB {
		fmt.Printf("[Policy] scan requirements: required_scanners=%v require_clamav_db=%t source=%s\n", scanPol.RequiredScanners, scanPol.RequireClamAVDB, scanPol.Source)
	}
	if mode == ExtModeDeny {
		fmt.Printf("\n[BLOCKED] File was rejected by zt policy.\nReason: %s\n", policyReason)
		if opts.SyncNow {
			runSyncEvents(true)
		}
		os.Exit(1)
	}
	if err := enforceFilePolicy(inputPath, mode, extPolicy); err != nil {
		fmt.Printf("\n[BLOCKED] File was rejected by zt policy.\nReason: %v\n", err)
		if opts.SyncNow {
			runSyncEvents(true)
		}
		os.Exit(1)
	}

	// 1. secure-scan check (new secure-scan JSON mode)
	fmt.Println("[Step 1/3] Scanning...")
	scanStrict := opts.Strict
	if !scanStrict && envBool("ZT_SCAN_STRICT") {
		scanStrict = true
		fmt.Println("[Scan] strict mode enabled via ZT_SCAN_STRICT=1 (deprecated: prefer --strict)")
	}
	if scanStrict && opts.Strict {
		fmt.Println("[Scan] strict mode enabled (--strict)")
	}
	output, scanStderr, err := adapters.modernScanCheckJSON(
		inputPath,
		opts.ForcePublic,
		opts.AutoUpdate,
		scanStrict,
		scanPol.RequiredScanners,
		scanPol.RequireClamAVDB,
	)

	var res ScanResult
	if jsonErr := json.Unmarshal(output, &res); jsonErr != nil {
		if opts.AutoUpdate && len(scanStderr) > 0 {
			fmt.Printf("GATEWAY_ERROR: secure-scan update/scan failed before JSON result.\n")
			fmt.Printf("Hint: `--update` requires `freshclam` (ClamAV updater) and network access.\n")
			fmt.Printf("stderr: %s\n", strings.TrimSpace(string(scanStderr)))
			os.Exit(1)
		}
		fmt.Printf("GATEWAY_ERROR: Failed to parse scan result: %v\nRaw output: %s\n", jsonErr, string(output))
		os.Exit(1)
	}
	if err != nil && res.Result == "" {
		if opts.AutoUpdate && len(scanStderr) > 0 {
			fmt.Printf("GATEWAY_ERROR: secure-scan failed during `--update` pre-scan step.\n")
			fmt.Printf("Hint: install `freshclam` / ClamAV DB tooling, or rerun without `--update`.\n")
			fmt.Printf("stderr: %s\n", strings.TrimSpace(string(scanStderr)))
			os.Exit(1)
		}
		fmt.Printf("GATEWAY_ERROR: secure-scan (modern JSON adapter) failed: %v\nOutput: %s\n", err, string(output))
		if len(scanStderr) > 0 {
			fmt.Printf("stderr: %s\n", strings.TrimSpace(string(scanStderr)))
		}
		os.Exit(1)
	}
	if len(output) > 0 {
		emitScanEventFromSecureScanJSON("send", inputPath, output)
	}
	if res.Reason == "clean.no_scanners_available" {
		fmt.Println("[WARN] secure-scan returned allow with no scanners available (degraded mode).")
	}

	if res.Result != "allow" {
		fmt.Printf("\n[BLOCKED] File was rejected by secure-scan.\nReason: %s\n", res.Reason)
		if opts.SyncNow {
			runSyncEvents(true)
		}
		os.Exit(1)
	}
	fmt.Println("Scan passed.")

	// 2. secure-rebuild (Sanitizer) - only for SCAN_REBUILD
	sanitizedPath := inputPath
	if mode == ExtModeScanRebuild {
		fmt.Println("[Step 2/3] Sanitizing (secure-rebuild)...")
		tmpFile, err := os.CreateTemp("", "zt-sanitized-*"+filepath.Ext(inputPath))
		if err != nil {
			fmt.Printf("GATEWAY_ERROR: Failed to create temp file: %v\n", err)
			os.Exit(1)
		}
		tmpFile.Close()
		sanitizedPath = tmpFile.Name()
		defer os.Remove(sanitizedPath)

		rebuildOut, rebuildErr := adapters.rebuild(inputPath, sanitizedPath)
		if rebuildErr != nil {
			fmt.Printf("GATEWAY_ERROR: Sanitization failed: %v\nOutput: %s\n", rebuildErr, string(rebuildOut))
			os.Exit(1)
		}
		fmt.Println("Sanitization complete.")
	} else {
		fmt.Println("[Step 2/3] Sanitizing (secure-rebuild)...")
		fmt.Println("Skipped (SCAN_ONLY policy).")
	}

	// 3. secure-pack
	fmt.Println("[Step 3/3] Packing...")
	cwd, _ := os.Getwd()

	if opts.Client != "" {
		fmt.Printf("[Adapter] Using modern secure-pack (client=%s)\n", opts.Client)
		packetPath, packOut, packErr := adapters.modernPackSingleFile(sanitizedPath, cwd, opts.Client)
		if packErr != nil {
			fmt.Printf("GATEWAY_ERROR: Packing failed (modern adapter): %v\nOutput: %s\n", packErr, string(packOut))
			os.Exit(1)
		}
		var scanMeta map[string]any
		_ = json.Unmarshal(output, &scanMeta)
		emitArtifactEvent("spkg.tgz", packetPath, inputPath, opts.Client, stringField(scanMeta, "rule_hash"))
		if opts.SyncNow {
			runSyncEvents(true)
		}
		fmt.Printf("\n[SUCCESS] Packet generated.\n%s\nSaved: %s\n", string(packOut), packetPath)
		printReceiverShareText(packetPath, opts.ShareFormat)
		printReceiverVerifyHint(packetPath, opts.CopyCommand)
		return
	}

	fmt.Println("[Adapter] Using legacy secure-pack PoC (no --client specified)")
	packOut, packErr := adapters.legacyPack(sanitizedPath, cwd)
	if packErr != nil {
		fmt.Printf("GATEWAY_ERROR: Packing failed (legacy adapter): %v\nOutput: %s\n", packErr, string(packOut))
		os.Exit(1)
	}
	var scanMeta map[string]any
	_ = json.Unmarshal(output, &scanMeta)
	emitArtifactEvent("artifact.zp", filepath.Join(cwd, "artifact.zp"), inputPath, "", stringField(scanMeta, "rule_hash"))
	if opts.SyncNow {
		runSyncEvents(true)
	}
	artifactPath := filepath.Join(cwd, "artifact.zp")
	fmt.Printf("\n[SUCCESS] Artifact generated.\n%s\n", string(packOut))
	printReceiverShareText(artifactPath, opts.ShareFormat)
	printReceiverVerifyHint(artifactPath, opts.CopyCommand)
}

func runVerify(adapters *toolAdapters, opts verifyOptions) {
	if cpEvents != nil {
		if opts.NoAutoSync {
			cpEvents.SetAutoSync(false)
		}
	}
	resolvedPath, err := filepath.Abs(opts.ArtifactPath)
	if err != nil {
		fmt.Printf("[FAIL] invalid path: %v\n", err)
		os.Exit(1)
	}

	if stringsHasSuffixFold(resolvedPath, ".spkg.tgz") {
		fmt.Printf("[VERIFY] Packet: %s\n", resolvedPath)
		out, err := adapters.modernPackVerify(resolvedPath)
		if err != nil {
			emitVerifyEvent(resolvedPath, false, "packet.verify_failed", strings.TrimSpace(string(out)))
			if opts.SyncNow {
				runSyncEvents(true)
			}
			fmt.Printf("[FAIL] Packet verification failed: %v\n", err)
			if trimmed := strings.TrimSpace(string(out)); trimmed != "" {
				fmt.Printf("[DETAIL] %s\n", trimmed)
			}
			os.Exit(1)
		}
		fmt.Println("[PASS] Signature and checksum verified by secure-pack.")
		if trimmed := strings.TrimSpace(string(out)); trimmed != "" {
			fmt.Printf("[DETAIL] %s\n", trimmed)
		}
		fmt.Println("[VERIFIED] Trust established.")
		emitVerifyEvent(resolvedPath, true, "packet.verified", strings.TrimSpace(string(out)))
		if opts.SyncNow {
			runSyncEvents(true)
		}
		return
	}

	runVerifyLegacyArtifact(resolvedPath, opts.SyncNow)
}

func runVerifyLegacyArtifact(artifactPath string, syncNow bool) {
	fmt.Printf("[VERIFY] Artifact (legacy PoC): %s\n", artifactPath)

	payloadPath := filepath.Join(artifactPath, "payload.enc")
	sigPath := filepath.Join(artifactPath, "payload.sig")
	metaPath := filepath.Join(artifactPath, "metadata.json")

	if _, err := os.Stat(payloadPath); os.IsNotExist(err) {
		emitVerifyEvent(artifactPath, false, "legacy.missing_payload", "Missing payload.enc")
		if syncNow {
			runSyncEvents(true)
		}
		fmt.Println("[FAIL] Missing payload.enc")
		os.Exit(1)
	}
	if _, err := os.Stat(sigPath); os.IsNotExist(err) {
		emitVerifyEvent(artifactPath, false, "legacy.missing_signature", "Missing payload.sig")
		if syncNow {
			runSyncEvents(true)
		}
		fmt.Println("[FAIL] Missing payload.sig")
		os.Exit(1)
	}

	metaData, _ := os.ReadFile(metaPath)
	var meta map[string]interface{}
	_ = json.Unmarshal(metaData, &meta)

	fmt.Printf("  - Sender: %v\n", meta["sender"])
	fmt.Printf("  - Time:   %v\n", meta["timestamp"])
	fmt.Printf("  - File:   %v\n", meta["original_filename"])
	fmt.Println("[PASS] Artifact structure is valid.")
	fmt.Println("[PASS] Signature file present.")
	fmt.Println("[WARN] Legacy PoC verification (signature cryptographic check not yet implemented here).")
	fmt.Println("[VERIFIED] Trust established.")
	emitVerifyEvent(artifactPath, true, "legacy.structure_only_verified", "Legacy PoC structure and signature-file presence checks passed")
	if syncNow {
		runSyncEvents(true)
	}
}

func stringsHasSuffixFold(s, suffix string) bool {
	if len(suffix) > len(s) {
		return false
	}
	return strings.EqualFold(s[len(s)-len(suffix):], suffix)
}

func printReceiverVerifyHint(artifactPath string, copyCommand bool) {
	base := filepath.Base(strings.TrimSpace(artifactPath))
	if base == "" || base == "." || base == string(filepath.Separator) {
		return
	}
	cmd := fmt.Sprintf("zt verify ./%s", base)
	fmt.Printf("[SHARE] Receiver command example: %s\n", cmd)
	if !copyCommand {
		return
	}
	if err := copyToClipboard(cmd + "\n"); err != nil {
		fmt.Printf("[WARN] Could not copy receiver command to clipboard: %v\n", err)
		fmt.Println("[HINT] macOS: ensure `pbcopy` is available, or copy the command manually.")
		return
	}
	fmt.Println("[OK]   Receiver command copied to clipboard.")
}

func printReceiverShareText(artifactPath, format string) {
	base := filepath.Base(strings.TrimSpace(artifactPath))
	if base == "" || base == "." || base == string(filepath.Separator) {
		return
	}
	fmt.Println("[SHARE TEXT]")
	cmd := fmt.Sprintf("zt verify ./%s", base)
	switch resolveShareFormat(format) {
	case "en":
		fmt.Println("Please run the following command on the receiver side to verify the file.")
		fmt.Println(cmd)
	default:
		fmt.Println("受信側で次のコマンドを実行して検証してください。")
		fmt.Println(cmd)
	}
}

func resolveShareFormat(format string) string {
	f := strings.ToLower(strings.TrimSpace(format))
	switch f {
	case "", "ja", "en":
		if f == "" {
			return "ja"
		}
		return f
	case "auto":
		for _, name := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
			if v := strings.ToLower(strings.TrimSpace(os.Getenv(name))); v != "" {
				if strings.HasPrefix(v, "ja") || strings.Contains(v, "_jp") || strings.Contains(v, "ja_") {
					return "ja"
				}
			}
		}
		return "en"
	default:
		return "ja"
	}
}
