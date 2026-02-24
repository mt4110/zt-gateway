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
