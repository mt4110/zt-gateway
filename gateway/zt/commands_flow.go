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

func resolveSendScanStrict(opts sendOptions, envZTScanStrict bool) (bool, string) {
	profile := normalizeTrustProfile(opts.Profile)
	if isStrictTrustProfile(profile) {
		return true, fmt.Sprintf("[Scan] strict mode enforced by profile=%s", profile)
	}
	if opts.AllowDegradedScan {
		return false, "[Scan] degraded scan mode enabled (--allow-degraded-scan). No-scanner-available may be allowed (unsafe)."
	}
	if opts.Strict {
		return true, "[Scan] strict mode enabled (--strict; default for zt send)"
	}
	if profile == trustProfilePublic {
		return false, "[Scan] degraded scan default enabled by profile=public (shared-priority posture)"
	}
	if envZTScanStrict {
		return true, "[Scan] strict mode enabled by default (`ZT_SCAN_STRICT=1` is redundant for zt send)"
	}
	return true, "[Scan] strict mode enabled by default (zt send)"
}

func runSendSecurePackPrecheck(repoRoot string) (bool, []string) {
	filesCheck, rootPinCheck, sigCheck, fixes := buildSecurePackSupplyChainSetupChecks(repoRoot)
	checks := []setupCheck{filesCheck, rootPinCheck, sigCheck}

	ok := true
	for _, c := range checks {
		if c.Status != "ok" {
			ok = false
			break
		}
	}

	if ok {
		fmt.Println("[Precheck] secure-pack root key + tools.lock signature OK (tool pins such as gpg/tar are verified in secure-pack send)")
		return true, nil
	}

	fmt.Println("[Precheck] secure-pack supply-chain issues detected before packing:")
	for _, c := range checks {
		if c.Status == "ok" {
			continue
		}
		printSetupCheckLine(c)
	}
	if len(fixes) > 0 {
		fmt.Printf("[Hint] %s\n", fixes[0])
	}
	return false, fixes
}

func runScan(adapters *toolAdapters, opts scanOptions) {
	if cpEvents != nil {
		if opts.NoAutoSync {
			cpEvents.SetAutoSync(false)
		}
	}
	targetPath, err := filepath.Abs(opts.Target)
	if err != nil {
		printZTErrorCode(ztErrorCodeScanInvalidPath)
		fmt.Fprintf(os.Stderr, "Scan Error: %v\n", err)
		os.Exit(1)
	}
	info, err := os.Stat(targetPath)
	if err != nil {
		printZTErrorCode(ztErrorCodeScanStatFailed)
		fmt.Fprintf(os.Stderr, "Scan Error: %v\n", err)
		os.Exit(1)
	}
	if !info.IsDir() {
		if err := enforceFileTypeConsistency(targetPath); err != nil {
			printZTErrorCode(ztErrorCodeScanInputRejected)
			fmt.Fprintf(os.Stderr, "Scan Error: %v\n", err)
			os.Exit(1)
		}
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
				printZTErrorCode(ztErrorCodeScanCheckFailed)
				os.Exit(1)
			}
			return
		}
		if err != nil {
			if len(stderr) > 0 {
				printZTErrorCode(ztErrorCodeScanCheckFailed)
				fmt.Fprintf(os.Stderr, "Scan Error: %s\n", strings.TrimSpace(string(stderr)))
				os.Exit(1)
			}
			printZTErrorCode(ztErrorCodeScanCheckFailed)
			fmt.Fprintf(os.Stderr, "Scan Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	fmt.Println("[Adapter] Using interactive secure-scan (new CLI/TUI)")
	if err := adapters.interactiveScan(targetPath, opts.ForcePublic, opts.AutoUpdate); err != nil {
		printZTErrorCode(ztErrorCodeScanTUIFailed)
		fmt.Fprintf(os.Stderr, "Failed to run secure-scan TUI: %v\n", err)
		os.Exit(1)
	}
}

func runSend(adapters *toolAdapters, opts sendOptions) {
	trustFail := func(code string) {
		printTrustStatusLine(newTrustStatusFailure(code))
	}

	if cpEvents != nil {
		if opts.NoAutoSync {
			cpEvents.SetAutoSync(false)
		}
	}
	inputPath, err := filepath.Abs(opts.InputFile)
	if err != nil {
		printZTErrorCode(ztErrorCodeSendInvalidPath)
		fmt.Printf("GATEWAY_ERROR: Failed to resolve file path: %v\n", err)
		trustFail(ztErrorCodeSendInvalidPath)
		os.Exit(1)
	}
	fmt.Printf("Processing %s...\n", inputPath)
	profileSelection, profileErr := resolveTrustProfilePolicySelection(adapters.repoRoot, opts.Profile)
	if profileErr != nil {
		printZTErrorCode(ztErrorCodeSendExtPolicyLoad)
		fmt.Printf("[BLOCKED] Failed to resolve trust profile %q: %v\n", opts.Profile, profileErr)
		fmt.Println("Reason: profile-specific policy files must be present for fail-closed routing.")
		if opts.SyncNow {
			runSyncEvents(true)
		}
		trustFail(ztErrorCodeSendExtPolicyLoad)
		os.Exit(1)
	}
	fmt.Printf("[Profile] %s source=%s\n", profileSelection.Name, profileSelection.Source)

	policyFile := profileSelection.ExtensionPolicyPath
	extPolicy, policyErr := loadExtensionPolicy(policyFile)
	if policyErr != nil {
		if os.IsNotExist(policyErr) && profileSelection.Name == trustProfileInternal {
			fmt.Printf("[Policy] WARN %s not found, using secure defaults: %v\n", policyFile, policyErr)
			extPolicy = defaultExtensionPolicy()
		} else {
			printZTErrorCode(ztErrorCodeSendExtPolicyLoad)
			fmt.Printf("[BLOCKED] Failed to load %s: %v\n", policyFile, policyErr)
			fmt.Println("Reason: extension policy parse/load failure is treated as fail-closed to avoid unsafe routing defaults.")
			if opts.SyncNow {
				runSyncEvents(true)
			}
			trustFail(ztErrorCodeSendExtPolicyLoad)
			os.Exit(1)
		}
	}
	scanPolicyFile := profileSelection.ScanPolicyPath
	scanPol, scanPolicyErr := loadScanPolicy(scanPolicyFile)
	if scanPolicyErr != nil {
		if os.IsNotExist(scanPolicyErr) && profileSelection.Name == trustProfileInternal {
			fmt.Printf("[Policy] WARN %s not found, using secure defaults: %v\n", scanPolicyFile, scanPolicyErr)
			scanPol = defaultScanPolicy()
		} else {
			printZTErrorCode(ztErrorCodeSendScanPolicyLoad)
			fmt.Printf("[BLOCKED] Failed to load %s: %v\n", scanPolicyFile, scanPolicyErr)
			fmt.Println("Reason: scan policy parse/load failure is treated as fail-closed to avoid degraded scanning requirements.")
			if opts.SyncNow {
				runSyncEvents(true)
			}
			trustFail(ztErrorCodeSendScanPolicyLoad)
			os.Exit(1)
		}
	}
	mode, policyReason := resolveExtensionMode(inputPath, extPolicy)
	fmt.Printf("[Policy] %s (%s) source=%s\n", mode, policyReason, extPolicy.Source)
	if len(scanPol.RequiredScanners) > 0 || scanPol.RequireClamAVDB {
		fmt.Printf("[Policy] scan requirements: required_scanners=%v require_clamav_db=%t source=%s\n", scanPol.RequiredScanners, scanPol.RequireClamAVDB, scanPol.Source)
	}
	if mode == ExtModeDeny {
		printZTErrorCode(ztErrorCodeSendPolicyBlocked)
		fmt.Printf("\n[BLOCKED] File was rejected by zt policy.\nReason: %s\n", policyReason)
		if opts.SyncNow {
			runSyncEvents(true)
		}
		trustFail(ztErrorCodeSendPolicyBlocked)
		os.Exit(1)
	}
	if err := enforceFilePolicy(inputPath, mode, extPolicy); err != nil {
		printZTErrorCode(ztErrorCodeSendPolicyBlocked)
		fmt.Printf("\n[BLOCKED] File was rejected by zt policy.\nReason: %v\n", err)
		if opts.SyncNow {
			runSyncEvents(true)
		}
		trustFail(ztErrorCodeSendPolicyBlocked)
		os.Exit(1)
	}
	if err := enforceFileTypeConsistency(inputPath); err != nil {
		printZTErrorCode(ztErrorCodeSendPolicyBlocked)
		fmt.Printf("\n[BLOCKED] File was rejected by zt policy.\nReason: %v\n", err)
		if opts.SyncNow {
			runSyncEvents(true)
		}
		trustFail(ztErrorCodeSendPolicyBlocked)
		os.Exit(1)
	}
	if ok, _ := runSendSecurePackPrecheck(adapters.repoRoot); !ok {
		printZTErrorCode(ztErrorCodePrecheckSupplyChain)
		fmt.Println("[BLOCKED] secure-pack supply-chain precheck failed; fix the items above and retry `zt send`.")
		if opts.SyncNow {
			runSyncEvents(true)
		}
		trustFail(ztErrorCodePrecheckSupplyChain)
		os.Exit(1)
	}

	// 1. secure-scan check (new secure-scan JSON mode)
	fmt.Println("[Step 1/3] Scanning...")
	scanStrict, strictMsg := resolveSendScanStrict(opts, envBool("ZT_SCAN_STRICT"))
	fmt.Println(strictMsg)
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
			printZTErrorCode(ztErrorCodeSendScanUpdateFail)
			fmt.Printf("GATEWAY_ERROR: secure-scan update/scan failed before JSON result.\n")
			fmt.Printf("Hint: `--update` requires `freshclam` (ClamAV updater) and network access.\n")
			fmt.Printf("stderr: %s\n", strings.TrimSpace(string(scanStderr)))
			trustFail(ztErrorCodeSendScanUpdateFail)
			os.Exit(1)
		}
		printZTErrorCode(ztErrorCodeSendScanJSONParse)
		fmt.Printf("GATEWAY_ERROR: Failed to parse scan result: %v\nRaw output: %s\n", jsonErr, string(output))
		trustFail(ztErrorCodeSendScanJSONParse)
		os.Exit(1)
	}
	if err != nil && res.Result == "" {
		if opts.AutoUpdate && len(scanStderr) > 0 {
			printZTErrorCode(ztErrorCodeSendScanUpdateFail)
			fmt.Printf("GATEWAY_ERROR: secure-scan failed during `--update` pre-scan step.\n")
			fmt.Printf("Hint: install `freshclam` / ClamAV DB tooling, or rerun without `--update`.\n")
			fmt.Printf("stderr: %s\n", strings.TrimSpace(string(scanStderr)))
			trustFail(ztErrorCodeSendScanUpdateFail)
			os.Exit(1)
		}
		printZTErrorCode(ztErrorCodeSendScanCheckFail)
		fmt.Printf("GATEWAY_ERROR: secure-scan (modern JSON adapter) failed: %v\nOutput: %s\n", err, string(output))
		if len(scanStderr) > 0 {
			fmt.Printf("stderr: %s\n", strings.TrimSpace(string(scanStderr)))
		}
		trustFail(ztErrorCodeSendScanCheckFail)
		os.Exit(1)
	}
	if len(output) > 0 {
		emitScanEventFromSecureScanJSON("send", inputPath, output)
	}
	if res.Reason == "clean.no_scanners_available" {
		fmt.Println("[WARN] secure-scan returned allow with no scanners available (degraded mode).")
	}

	if res.Result != "allow" {
		printZTErrorCode(ztErrorCodeSendScanDenied)
		fmt.Printf("\n[BLOCKED] File was rejected by secure-scan.\nReason: %s\n", res.Reason)
		if opts.SyncNow {
			runSyncEvents(true)
		}
		trustFail(ztErrorCodeSendScanDenied)
		os.Exit(1)
	}
	fmt.Println("Scan passed.")

	// 2. secure-rebuild (Sanitizer) - only for SCAN_REBUILD
	sanitizedPath := inputPath
	if mode == ExtModeScanRebuild {
		fmt.Println("[Step 2/3] Sanitizing (secure-rebuild)...")
		tmpFile, err := os.CreateTemp("", "zt-sanitized-*"+filepath.Ext(inputPath))
		if err != nil {
			printZTErrorCode(ztErrorCodeSendSanitizeTemp)
			fmt.Printf("GATEWAY_ERROR: Failed to create temp file: %v\n", err)
			trustFail(ztErrorCodeSendSanitizeTemp)
			os.Exit(1)
		}
		tmpFile.Close()
		sanitizedPath = tmpFile.Name()
		defer os.Remove(sanitizedPath)

		rebuildOut, rebuildErr := adapters.rebuild(inputPath, sanitizedPath)
		if rebuildErr != nil {
			printZTErrorCode(ztErrorCodeSendSanitizeFail)
			fmt.Printf("GATEWAY_ERROR: Sanitization failed: %v\nOutput: %s\n", rebuildErr, string(rebuildOut))
			trustFail(ztErrorCodeSendSanitizeFail)
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
			printZTErrorCode(ztErrorCodeSendPackFail)
			fmt.Printf("GATEWAY_ERROR: Packing failed (modern adapter): %v\nOutput: %s\n", packErr, string(packOut))
			trustFail(ztErrorCodeSendPackFail)
			os.Exit(1)
		}
		var scanMeta map[string]any
		_ = json.Unmarshal(output, &scanMeta)
		emitArtifactEvent("spkg.tgz", packetPath, inputPath, opts.Client, stringField(scanMeta, "rule_hash"))
		if opts.SyncNow {
			runSyncEvents(true)
		}
		fmt.Printf("\n[SUCCESS] Packet generated.\n%s\nSaved: %s\n", string(packOut), packetPath)
		deliverReceiverShare(packetPath, opts)
		printTrustStatusLine(newTrustStatusSuccess("pending"))
		return
	}
	printZTErrorCode(ztErrorCodeSendClientRequired)
	fmt.Println("[BLOCKED] zt send now requires --client <name> and only supports spkg.tgz packets.")
	fmt.Println("Reason: legacy artifact.zp path was removed.")
	trustFail(ztErrorCodeSendClientRequired)
	os.Exit(1)
}
