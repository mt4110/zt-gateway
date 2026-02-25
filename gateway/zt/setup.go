package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func runSetup(repoRoot string, opts setupOptions) error {
	jsonOut := opts.JSON
	profileName, err := validateTrustProfile(opts.Profile)
	if err != nil {
		return err
	}
	profileSelection, profileErr := resolveTrustProfilePolicySelection(repoRoot, profileName)
	if profileErr != nil {
		profileSelection = trustProfilePolicySelection{
			Name:                profileName,
			Source:              "unresolved",
			ExtensionPolicyPath: filepath.Join(repoRoot, "policy", "extension_policy.toml"),
			ScanPolicyPath:      filepath.Join(repoRoot, "policy", "scan_policy.toml"),
		}
	}
	if !jsonOut {
		fmt.Println("[SETUP] zt quick setup check")
		fmt.Println("This checks local config, signing key env, required tools, and control-plane reachability.")
	}

	result := setupResult{
		SchemaVersion: 1,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Command:       "zt setup",
		Argv:          append([]string(nil), os.Args...),
		RepoRoot:      repoRoot,
		Checks:        make([]setupCheck, 0, 16),
	}
	quickFixes := make([]string, 0, 8)
	addCheck := func(name, status, msg string) {
		result.Checks = append(result.Checks, setupCheck{Name: name, Status: status, Message: msg})
		switch status {
		case "fail":
			result.Failures++
		case "warn":
			result.Warnings++
		}
	}

	cfg, cfgErr := loadZTClientConfig(repoRoot)
	if cfgErr != nil {
		addCheck("zt_client_config", "fail", cfgErr.Error())
		if !jsonOut {
			fmt.Printf("[FAIL] zt_client.toml parse error: %v\n", cfgErr)
		}
		cfg = defaultZTClientConfig()
		result.ConfigSource = "(parse_failed)"
	} else {
		result.ConfigSource = cfg.Source
		addCheck("zt_client_config", "ok", "loaded from "+cfg.Source)
		if !jsonOut {
			fmt.Printf("[OK]   zt_client config loaded (%s)\n", cfg.Source)
		}
	}

	autoSync, autoSyncSrc := resolveEventAutoSyncDefault(cfg)
	cpURL, cpURLSrc := resolveControlPlaneURL(cfg)
	cpAPIKey, cpAPIKeySrc := resolveControlPlaneAPIKey(cfg)
	spoolDir := strings.TrimSpace(os.Getenv("ZT_EVENT_SPOOL_DIR"))
	if spoolDir == "" {
		spoolDir = filepath.Join(repoRoot, ".zt-spool")
	}
	result.Resolved = setupResolved{
		AutoSync:        autoSync,
		AutoSyncSource:  autoSyncSrc,
		ControlPlaneURL: cpURL,
		ControlPlaneSrc: cpURLSrc,
		APIKeySet:       cpAPIKey != "",
		APIKeySource:    cpAPIKeySrc,
		SpoolDir:        spoolDir,
		Profile:         profileSelection.Name,
		ProfileSource:   profileSelection.Source,
	}
	if profileErr != nil {
		addCheck("trust_profile", "fail", profileErr.Error())
		quickFixes = append(quickFixes,
			fmt.Sprintf("Create `%s` and `%s` for profile `%s`, or rerun with `--profile %s`.",
				profileSelection.ExtensionPolicyPath,
				profileSelection.ScanPolicyPath,
				profileName,
				trustProfileInternal))
		if !jsonOut {
			fmt.Printf("[FAIL] trust profile resolution failed: %v\n", profileErr)
		}
	} else {
		addCheck("trust_profile", "ok", fmt.Sprintf("resolved=%s source=%s", profileSelection.Name, profileSelection.Source))
		if !jsonOut {
			fmt.Printf("[OK]   trust profile resolved (%s via %s)\n", profileSelection.Name, profileSelection.Source)
		}
	}
	if pinInfo := collectSetupRootPinJSONInfo(repoRoot); pinInfo != nil {
		result.Resolved.ActualRootFingerprint = pinInfo.ActualRootFingerprint
		result.Resolved.PinSource = pinInfo.PinSource
		result.Resolved.PinMatchCount = pinInfo.PinMatchCount
	}
	addCheck("auto_sync_resolution", "ok", fmt.Sprintf("resolved=%t source=%s", autoSync, autoSyncSrc))
	if !jsonOut {
		fmt.Printf("[INFO] auto_sync=%t (%s)\n", autoSync, autoSyncSrc)
	}
	if cpURL == "" {
		addCheck("control_plane_url", "warn", "empty ("+cpURLSrc+")")
		if !jsonOut {
			fmt.Printf("[WARN] control_plane_url is empty (%s)\n", cpURLSrc)
		}
		quickFixes = append(quickFixes, "Set `control_plane_url` in `policy/zt_client.toml` (or `ZT_CONTROL_PLANE_URL`) if you want event sync / dashboard.")
	} else {
		addCheck("control_plane_url", "ok", "configured ("+cpURLSrc+")")
		if !jsonOut {
			fmt.Printf("[OK]   control_plane_url configured (%s)\n", cpURLSrc)
		}
	}
	if cpAPIKey == "" {
		addCheck("control_plane_api_key", "warn", "empty ("+cpAPIKeySrc+")")
		if !jsonOut {
			fmt.Printf("[WARN] control_plane_api_key is empty (%s)\n", cpAPIKeySrc)
		}
		quickFixes = append(quickFixes, "Set `api_key` in `policy/zt_client.toml` (or `ZT_CONTROL_PLANE_API_KEY`) if your Control Plane requires auth.")
	} else {
		addCheck("control_plane_api_key", "ok", "configured ("+cpAPIKeySrc+")")
		if !jsonOut {
			fmt.Printf("[OK]   control_plane_api_key configured (%s)\n", cpAPIKeySrc)
		}
	}

	if err := os.MkdirAll(spoolDir, 0o755); err != nil {
		addCheck("spool_dir", "fail", fmt.Sprintf("mkdir failed: %s (%v)", spoolDir, err))
		if !jsonOut {
			fmt.Printf("[FAIL] spool dir create failed: %s (%v)\n", spoolDir, err)
		}
	} else {
		testFile := filepath.Join(spoolDir, ".setup-write-test")
		if err := os.WriteFile(testFile, []byte("ok\n"), 0o600); err != nil {
			addCheck("spool_dir", "fail", fmt.Sprintf("not writable: %s (%v)", spoolDir, err))
			if !jsonOut {
				fmt.Printf("[FAIL] spool dir not writable: %s (%v)\n", spoolDir, err)
			}
		} else {
			_ = os.Remove(testFile)
			addCheck("spool_dir", "ok", "writable: "+spoolDir)
			if !jsonOut {
				fmt.Printf("[OK]   spool dir writable: %s\n", spoolDir)
			}
		}
	}

	if signer, err := loadEventEnvelopeSignerFromEnv(); err != nil {
		addCheck("event_signing_key_env", "fail", err.Error())
		if !jsonOut {
			fmt.Printf("[FAIL] event signing key env invalid: %v\n", err)
		}
	} else if signer == nil {
		addCheck("event_signing_key_env", "warn", "not configured (ZT_EVENT_SIGNING_ED25519_PRIV_B64)")
		if !jsonOut {
			fmt.Println("[WARN] event signing key env not configured (ZT_EVENT_SIGNING_ED25519_PRIV_B64)")
		}
		quickFixes = append(quickFixes, "Set `ZT_EVENT_SIGNING_ED25519_PRIV_B64` (and optional `ZT_EVENT_SIGNING_KEY_ID`) to sign events sent to Control Plane.")
	} else {
		keyID := signer.KeyID
		if keyID == "" {
			keyID = "(empty)"
		}
		addCheck("event_signing_key_env", "ok", "loaded key_id="+keyID)
		if !jsonOut {
			fmt.Printf("[OK]   event signing key env loaded (key_id=%s)\n", keyID)
		}
	}

	if !jsonOut {
		fmt.Println("")
		fmt.Println("[TOOLS] local executables")
	}
	checkTool := func(name string, required bool, note string) {
		if p, err := exec.LookPath(name); err == nil {
			addCheck("tool."+name, "ok", p)
			if !jsonOut {
				fmt.Printf("[OK]   %s -> %s\n", name, p)
			}
			return
		}
		if required {
			addCheck("tool."+name, "fail", "not found ("+note+")")
			if !jsonOut {
				fmt.Printf("[FAIL] %s not found (%s)\n", name, note)
			}
			quickFixes = append(quickFixes, quickFixForMissingTool(name))
			return
		}
		addCheck("tool."+name, "warn", "not found ("+note+")")
		if !jsonOut {
			fmt.Printf("[WARN] %s not found (%s)\n", name, note)
		}
		if fix := quickFixForMissingTool(name); fix != "" {
			quickFixes = append(quickFixes, fix)
		}
	}
	checkTool("go", true, "needed to run local tools in this repo")
	checkTool("gpg", false, "needed for secure-pack packet signing/verification workflows")
	checkTool("clamscan", false, "recommended for malware scanning")
	checkTool("freshclam", false, "needed when using --update for ClamAV definitions")
	checkTool("yara", false, "recommended for rule-based scanning")

	preflight := collectSetupPreflightChecksWithPolicy(repoRoot, profileSelection)
	for _, c := range preflight.Checks {
		addCheck(c.Name, c.Status, c.Message)
		if !jsonOut {
			printSetupCheckLine(c)
		}
	}
	quickFixes = append(quickFixes, preflight.QuickFixes...)
	result.Compatibility = preflight.Compatibility

	if cpURL != "" {
		if !jsonOut {
			fmt.Println("")
		}
		if err := checkControlPlaneHealth(cpURL, cpAPIKey); err != nil {
			addCheck("control_plane_health", "warn", err.Error())
			if !jsonOut {
				fmt.Printf("[WARN] control plane health check failed: %v\n", err)
			}
			quickFixes = append(quickFixes, "Start Control Plane and verify `GET /healthz`, then rerun `zt setup`.")
		} else {
			msg := strings.TrimRight(cpURL, "/") + "/healthz"
			addCheck("control_plane_health", "ok", "reachable: "+msg)
			if !jsonOut {
				fmt.Printf("[OK]   control plane reachable: %s\n", msg)
			}
		}
	}

	result.QuickFixes = dedupeStrings(quickFixes)
	result.Next = []string{
		"Sender: zt send [--client <name>] <file>",
		"Receiver: zt verify <packet.spkg.tgz>",
		"Details: zt --help-advanced",
	}
	result.OK = result.Failures == 0
	if !result.OK {
		result.ErrorCode = ztErrorCodeSetupChecksFailed
		result.Summary = "setup checks failed"
		result.TrustStatus = newTrustStatusFailure(result.ErrorCode)
	} else {
		result.Summary = "setup checks passed"
		result.TrustStatus = newTrustStatusSuccess("none")
	}
	retryCommand := "zt setup"
	if profileName != trustProfileInternal {
		retryCommand += " --profile " + profileName
	}
	if jsonOut {
		retryCommand += " --json"
	}
	if len(result.QuickFixes) > 0 || !result.OK {
		result.QuickFixBundle = buildQuickFixBundle(result.Summary, result.QuickFixes, retryCommand)
	}

	if jsonOut {
		emitSetupJSON(result)
		if !result.OK {
			return fmt.Errorf("setup checks failed")
		}
		return nil
	}

	if len(result.QuickFixes) > 0 {
		fmt.Println("")
		fmt.Println("[QUICK FIX]")
		for i, fix := range result.QuickFixes {
			fmt.Printf("%d. %s\n", i+1, fix)
		}
	}

	fmt.Println("")
	fmt.Println("[NEXT]")
	fmt.Println("1. Sender:   zt send [--client <name>] <file>")
	fmt.Println("2. Receiver: zt verify <packet.spkg.tgz>")
	fmt.Println("3. Details:  zt --help-advanced")
	fmt.Printf("[RESULT] failures=%d warnings=%d\n", result.Failures, result.Warnings)
	if !result.OK {
		printZTErrorCode(result.ErrorCode)
		printTrustStatusLine(result.TrustStatus)
		return fmt.Errorf("setup checks failed")
	}
	printTrustStatusLine(result.TrustStatus)
	return nil
}

type setupRootPinJSONInfo struct {
	ActualRootFingerprint string
	PinSource             string
	PinMatchCount         int
}

func collectSetupRootPinJSONInfo(repoRoot string) *setupRootPinJSONInfo {
	pins, source, pinErr := resolveSecurePackRootPubKeyFingerprintPinsWithSource()
	info := &setupRootPinJSONInfo{PinSource: source}
	if pinErr != nil {
		info.PinSource = "invalid"
	}
	rootPubKeyPath := filepath.Join(repoRoot, "tools", "secure-pack", "ROOT_PUBKEY.asc")
	if _, err := os.Stat(rootPubKeyPath); err != nil {
		if info.PinSource == "" {
			info.PinSource = "none"
		}
		return info
	}
	if _, err := exec.LookPath("gpg"); err != nil {
		return info
	}
	actual, err := readRootPubKeyFingerprint(rootPubKeyPath)
	if err != nil {
		return info
	}
	info.ActualRootFingerprint = actual
	if pinErr == nil {
		info.PinMatchCount = countFingerprintMatches(actual, pins)
	}
	return info
}
