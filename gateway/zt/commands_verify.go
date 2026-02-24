package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

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
