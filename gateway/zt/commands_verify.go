package main

import (
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
		printZTErrorCode(ztErrorCodeVerifyInvalidPath)
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
			printZTErrorCode(ztErrorCodeVerifyPacketFailed)
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
	emitVerifyEvent(resolvedPath, false, "verify.unsupported_input", "zt verify now supports only .spkg.tgz packets")
	if opts.SyncNow {
		runSyncEvents(true)
	}
	printZTErrorCode(ztErrorCodeVerifyUnsupported)
	fmt.Println("[FAIL] Unsupported input for `zt verify`.")
	fmt.Println("Reason: legacy artifact.zp verification path was removed.")
	fmt.Println("Use: `zt verify <packet.spkg.tgz>`")
	os.Exit(1)
}
