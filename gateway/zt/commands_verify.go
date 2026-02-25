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
		printTrustStatusLine(newTrustStatusFailure(ztErrorCodeVerifyInvalidPath))
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
			printTrustStatusLine(newTrustStatusFailure(ztErrorCodeVerifyPacketFailed))
			os.Exit(1)
		}
		fmt.Println("[PASS] Signature and checksum verified by secure-pack.")
		if trimmed := strings.TrimSpace(string(out)); trimmed != "" {
			fmt.Printf("[DETAIL] %s\n", trimmed)
		}
		receipt := buildVerificationReceipt(resolvedPath)
		if strings.TrimSpace(opts.ReceiptOut) != "" {
			receiptPath, err := filepath.Abs(opts.ReceiptOut)
			if err != nil {
				emitVerifyEvent(resolvedPath, false, "receipt.path_invalid", err.Error())
				if opts.SyncNow {
					runSyncEvents(true)
				}
				printZTErrorCode(ztErrorCodeVerifyReceiptWrite)
				fmt.Printf("[FAIL] receipt path invalid: %v\n", err)
				printTrustStatusLine(newTrustStatusFailure(ztErrorCodeVerifyReceiptWrite))
				os.Exit(1)
			}
			if err := writeVerificationReceipt(receiptPath, receipt); err != nil {
				emitVerifyEvent(resolvedPath, false, "receipt.write_failed", err.Error())
				if opts.SyncNow {
					runSyncEvents(true)
				}
				printZTErrorCode(ztErrorCodeVerifyReceiptWrite)
				fmt.Printf("[FAIL] could not write receipt: %v\n", err)
				printTrustStatusLine(newTrustStatusFailure(ztErrorCodeVerifyReceiptWrite))
				os.Exit(1)
			}
			fmt.Printf("[RECEIPT] saved: %s\n", receiptPath)
		} else {
			fmt.Printf("[RECEIPT] id=%s verified_at=%s\n", receipt.ReceiptID, receipt.VerifiedAt)
		}
		fmt.Println("[VERIFIED] Trust established.")
		emitVerifyEvent(resolvedPath, true, "packet.verified", strings.TrimSpace(string(out)))
		if opts.SyncNow {
			runSyncEvents(true)
		}
		printTrustStatusLine(newTrustStatusSuccess(receipt.ReceiptID))
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
	printTrustStatusLine(newTrustStatusFailure(ztErrorCodeVerifyUnsupported))
	os.Exit(1)
}
