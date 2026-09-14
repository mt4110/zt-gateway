package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func runVerify(adapters *toolAdapters, opts verifyOptions) {
	resetAuditAppendFailureState()
	setActiveTeamBoundaryContext(nil)
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
		boundaryPolicy, boundaryActive, boundaryErr := resolveTeamBoundaryPolicy(adapters.repoRoot)
		if boundaryErr != nil {
			decision := decisionForVerify(false, "policy_team_boundary_load_failed")
			emitPolicyDecisionCLI(decision)
			emitVerifyEvent(resolvedPath, false, "packet.team_boundary_load_failed", boundaryErr.Error(), decision)
			if opts.SyncNow {
				runSyncEvents(true)
			}
			printZTErrorCode(ztErrorCodeVerifyBoundaryPolicy)
			fmt.Printf("[FAIL] Team boundary policy failed: %v\n", boundaryErr)
			printTrustStatusLine(newTrustStatusFailure(ztErrorCodeVerifyBoundaryPolicy))
			os.Exit(1)
		}
		if boundaryActive {
			setActiveTeamBoundaryContext(newTeamBoundaryRuntimeContext(boundaryPolicy, false, ""))
			if guardErr := enforceTeamBoundaryBreakGlassStartupGuardrail(boundaryPolicy); guardErr != nil {
				errorCode, reasonCode := classifyTeamBoundaryVerifyEnforcementError(guardErr)
				decision := decisionForVerify(false, reasonCode)
				emitPolicyDecisionCLI(decision)
				emitVerifyEvent(resolvedPath, false, "packet.team_boundary_break_glass_env_present", guardErr.Error(), decision)
				if opts.SyncNow {
					runSyncEvents(true)
				}
				printZTErrorCode(errorCode)
				fmt.Printf("[FAIL] Team boundary startup guardrail failed: %v\n", guardErr)
				printTrustStatusLine(newTrustStatusFailure(errorCode))
				os.Exit(1)
			}
		}

		fmt.Printf("[VERIFY] Packet: %s\n", resolvedPath)
		out, runErr := adapters.modernPackVerify(resolvedPath)
		if runErr != nil {
			ztCode, reasonCode, hints, meta := classifyVerifyPacketFailure(string(out), runErr)
			decision := decisionForVerify(false, reasonCode)
			emitPolicyDecisionCLI(decision)
			emitVerifyEventWithMeta(resolvedPath, false, "packet.verify_failed", strings.TrimSpace(string(out)), decision, meta)
			if opts.SyncNow {
				runSyncEvents(true)
			}
			printZTErrorCode(ztCode)
			fmt.Printf("[FAIL] Packet verification failed: %v\n", runErr)
			if trimmed := strings.TrimSpace(string(out)); trimmed != "" {
				fmt.Printf("[DETAIL] %s\n", trimmed)
			}
			for _, hint := range hints {
				fmt.Printf("[HINT] %s\n", hint)
			}
			printTrustStatusLine(newTrustStatusFailure(ztCode))
			os.Exit(1)
		}
		fmt.Println("[PASS] Signature and checksum verified by secure-pack.")
		if trimmed := strings.TrimSpace(string(out)); trimmed != "" {
			fmt.Printf("[DETAIL] %s\n", trimmed)
		}
		signerFingerprint, signerErr := extractVerifiedSignerFingerprint(string(out))
		if signerErr != nil {
			decision := decisionForVerify(false, "policy_verify_provenance_binding_failed")
			emitPolicyDecisionCLI(decision)
			emitVerifyEvent(resolvedPath, false, "packet.verify_provenance_binding_failed", signerErr.Error(), decision)
			if opts.SyncNow {
				runSyncEvents(true)
			}
			printZTErrorCode(ztErrorCodeVerifyProvenance)
			fmt.Printf("[FAIL] Could not bind verify provenance: %v\n", signerErr)
			printTrustStatusLine(newTrustStatusFailure(ztErrorCodeVerifyProvenance))
			os.Exit(1)
		}
		if boundaryActive {
			breakGlassUsed, breakGlassReason, boundarySignerErr := enforceTeamBoundaryForSigner(boundaryPolicy, signerFingerprint, opts)
			if boundarySignerErr != nil {
				errorCode, reasonCode := classifyTeamBoundaryVerifyEnforcementError(boundarySignerErr)
				decision := decisionForVerify(false, reasonCode)
				emitPolicyDecisionCLI(decision)
				emitVerifyEvent(resolvedPath, false, "packet.team_boundary_contract_failed", boundarySignerErr.Error(), decision)
				if opts.SyncNow {
					runSyncEvents(true)
				}
				printZTErrorCode(errorCode)
				fmt.Printf("[FAIL] Team boundary contract failed: %v\n", boundarySignerErr)
				printTrustStatusLine(newTrustStatusFailure(errorCode))
				os.Exit(1)
			}
			setActiveTeamBoundaryContext(newTeamBoundaryRuntimeContext(boundaryPolicy, breakGlassUsed, breakGlassReason))
			if breakGlassUsed {
				fmt.Printf("[WARN] Team boundary break-glass accepted (reason=%q).\n", breakGlassReason)
			}
		}

		decision := decisionForVerify(true, "policy_verify_pass")
		receipt, receiptErr := buildVerificationReceipt(resolvedPath, decision, signerFingerprint)
		if receiptErr != nil {
			failDecision := decisionForVerify(false, "policy_verify_provenance_binding_failed")
			emitPolicyDecisionCLI(failDecision)
			emitVerifyEvent(resolvedPath, false, "packet.verify_provenance_binding_failed", receiptErr.Error(), failDecision)
			if opts.SyncNow {
				runSyncEvents(true)
			}
			printZTErrorCode(ztErrorCodeVerifyProvenance)
			fmt.Printf("[FAIL] Could not build provenance-bound receipt: %v\n", receiptErr)
			printTrustStatusLine(newTrustStatusFailure(ztErrorCodeVerifyProvenance))
			os.Exit(1)
		}
		if strings.TrimSpace(opts.ReceiptOut) != "" {
			receiptPath, pathErr := filepath.Abs(opts.ReceiptOut)
			if pathErr != nil {
				failDecision := decisionForVerify(false, "policy_receipt_path_invalid")
				emitPolicyDecisionCLI(failDecision)
				emitVerifyEvent(resolvedPath, false, "receipt.path_invalid", pathErr.Error(), failDecision)
				if opts.SyncNow {
					runSyncEvents(true)
				}
				printZTErrorCode(ztErrorCodeVerifyReceiptWrite)
				fmt.Printf("[FAIL] receipt path invalid: %v\n", pathErr)
				printTrustStatusLine(newTrustStatusFailure(ztErrorCodeVerifyReceiptWrite))
				os.Exit(1)
			}
			if writeErr := writeVerificationReceipt(receiptPath, receipt); writeErr != nil {
				failDecision := decisionForVerify(false, "policy_receipt_write_failed")
				emitPolicyDecisionCLI(failDecision)
				emitVerifyEvent(resolvedPath, false, "receipt.write_failed", writeErr.Error(), failDecision)
				if opts.SyncNow {
					runSyncEvents(true)
				}
				printZTErrorCode(ztErrorCodeVerifyReceiptWrite)
				fmt.Printf("[FAIL] could not write receipt: %v\n", writeErr)
				printTrustStatusLine(newTrustStatusFailure(ztErrorCodeVerifyReceiptWrite))
				os.Exit(1)
			}
			fmt.Printf("[RECEIPT] saved: %s\n", receiptPath)
		} else {
			fmt.Printf("[RECEIPT] id=%s verified_at=%s\n", receipt.ReceiptID, receipt.VerifiedAt)
		}
		emitPolicyDecisionCLI(decision)
		emitVerifyEvent(resolvedPath, true, "packet.verified", strings.TrimSpace(string(out)), decision)
		if auditFail := consumeAuditAppendFailureState(); auditFail != nil {
			printZTErrorCode(ztErrorCodeVerifyAuditAppendFail)
			fmt.Printf("[FAIL] Packet verify succeeded but audit trail append failed (endpoint=%s): %s\n", auditFail.Endpoint, auditFail.Message)
			fmt.Printf("[HINT] Restore spool/audit write path and run `zt config doctor --json`; follow docs/V0.9.2_ABNORMAL_USECASES.md#audit-trail-append-failed.\n")
			printTrustStatusLine(newTrustStatusFailure(ztErrorCodeVerifyAuditAppendFail))
			os.Exit(1)
		}
		if opts.SyncNow {
			runSyncEvents(true)
		}
		fmt.Println("[VERIFIED] Trust established.")
		printTrustStatusLine(newTrustStatusSuccess(receipt.ReceiptID))
		return
	}
	decision := decisionForVerify(false, "policy_verify_unsupported_input")
	emitPolicyDecisionCLI(decision)
	emitVerifyEvent(resolvedPath, false, "verify.unsupported_input", "zt verify now supports only .spkg.tgz packets", decision)
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

func classifyVerifyPacketFailure(output string, runErr error) (string, string, []string, map[string]any) {
	_ = runErr
	securePackCode := parseSecurePackErrorCode(output)
	meta := map[string]any{}
	if securePackCode != "" {
		meta["secure_pack_error_code"] = securePackCode
	}
	switch securePackCode {
	case "SP_SIGNER_PIN_MISSING":
		return ztErrorCodeVerifySignerPinMissing, "policy_verify_signer_pin_missing", []string{
			"Set `ZT_SECURE_PACK_SIGNER_FINGERPRINTS` or provide `tools/secure-pack/SIGNERS_ALLOWLIST.txt`.",
			"If signer key was rotated/lost, register the recovered key fingerprint after approval.",
		}, meta
	case "SP_SIGNER_PIN_MISMATCH":
		actual, allowed := extractSignerPinMismatchDetails(output)
		if actual != "" {
			meta["actual_signer_fingerprint"] = actual
		}
		if len(allowed) > 0 {
			meta["allowed_signer_fingerprints"] = allowed
		}
		return ztErrorCodeVerifySignerPinMismatch, "policy_verify_signer_pin_mismatch", []string{
			"Signer fingerprint is outside current allowlist.",
			"After key recovery/rotation approval, add the new fingerprint and retry.",
		}, meta
	case "SP_SIGNER_PIN_CONFIG_INVALID":
		return ztErrorCodeVerifySignerPinConfig, "policy_verify_signer_pin_config_invalid", []string{
			"Fix signer fingerprint format in `ZT_SECURE_PACK_SIGNER_FINGERPRINTS` (40/64 hex).",
		}, meta
	default:
		return ztErrorCodeVerifyPacketFailed, "policy_verify_failed", nil, meta
	}
}

func parseSecurePackErrorCode(output string) string {
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(raw)
		const prefix = "SECURE_PACK_ERROR_CODE="
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	return ""
}

func extractSignerPinMismatchDetails(output string) (string, []string) {
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(raw)
		const marker = "packet signer fingerprint mismatch: got "
		idx := strings.Index(line, marker)
		if idx < 0 {
			continue
		}
		rest := line[idx+len(marker):]
		parts := strings.SplitN(rest, ", allowed=", 2)
		actual := strings.TrimSpace(parts[0])
		if len(parts) != 2 {
			return actual, nil
		}
		allowedRaw := strings.TrimSpace(parts[1])
		if allowedRaw == "" {
			return actual, nil
		}
		return actual, dedupeStrings(strings.Split(allowedRaw, ","))
	}
	return "", nil
}
