package main

import (
	"fmt"
	"strings"
)

type trustStatus struct {
	Verified bool   `json:"verified"`
	Tamper   string `json:"tamper"`
	Policy   string `json:"policy"`
	Receipt  string `json:"receipt,omitempty"`
	Reason   string `json:"reason,omitempty"`
	Line     string `json:"line"`
}

type quickFixBundle struct {
	Why           string   `json:"why"`
	Commands      []string `json:"commands,omitempty"`
	Runbook       string   `json:"runbook,omitempty"`
	RunbookAnchor string   `json:"runbook_anchor,omitempty"`
	Retry         string   `json:"retry,omitempty"`
}

func newTrustStatusSuccess(receiptID string) trustStatus {
	receiptID = strings.TrimSpace(receiptID)
	if receiptID == "" {
		receiptID = "none"
	}
	line := fmt.Sprintf("TRUST: verified=true tamper=false policy=pass receipt=%s", receiptID)
	return trustStatus{
		Verified: true,
		Tamper:   "false",
		Policy:   "pass",
		Receipt:  receiptID,
		Line:     line,
	}
}

func newTrustStatusFailure(reason string) trustStatus {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "UNKNOWN"
	}
	line := fmt.Sprintf("TRUST: verified=false tamper=unknown policy=fail reason=%s", reason)
	return trustStatus{
		Verified: false,
		Tamper:   "unknown",
		Policy:   "fail",
		Reason:   reason,
		Line:     line,
	}
}

func printTrustStatusLine(status trustStatus) {
	fmt.Println(status.Line)
}

func buildQuickFixBundle(summary string, quickFixes []string, retryCommand string) *quickFixBundle {
	return buildQuickFixBundleWithCode(summary, quickFixes, retryCommand, "")
}

func buildQuickFixBundleWithCode(summary string, quickFixes []string, retryCommand string, errorCode string) *quickFixBundle {
	why := strings.TrimSpace(summary)
	if why == "" {
		why = "operation failed; apply fixes and retry"
	}
	retry := strings.TrimSpace(retryCommand)
	if retry == "" {
		retry = "zt setup --json"
	}
	commands := dedupeStrings(append([]string(nil), quickFixes...))
	if len(commands) == 0 {
		commands = []string{retry}
	}
	return &quickFixBundle{
		Why:           why,
		Commands:      commands,
		Runbook:       runbookPathForErrorCode(errorCode),
		RunbookAnchor: runbookAnchorForErrorCode(errorCode),
		Retry:         retry,
	}
}

func runbookPathForErrorCode(errorCode string) string {
	switch strings.ToLower(strings.TrimSpace(errorCode)) {
	case strings.ToLower(ztErrorCodeSendBoundaryPolicy),
		strings.ToLower(ztErrorCodeSendBoundaryClient),
		strings.ToLower(ztErrorCodeSendBoundaryRoute),
		strings.ToLower(ztErrorCodeSendBoundaryBreakGlassEnvPresent),
		strings.ToLower(ztErrorCodeSendBoundaryBreakGlassReasonRequired),
		strings.ToLower(ztErrorCodeSendBoundaryBreakGlassTokenInvalid),
		strings.ToLower(ztErrorCodeSendBoundaryBreakGlassTokenExpired),
		strings.ToLower(ztErrorCodeSendAuditAppendFail),
		strings.ToLower(ztErrorCodeVerifyBoundaryPolicy),
		strings.ToLower(ztErrorCodeVerifyBoundarySigner),
		strings.ToLower(ztErrorCodeVerifyBoundaryBreakGlassEnvPresent),
		strings.ToLower(ztErrorCodeVerifyBoundaryBreakGlassReasonRequired),
		strings.ToLower(ztErrorCodeVerifyBoundaryBreakGlassTokenInvalid),
		strings.ToLower(ztErrorCodeVerifyBoundaryBreakGlassTokenExpired),
		strings.ToLower(ztErrorCodeVerifySignerPinMissing),
		strings.ToLower(ztErrorCodeVerifySignerPinMismatch),
		strings.ToLower(ztErrorCodeVerifySignerPinConfig),
		strings.ToLower(ztErrorCodeVerifyAuditAppendFail),
		"sp_signer_pin_missing",
		"sp_signer_pin_mismatch",
		"sp_signer_pin_config_invalid",
		teamBoundarySignerSplitBrainCode,
		teamBoundarySignerPinMissingCode,
		teamBoundarySignerPinConfigInvalidCode,
		auditTrailAppendUnavailableCode,
		teamBoundaryBreakGlassEnvPresentCode,
		teamBoundaryBreakGlassGuardrailWeakCode,
		teamBoundaryBreakGlassReasonRequiredCode,
		teamBoundaryBreakGlassTokenInvalidCode,
		teamBoundaryBreakGlassTokenExpiredCode:
		return "docs/V0.9.2_ABNORMAL_USECASES.md"
	default:
		return "docs/OPERATIONS.md"
	}
}

func runbookAnchorForErrorCode(errorCode string) string {
	switch strings.ToLower(strings.TrimSpace(errorCode)) {
	case strings.ToLower(ztErrorCodeSendBoundaryPolicy), strings.ToLower(ztErrorCodeVerifyBoundaryPolicy):
		return "#team-boundary-policy-missing-or-invalid"
	case strings.ToLower(ztErrorCodeSendBoundaryClient):
		return "#recipient-boundary-denied"
	case strings.ToLower(ztErrorCodeSendBoundaryRoute):
		return "#share-route-boundary-denied"
	case strings.ToLower(ztErrorCodeSendBoundaryBreakGlassEnvPresent), strings.ToLower(ztErrorCodeVerifyBoundaryBreakGlassEnvPresent):
		return "#break-glass-override-left-enabled"
	case strings.ToLower(ztErrorCodeSendBoundaryBreakGlassReasonRequired), strings.ToLower(ztErrorCodeVerifyBoundaryBreakGlassReasonRequired), teamBoundaryBreakGlassReasonRequiredCode:
		return "#break-glass-reason-required"
	case strings.ToLower(ztErrorCodeSendBoundaryBreakGlassTokenInvalid), strings.ToLower(ztErrorCodeVerifyBoundaryBreakGlassTokenInvalid):
		return "#break-glass-token-invalid"
	case strings.ToLower(ztErrorCodeSendBoundaryBreakGlassTokenExpired), strings.ToLower(ztErrorCodeVerifyBoundaryBreakGlassTokenExpired):
		return "#break-glass-token-expired"
	case strings.ToLower(ztErrorCodeSendAuditAppendFail):
		return "#audit-trail-append-failed"
	case strings.ToLower(ztErrorCodeVerifyBoundarySigner):
		return "#signer-boundary-denied"
	case strings.ToLower(ztErrorCodeVerifySignerPinMissing):
		return "#signer-allowlist-missing"
	case strings.ToLower(ztErrorCodeVerifySignerPinMismatch):
		return "#signer-key-loss"
	case strings.ToLower(ztErrorCodeVerifySignerPinConfig):
		return "#signer-allowlist-invalid-format"
	case strings.ToLower(ztErrorCodeVerifyAuditAppendFail):
		return "#audit-trail-append-failed"
	case "sp_signer_pin_missing":
		return "#signer-allowlist-missing"
	case "sp_signer_pin_mismatch":
		return "#signer-key-loss"
	case "sp_signer_pin_config_invalid":
		return "#signer-allowlist-invalid-format"
	case teamBoundarySignerSplitBrainCode:
		return "#signer-policy-split-brain-detected"
	case teamBoundarySignerPinMissingCode:
		return "#signer-allowlist-missing"
	case teamBoundarySignerPinConfigInvalidCode:
		return "#signer-allowlist-invalid-format"
	case auditTrailAppendUnavailableCode:
		return "#audit-trail-append-failed"
	case teamBoundaryBreakGlassEnvPresentCode:
		return "#break-glass-override-left-enabled"
	case teamBoundaryBreakGlassGuardrailWeakCode:
		return "#break-glass-guardrail-weak"
	case teamBoundaryBreakGlassTokenInvalidCode:
		return "#break-glass-token-invalid"
	case teamBoundaryBreakGlassTokenExpiredCode:
		return "#break-glass-token-expired"
	case "policy_set_skew_detected":
		return "#policy-set-consistency-reason"
	case "policy_sync_slo_breached":
		return "#policy-sync-slo-breached"
	case "policy_scan_posture_violation":
		return "#policy-scan-posture-violation"
	case "sync_backlog_slo_breached":
		return "#sync-backlog-slo-breached-v070"
	case "ingest_ack_mismatch":
		return "#ingest-ack-mismatch-v070"
	default:
		return ""
	}
}
