package main

import (
	"encoding/json"
	"testing"
)

func TestNewTrustStatusSuccess_DefaultReceipt(t *testing.T) {
	got := newTrustStatusSuccess("")
	if !got.Verified {
		t.Fatalf("Verified = false, want true")
	}
	if got.Receipt != "none" {
		t.Fatalf("Receipt = %q, want none", got.Receipt)
	}
	want := "TRUST: verified=true tamper=false policy=pass receipt=none"
	if got.Line != want {
		t.Fatalf("Line = %q, want %q", got.Line, want)
	}
}

func TestNewTrustStatusFailure_Reason(t *testing.T) {
	got := newTrustStatusFailure(ztErrorCodeSendPackFail)
	if got.Verified {
		t.Fatalf("Verified = true, want false")
	}
	if got.Reason != ztErrorCodeSendPackFail {
		t.Fatalf("Reason = %q", got.Reason)
	}
	want := "TRUST: verified=false tamper=unknown policy=fail reason=" + ztErrorCodeSendPackFail
	if got.Line != want {
		t.Fatalf("Line = %q, want %q", got.Line, want)
	}
}

func TestBuildQuickFixBundle_UsesRetryWhenNoFixes(t *testing.T) {
	got := buildQuickFixBundle("setup checks failed", nil, "zt setup --json")
	if got == nil {
		t.Fatalf("bundle = nil")
	}
	if len(got.Commands) != 1 || got.Commands[0] != "zt setup --json" {
		t.Fatalf("Commands = %#v", got.Commands)
	}
	if got.Runbook != "docs/OPERATIONS.md" {
		t.Fatalf("Runbook = %q", got.Runbook)
	}
}

func TestFailureEnvelope_Contract(t *testing.T) {
	bundle := buildQuickFixBundle("setup checks failed", []string{"zt setup --json", "zt setup --json", "zt sync --force"}, "zt setup --json")
	payload := struct {
		ErrorCode      string          `json:"error_code"`
		Summary        string          `json:"summary"`
		QuickFixBundle *quickFixBundle `json:"quick_fix_bundle,omitempty"`
	}{
		ErrorCode:      ztErrorCodeSetupChecksFailed,
		Summary:        "setup checks failed",
		QuickFixBundle: bundle,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal returned error: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}
	if got["error_code"] != ztErrorCodeSetupChecksFailed {
		t.Fatalf("error_code = %v", got["error_code"])
	}
	if got["summary"] != "setup checks failed" {
		t.Fatalf("summary = %v", got["summary"])
	}
	qfb, ok := got["quick_fix_bundle"].(map[string]any)
	if !ok {
		t.Fatalf("quick_fix_bundle missing or invalid: %#v", got["quick_fix_bundle"])
	}
	if qfb["why"] != "setup checks failed" {
		t.Fatalf("why = %v", qfb["why"])
	}
	if qfb["runbook"] != "docs/OPERATIONS.md" {
		t.Fatalf("runbook = %v", qfb["runbook"])
	}
	if qfb["retry"] != "zt setup --json" {
		t.Fatalf("retry = %v", qfb["retry"])
	}
	commands, ok := qfb["commands"].([]any)
	if !ok || len(commands) != 2 {
		t.Fatalf("commands = %#v, want deduped length 2", qfb["commands"])
	}
}

func TestBuildQuickFixBundleWithCode_RunbookAnchorContract(t *testing.T) {
	got := buildQuickFixBundleWithCode("sync attention required", []string{"zt sync --force --json"}, "zt sync --force --json", syncErrorCodeBacklogSLOBreached)
	if got == nil {
		t.Fatalf("bundle = nil")
	}
	if got.Runbook != "docs/OPERATIONS.md" {
		t.Fatalf("Runbook = %q", got.Runbook)
	}
	if got.RunbookAnchor != "#sync-backlog-slo-breached-v070" {
		t.Fatalf("RunbookAnchor = %q, want #sync-backlog-slo-breached-v070", got.RunbookAnchor)
	}
}

func TestBuildQuickFixBundleWithCode_V092RunbookMappingContract(t *testing.T) {
	got := buildQuickFixBundleWithCode(
		"verify signer mismatch",
		[]string{"update signer allowlist"},
		"zt verify -- ./bundle.spkg.tgz",
		ztErrorCodeVerifySignerPinMismatch,
	)
	if got == nil {
		t.Fatalf("bundle = nil")
	}
	if got.Runbook != "docs/V0.9.2_ABNORMAL_USECASES.md" {
		t.Fatalf("Runbook = %q, want docs/V0.9.2_ABNORMAL_USECASES.md", got.Runbook)
	}
	if got.RunbookAnchor != "#signer-key-loss" {
		t.Fatalf("RunbookAnchor = %q, want #signer-key-loss", got.RunbookAnchor)
	}
}

func TestBuildQuickFixBundleWithCode_V092RunbookAnchorMatrix(t *testing.T) {
	tests := []struct {
		name   string
		code   string
		anchor string
	}{
		{
			name:   "send policy",
			code:   ztErrorCodeSendBoundaryPolicy,
			anchor: "#team-boundary-policy-missing-or-invalid",
		},
		{
			name:   "verify policy",
			code:   ztErrorCodeVerifyBoundaryPolicy,
			anchor: "#team-boundary-policy-missing-or-invalid",
		},
		{
			name:   "recipient denied",
			code:   ztErrorCodeSendBoundaryClient,
			anchor: "#recipient-boundary-denied",
		},
		{
			name:   "route denied",
			code:   ztErrorCodeSendBoundaryRoute,
			anchor: "#share-route-boundary-denied",
		},
		{
			name:   "send break-glass reason required",
			code:   ztErrorCodeSendBoundaryBreakGlassReasonRequired,
			anchor: "#break-glass-reason-required",
		},
		{
			name:   "send break-glass env present",
			code:   ztErrorCodeSendBoundaryBreakGlassEnvPresent,
			anchor: "#break-glass-override-left-enabled",
		},
		{
			name:   "send break-glass token invalid",
			code:   ztErrorCodeSendBoundaryBreakGlassTokenInvalid,
			anchor: "#break-glass-token-invalid",
		},
		{
			name:   "send break-glass token expired",
			code:   ztErrorCodeSendBoundaryBreakGlassTokenExpired,
			anchor: "#break-glass-token-expired",
		},
		{
			name:   "send audit append failed",
			code:   ztErrorCodeSendAuditAppendFail,
			anchor: "#audit-trail-append-failed",
		},
		{
			name:   "signer denied",
			code:   ztErrorCodeVerifyBoundarySigner,
			anchor: "#signer-boundary-denied",
		},
		{
			name:   "verify break-glass reason required",
			code:   ztErrorCodeVerifyBoundaryBreakGlassReasonRequired,
			anchor: "#break-glass-reason-required",
		},
		{
			name:   "verify break-glass env present",
			code:   ztErrorCodeVerifyBoundaryBreakGlassEnvPresent,
			anchor: "#break-glass-override-left-enabled",
		},
		{
			name:   "verify break-glass token invalid",
			code:   ztErrorCodeVerifyBoundaryBreakGlassTokenInvalid,
			anchor: "#break-glass-token-invalid",
		},
		{
			name:   "verify break-glass token expired",
			code:   ztErrorCodeVerifyBoundaryBreakGlassTokenExpired,
			anchor: "#break-glass-token-expired",
		},
		{
			name:   "signer missing",
			code:   ztErrorCodeVerifySignerPinMissing,
			anchor: "#signer-allowlist-missing",
		},
		{
			name:   "signer mismatch",
			code:   ztErrorCodeVerifySignerPinMismatch,
			anchor: "#signer-key-loss",
		},
		{
			name:   "signer config invalid",
			code:   ztErrorCodeVerifySignerPinConfig,
			anchor: "#signer-allowlist-invalid-format",
		},
		{
			name:   "verify audit append failed",
			code:   ztErrorCodeVerifyAuditAppendFail,
			anchor: "#audit-trail-append-failed",
		},
		{
			name:   "secure-pack signer missing",
			code:   "SP_SIGNER_PIN_MISSING",
			anchor: "#signer-allowlist-missing",
		},
		{
			name:   "secure-pack signer mismatch",
			code:   "SP_SIGNER_PIN_MISMATCH",
			anchor: "#signer-key-loss",
		},
		{
			name:   "secure-pack signer config invalid",
			code:   "SP_SIGNER_PIN_CONFIG_INVALID",
			anchor: "#signer-allowlist-invalid-format",
		},
		{
			name:   "team boundary split brain",
			code:   teamBoundarySignerSplitBrainCode,
			anchor: "#signer-policy-split-brain-detected",
		},
		{
			name:   "team boundary signer pin missing",
			code:   teamBoundarySignerPinMissingCode,
			anchor: "#signer-allowlist-missing",
		},
		{
			name:   "team boundary signer pin invalid",
			code:   teamBoundarySignerPinConfigInvalidCode,
			anchor: "#signer-allowlist-invalid-format",
		},
		{
			name:   "audit trail append unavailable",
			code:   auditTrailAppendUnavailableCode,
			anchor: "#audit-trail-append-failed",
		},
		{
			name:   "break-glass env present",
			code:   teamBoundaryBreakGlassEnvPresentCode,
			anchor: "#break-glass-override-left-enabled",
		},
		{
			name:   "break-glass guardrail weak",
			code:   teamBoundaryBreakGlassGuardrailWeakCode,
			anchor: "#break-glass-guardrail-weak",
		},
		{
			name:   "break-glass reason required policy",
			code:   teamBoundaryBreakGlassReasonRequiredCode,
			anchor: "#break-glass-reason-required",
		},
		{
			name:   "break-glass token invalid",
			code:   teamBoundaryBreakGlassTokenInvalidCode,
			anchor: "#break-glass-token-invalid",
		},
		{
			name:   "break-glass token expired",
			code:   teamBoundaryBreakGlassTokenExpiredCode,
			anchor: "#break-glass-token-expired",
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := buildQuickFixBundleWithCode("v0.9.2 failure", nil, "zt verify -- ./bundle.spkg.tgz", tc.code)
			if got == nil {
				t.Fatalf("bundle = nil")
			}
			if got.Runbook != "docs/V0.9.2_ABNORMAL_USECASES.md" {
				t.Fatalf("Runbook = %q, want docs/V0.9.2_ABNORMAL_USECASES.md", got.Runbook)
			}
			if got.RunbookAnchor != tc.anchor {
				t.Fatalf("RunbookAnchor = %q, want %q", got.RunbookAnchor, tc.anchor)
			}
		})
	}
}
