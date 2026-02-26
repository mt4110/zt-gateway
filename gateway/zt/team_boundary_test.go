package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestResolveTeamBoundaryPolicy_DisabledPolicyIsNotActive(t *testing.T) {
	repoRoot := t.TempDir()
	policyDir := filepath.Join(repoRoot, "policy")
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	content := "" +
		"enabled = false\n" +
		"tenant_id = \"corp-example\"\n" +
		"team_id = \"secops\"\n" +
		"boundary_policy_version = \"2026-02-26\"\n" +
		"allowed_recipients = [\"clientA\"]\n" +
		"allowed_signer_fingerprints = [\"0123456789ABCDEF0123456789ABCDEF01234567\"]\n" +
		"allowed_share_routes = [\"stdout\", \"none\"]\n"
	if err := os.WriteFile(filepath.Join(policyDir, "team_boundary.toml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	pol, active, err := resolveTeamBoundaryPolicy(repoRoot)
	if err != nil {
		t.Fatalf("resolveTeamBoundaryPolicy() error = %v", err)
	}
	if active {
		t.Fatalf("active = true, want false")
	}
	if pol.TenantID != "corp-example" {
		t.Fatalf("TenantID = %q", pol.TenantID)
	}
}

func TestResolveTeamBoundaryPolicy_RequiredMissingFails(t *testing.T) {
	repoRoot := t.TempDir()
	t.Setenv(teamBoundaryRequiredEnv, "1")
	_, _, err := resolveTeamBoundaryPolicy(repoRoot)
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestResolveTeamBoundaryPolicy_NegativeBreakGlassTTLRejected(t *testing.T) {
	repoRoot := t.TempDir()
	policyDir := filepath.Join(repoRoot, "policy")
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	content := "" +
		"enabled = true\n" +
		"tenant_id = \"corp-example\"\n" +
		"team_id = \"secops\"\n" +
		"boundary_policy_version = \"2026-02-26\"\n" +
		"allowed_recipients = [\"clientA\"]\n" +
		"allowed_signer_fingerprints = [\"0123456789ABCDEF0123456789ABCDEF01234567\"]\n" +
		"allowed_share_routes = [\"stdout\"]\n" +
		"break_glass_max_ttl_minutes = -1\n"
	if err := os.WriteFile(filepath.Join(policyDir, "team_boundary.toml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err := resolveTeamBoundaryPolicy(repoRoot)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "break_glass_max_ttl_minutes") {
		t.Fatalf("error = %q", err.Error())
	}
}

func TestResolveTeamBoundaryPolicy_BreakGlassStrictGuardrailRequired(t *testing.T) {
	repoRoot := t.TempDir()
	policyDir := filepath.Join(repoRoot, "policy")
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	content := "" +
		"enabled = true\n" +
		"tenant_id = \"corp-example\"\n" +
		"team_id = \"secops\"\n" +
		"boundary_policy_version = \"2026-02-26\"\n" +
		"allowed_recipients = [\"clientA\"]\n" +
		"allowed_signer_fingerprints = [\"0123456789ABCDEF0123456789ABCDEF01234567\"]\n" +
		"allowed_share_routes = [\"stdout\"]\n" +
		"break_glass_enabled = true\n" +
		"break_glass_require_reason = true\n"
	if err := os.WriteFile(filepath.Join(policyDir, "team_boundary.toml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	_, _, err := resolveTeamBoundaryPolicy(repoRoot)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "strict guardrail") {
		t.Fatalf("error = %q", err.Error())
	}
}

func TestEnforceTeamBoundaryForSend_RecipientDenied(t *testing.T) {
	pol := teamBoundaryPolicy{
		Enabled:                   true,
		TenantID:                  "corp",
		TeamID:                    "secops",
		BoundaryPolicyVersion:     "v1",
		AllowedRecipients:         []string{"clientA"},
		AllowedShareRoutes:        []string{"stdout"},
		AllowedSignerFingerprints: []string{"0123456789ABCDEF0123456789ABCDEF01234567"},
	}
	_, _, err := enforceTeamBoundaryForSend(pol, sendOptions{Client: "clientB"})
	if err == nil {
		t.Fatalf("expected boundary error")
	}
}

func TestEnforceTeamBoundaryForSend_BreakGlassAllows(t *testing.T) {
	pol := teamBoundaryPolicy{
		Enabled:                   true,
		TenantID:                  "corp",
		TeamID:                    "secops",
		BoundaryPolicyVersion:     "v1",
		AllowedRecipients:         []string{"clientA"},
		AllowedShareRoutes:        []string{"stdout"},
		AllowedSignerFingerprints: []string{"0123456789ABCDEF0123456789ABCDEF01234567"},
		BreakGlassEnabled:         true,
		BreakGlassRequireReason:   true,
		BreakGlassRequireApprover: true,
		BreakGlassMaxTTLMinutes:   120,
	}
	expiresAt := time.Now().UTC().Add(30 * time.Minute).Format(time.RFC3339)
	used, reason, err := enforceTeamBoundaryForSend(pol, sendOptions{
		Client:           "clientB",
		BreakGlassReason: "incident=inc-9202;approved_by=alice;expires_at=" + expiresAt,
	})
	if err != nil {
		t.Fatalf("enforceTeamBoundaryForSend() error = %v", err)
	}
	if !used {
		t.Fatalf("break-glass used = false, want true")
	}
	if !strings.Contains(reason, "incident=inc-9202") {
		t.Fatalf("reason = %q", reason)
	}
}

func TestEnforceTeamBoundaryForSend_BreakGlassWeakGuardrailFailsClosed(t *testing.T) {
	pol := teamBoundaryPolicy{
		Enabled:                   true,
		TenantID:                  "corp",
		TeamID:                    "secops",
		BoundaryPolicyVersion:     "v1",
		AllowedRecipients:         []string{"clientA"},
		AllowedShareRoutes:        []string{"stdout"},
		AllowedSignerFingerprints: []string{"0123456789ABCDEF0123456789ABCDEF01234567"},
		BreakGlassEnabled:         true,
		BreakGlassRequireReason:   true,
	}
	_, _, err := enforceTeamBoundaryForSend(pol, sendOptions{
		Client:           "clientB",
		BreakGlassReason: "incident=inc-weak;approved_by=alice;expires_at=2099-01-01T00:00:00Z",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := classifyTeamBoundaryEnforcementError(err); got != teamBoundaryBreakGlassGuardrailWeakCode {
		t.Fatalf("enforcement code = %q, want %q", got, teamBoundaryBreakGlassGuardrailWeakCode)
	}
}

func TestEnforceTeamBoundaryForSend_BreakGlassGuardrailExpiredDenied(t *testing.T) {
	pol := teamBoundaryPolicy{
		Enabled:                   true,
		TenantID:                  "corp",
		TeamID:                    "secops",
		BoundaryPolicyVersion:     "v1",
		AllowedRecipients:         []string{"clientA"},
		AllowedShareRoutes:        []string{"stdout"},
		AllowedSignerFingerprints: []string{"0123456789ABCDEF0123456789ABCDEF01234567"},
		BreakGlassEnabled:         true,
		BreakGlassRequireReason:   true,
		BreakGlassRequireApprover: true,
		BreakGlassMaxTTLMinutes:   60,
	}
	_, _, err := enforceTeamBoundaryForSend(pol, sendOptions{
		Client:           "clientB",
		BreakGlassReason: "incident=inc-1;approved_by=alice;expires_at=2000-01-01T00:00:00Z",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("error = %q, want expired", err.Error())
	}
	if got := classifyTeamBoundaryEnforcementError(err); got != teamBoundaryBreakGlassTokenExpiredCode {
		t.Fatalf("enforcement code = %q, want %q", got, teamBoundaryBreakGlassTokenExpiredCode)
	}
}

func TestEnforceTeamBoundaryForSend_BreakGlassGuardrailApproverRequired(t *testing.T) {
	pol := teamBoundaryPolicy{
		Enabled:                   true,
		TenantID:                  "corp",
		TeamID:                    "secops",
		BoundaryPolicyVersion:     "v1",
		AllowedRecipients:         []string{"clientA"},
		AllowedShareRoutes:        []string{"stdout"},
		AllowedSignerFingerprints: []string{"0123456789ABCDEF0123456789ABCDEF01234567"},
		BreakGlassEnabled:         true,
		BreakGlassRequireReason:   true,
		BreakGlassRequireApprover: true,
		BreakGlassMaxTTLMinutes:   60,
	}
	_, _, err := enforceTeamBoundaryForSend(pol, sendOptions{
		Client:           "clientB",
		BreakGlassReason: "incident=inc-2;expires_at=2099-01-01T00:00:00Z",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "approved_by") {
		t.Fatalf("error = %q, want approved_by", err.Error())
	}
	if got := classifyTeamBoundaryEnforcementError(err); got != teamBoundaryBreakGlassTokenInvalidCode {
		t.Fatalf("enforcement code = %q, want %q", got, teamBoundaryBreakGlassTokenInvalidCode)
	}
}

func TestEnforceTeamBoundaryForSend_BreakGlassGuardrailTokenAccepted(t *testing.T) {
	pol := teamBoundaryPolicy{
		Enabled:                   true,
		TenantID:                  "corp",
		TeamID:                    "secops",
		BoundaryPolicyVersion:     "v1",
		AllowedRecipients:         []string{"clientA"},
		AllowedShareRoutes:        []string{"stdout"},
		AllowedSignerFingerprints: []string{"0123456789ABCDEF0123456789ABCDEF01234567"},
		BreakGlassEnabled:         true,
		BreakGlassRequireReason:   true,
		BreakGlassRequireApprover: true,
		BreakGlassMaxTTLMinutes:   120,
	}
	expiresAt := time.Now().UTC().Add(30 * time.Minute).Format(time.RFC3339)
	used, reason, err := enforceTeamBoundaryForSend(pol, sendOptions{
		Client:           "clientB",
		BreakGlassReason: "incident=inc-3;approved_by=bob;expires_at=" + expiresAt,
	})
	if err != nil {
		t.Fatalf("enforceTeamBoundaryForSend() error = %v", err)
	}
	if !used {
		t.Fatalf("break-glass used = false, want true")
	}
	if !strings.Contains(reason, "incident=inc-3") {
		t.Fatalf("reason = %q", reason)
	}
}

func TestEnforceTeamBoundaryForSigner_BreakGlassReasonRequired(t *testing.T) {
	pol := teamBoundaryPolicy{
		Enabled:                   true,
		TenantID:                  "corp",
		TeamID:                    "secops",
		BoundaryPolicyVersion:     "v1",
		AllowedRecipients:         []string{"clientA"},
		AllowedShareRoutes:        []string{"stdout"},
		AllowedSignerFingerprints: []string{"0123456789ABCDEF0123456789ABCDEF01234567"},
		BreakGlassEnabled:         true,
		BreakGlassRequireReason:   true,
		BreakGlassRequireApprover: true,
		BreakGlassMaxTTLMinutes:   60,
	}
	_, _, err := enforceTeamBoundaryForSigner(pol, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", verifyOptions{})
	if err == nil {
		t.Fatalf("expected boundary error")
	}
	if got := classifyTeamBoundaryEnforcementError(err); got != teamBoundaryBreakGlassReasonRequiredCode {
		t.Fatalf("enforcement code = %q, want %q", got, teamBoundaryBreakGlassReasonRequiredCode)
	}
}

func TestEnforceTeamBoundaryBreakGlassStartupGuardrail_EnvPresent(t *testing.T) {
	pol := teamBoundaryPolicy{
		Enabled:           true,
		BreakGlassEnabled: true,
	}
	t.Setenv(teamBoundaryBreakGlassEnv, "incident=inc-1;approved_by=alice;expires_at=2099-01-01T00:00:00Z")

	err := enforceTeamBoundaryBreakGlassStartupGuardrail(pol)
	if err == nil {
		t.Fatalf("expected guardrail error")
	}
	if got := classifyTeamBoundaryEnforcementError(err); got != teamBoundaryBreakGlassEnvPresentCode {
		t.Fatalf("enforcement code = %q, want %q", got, teamBoundaryBreakGlassEnvPresentCode)
	}
}

func TestEnforceTeamBoundaryBreakGlassStartupGuardrail_EnvPresentWhenBreakGlassDisabled(t *testing.T) {
	pol := teamBoundaryPolicy{
		Enabled:           true,
		BreakGlassEnabled: false,
	}
	t.Setenv(teamBoundaryBreakGlassEnv, "incident=inc-1;approved_by=alice;expires_at=2099-01-01T00:00:00Z")
	err := enforceTeamBoundaryBreakGlassStartupGuardrail(pol)
	if err == nil {
		t.Fatalf("expected guardrail error")
	}
	if got := classifyTeamBoundaryEnforcementError(err); got != teamBoundaryBreakGlassEnvPresentCode {
		t.Fatalf("enforcement code = %q, want %q", got, teamBoundaryBreakGlassEnvPresentCode)
	}
}

func TestEnforceTeamBoundaryBreakGlassStartupGuardrail_EnvAbsent(t *testing.T) {
	pol := teamBoundaryPolicy{
		Enabled:           true,
		BreakGlassEnabled: true,
	}
	t.Setenv(teamBoundaryBreakGlassEnv, "")
	if err := enforceTeamBoundaryBreakGlassStartupGuardrail(pol); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestClassifyTeamBoundarySendEnforcementError_BreakGlassCases(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantZT     string
		wantReason string
	}{
		{
			name:       "env present",
			err:        &teamBoundaryEnforceError{Code: teamBoundaryBreakGlassEnvPresentCode, Message: "env present"},
			wantZT:     ztErrorCodeSendBoundaryBreakGlassEnvPresent,
			wantReason: teamBoundaryBreakGlassEnvPresentCode,
		},
		{
			name:       "guardrail weak",
			err:        &teamBoundaryEnforceError{Code: teamBoundaryBreakGlassGuardrailWeakCode, Message: "guardrail weak"},
			wantZT:     ztErrorCodeSendBoundaryPolicy,
			wantReason: teamBoundaryBreakGlassGuardrailWeakCode,
		},
		{
			name:       "reason required",
			err:        &teamBoundaryEnforceError{Code: teamBoundaryBreakGlassReasonRequiredCode, Message: "reason required"},
			wantZT:     ztErrorCodeSendBoundaryBreakGlassReasonRequired,
			wantReason: teamBoundaryBreakGlassReasonRequiredCode,
		},
		{
			name:       "token invalid",
			err:        &teamBoundaryEnforceError{Code: teamBoundaryBreakGlassTokenInvalidCode, Message: "token invalid"},
			wantZT:     ztErrorCodeSendBoundaryBreakGlassTokenInvalid,
			wantReason: teamBoundaryBreakGlassTokenInvalidCode,
		},
		{
			name:       "token expired",
			err:        &teamBoundaryEnforceError{Code: teamBoundaryBreakGlassTokenExpiredCode, Message: "token expired"},
			wantZT:     ztErrorCodeSendBoundaryBreakGlassTokenExpired,
			wantReason: teamBoundaryBreakGlassTokenExpiredCode,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			gotZT, gotReason := classifyTeamBoundarySendEnforcementError(tc.err)
			if gotZT != tc.wantZT {
				t.Fatalf("zt code = %q, want %q", gotZT, tc.wantZT)
			}
			if gotReason != tc.wantReason {
				t.Fatalf("reason code = %q, want %q", gotReason, tc.wantReason)
			}
		})
	}
}

func TestClassifyTeamBoundaryVerifyEnforcementError_BreakGlassCases(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantZT     string
		wantReason string
	}{
		{
			name:       "env present",
			err:        &teamBoundaryEnforceError{Code: teamBoundaryBreakGlassEnvPresentCode, Message: "env present"},
			wantZT:     ztErrorCodeVerifyBoundaryBreakGlassEnvPresent,
			wantReason: teamBoundaryBreakGlassEnvPresentCode,
		},
		{
			name:       "guardrail weak",
			err:        &teamBoundaryEnforceError{Code: teamBoundaryBreakGlassGuardrailWeakCode, Message: "guardrail weak"},
			wantZT:     ztErrorCodeVerifyBoundaryPolicy,
			wantReason: teamBoundaryBreakGlassGuardrailWeakCode,
		},
		{
			name:       "reason required",
			err:        &teamBoundaryEnforceError{Code: teamBoundaryBreakGlassReasonRequiredCode, Message: "reason required"},
			wantZT:     ztErrorCodeVerifyBoundaryBreakGlassReasonRequired,
			wantReason: teamBoundaryBreakGlassReasonRequiredCode,
		},
		{
			name:       "token invalid",
			err:        &teamBoundaryEnforceError{Code: teamBoundaryBreakGlassTokenInvalidCode, Message: "token invalid"},
			wantZT:     ztErrorCodeVerifyBoundaryBreakGlassTokenInvalid,
			wantReason: teamBoundaryBreakGlassTokenInvalidCode,
		},
		{
			name:       "token expired",
			err:        &teamBoundaryEnforceError{Code: teamBoundaryBreakGlassTokenExpiredCode, Message: "token expired"},
			wantZT:     ztErrorCodeVerifyBoundaryBreakGlassTokenExpired,
			wantReason: teamBoundaryBreakGlassTokenExpiredCode,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			gotZT, gotReason := classifyTeamBoundaryVerifyEnforcementError(tc.err)
			if gotZT != tc.wantZT {
				t.Fatalf("zt code = %q, want %q", gotZT, tc.wantZT)
			}
			if gotReason != tc.wantReason {
				t.Fatalf("reason code = %q, want %q", gotReason, tc.wantReason)
			}
		})
	}
}

func TestResolveEffectiveShareRouteKinds_Contract(t *testing.T) {
	routes, err := resolveEffectiveShareRouteKinds(sendOptions{})
	if err != nil {
		t.Fatalf("resolveEffectiveShareRouteKinds() error = %v", err)
	}
	if len(routes) != 1 || routes[0] != "stdout" {
		t.Fatalf("routes = %v, want [stdout]", routes)
	}

	routes, err = resolveEffectiveShareRouteKinds(sendOptions{ShareRoutes: []string{"none"}})
	if err != nil {
		t.Fatalf("resolveEffectiveShareRouteKinds(none) error = %v", err)
	}
	if len(routes) != 1 || routes[0] != "none" {
		t.Fatalf("routes = %v, want [none]", routes)
	}
}

func TestApplyTeamBoundaryMetadata(t *testing.T) {
	setActiveTeamBoundaryContext(&teamBoundaryRuntimeContext{
		TenantID:              "corp-example",
		TeamID:                "secops",
		BoundaryPolicyVersion: "2026-02-26",
		BreakGlass:            true,
		BreakGlassReason:      "incident-1",
	})
	defer setActiveTeamBoundaryContext(nil)

	payload := map[string]any{"event_id": "x"}
	applyTeamBoundaryMetadata(payload)
	if payload["tenant_id"] != "corp-example" {
		t.Fatalf("tenant_id = %v", payload["tenant_id"])
	}
	if payload["team_id"] != "secops" {
		t.Fatalf("team_id = %v", payload["team_id"])
	}
	if payload["boundary_policy_version"] != "2026-02-26" {
		t.Fatalf("boundary_policy_version = %v", payload["boundary_policy_version"])
	}
}

func TestBuildTeamBoundarySetupChecks_SignerPinConsistencySplitBrain(t *testing.T) {
	repoRoot := t.TempDir()
	fpPolicy := "0123456789ABCDEF0123456789ABCDEF01234567"
	fpVerify := "89ABCDEF0123456789ABCDEF0123456789ABCDEF"
	writeTeamBoundaryPolicyFixture(t, repoRoot, fpPolicy)
	if err := os.MkdirAll(filepath.Join(repoRoot, "tools", "secure-pack"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(repoRoot, "tools", "secure-pack", "SIGNERS_ALLOWLIST.txt"),
		[]byte(fpVerify+"\n"),
		0o644,
	); err != nil {
		t.Fatal(err)
	}

	checks, quickFixes := buildTeamBoundarySetupChecks(repoRoot)
	c, ok := findSetupCheckByName(checks, teamBoundarySignerPinConsistencyCheckName)
	if !ok {
		t.Fatalf("missing check: %s", teamBoundarySignerPinConsistencyCheckName)
	}
	if c.Status != "fail" {
		t.Fatalf("status = %q, want fail", c.Status)
	}
	if c.Code != teamBoundarySignerSplitBrainCode {
		t.Fatalf("code = %q, want %q", c.Code, teamBoundarySignerSplitBrainCode)
	}
	if !strings.Contains(c.Message, "missing_in_verify") {
		t.Fatalf("message = %q, want split-brain details", c.Message)
	}
	if len(quickFixes) == 0 {
		t.Fatalf("quickFixes should not be empty")
	}
}

func TestBuildTeamBoundarySetupChecks_SignerPinConsistencyMissing(t *testing.T) {
	repoRoot := t.TempDir()
	fpPolicy := "0123456789ABCDEF0123456789ABCDEF01234567"
	writeTeamBoundaryPolicyFixture(t, repoRoot, fpPolicy)

	checks, _ := buildTeamBoundarySetupChecks(repoRoot)
	c, ok := findSetupCheckByName(checks, teamBoundarySignerPinConsistencyCheckName)
	if !ok {
		t.Fatalf("missing check: %s", teamBoundarySignerPinConsistencyCheckName)
	}
	if c.Status != "fail" {
		t.Fatalf("status = %q, want fail", c.Status)
	}
	if c.Code != teamBoundarySignerPinMissingCode {
		t.Fatalf("code = %q, want %q", c.Code, teamBoundarySignerPinMissingCode)
	}
}

func TestBuildTeamBoundarySetupChecks_SignerPinConsistencyOK(t *testing.T) {
	repoRoot := t.TempDir()
	fpPolicy := "0123456789ABCDEF0123456789ABCDEF01234567"
	writeTeamBoundaryPolicyFixture(t, repoRoot, fpPolicy)
	if err := os.MkdirAll(filepath.Join(repoRoot, "tools", "secure-pack"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(repoRoot, "tools", "secure-pack", "SIGNERS_ALLOWLIST.txt"),
		[]byte("# allowlist\n"+fpPolicy+"\n"),
		0o644,
	); err != nil {
		t.Fatal(err)
	}

	checks, _ := buildTeamBoundarySetupChecks(repoRoot)
	c, ok := findSetupCheckByName(checks, teamBoundarySignerPinConsistencyCheckName)
	if !ok {
		t.Fatalf("missing check: %s", teamBoundarySignerPinConsistencyCheckName)
	}
	if c.Status != "ok" {
		t.Fatalf("status = %q, want ok", c.Status)
	}
	if c.Code != "" {
		t.Fatalf("code = %q, want empty", c.Code)
	}
}

func TestBuildTeamBoundarySetupChecks_BreakGlassGuardrailWeak(t *testing.T) {
	repoRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repoRoot, "policy"), 0o755); err != nil {
		t.Fatal(err)
	}
	content := "" +
		"enabled = true\n" +
		"tenant_id = \"corp-example\"\n" +
		"team_id = \"secops\"\n" +
		"boundary_policy_version = \"2026-02-26\"\n" +
		"allowed_recipients = [\"clientA\"]\n" +
		"allowed_signer_fingerprints = [\"0123456789ABCDEF0123456789ABCDEF01234567\"]\n" +
		"allowed_share_routes = [\"stdout\"]\n" +
		"break_glass_enabled = true\n" +
		"break_glass_require_reason = true\n"
	if err := os.WriteFile(filepath.Join(repoRoot, "policy", "team_boundary.toml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	checks, _ := buildTeamBoundarySetupChecks(repoRoot)
	c, ok := findSetupCheckByName(checks, teamBoundaryBreakGlassGuardrailCheckName)
	if !ok {
		t.Fatalf("missing check: %s", teamBoundaryBreakGlassGuardrailCheckName)
	}
	if c.Status != "fail" {
		t.Fatalf("status = %q, want fail", c.Status)
	}
	if c.Code != teamBoundaryBreakGlassGuardrailWeakCode {
		t.Fatalf("code = %q, want %q", c.Code, teamBoundaryBreakGlassGuardrailWeakCode)
	}
}

func TestBuildTeamBoundarySetupChecks_BreakGlassEnvPresentDetected(t *testing.T) {
	repoRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repoRoot, "policy"), 0o755); err != nil {
		t.Fatal(err)
	}
	content := "" +
		"enabled = true\n" +
		"tenant_id = \"corp-example\"\n" +
		"team_id = \"secops\"\n" +
		"boundary_policy_version = \"2026-02-26\"\n" +
		"allowed_recipients = [\"clientA\"]\n" +
		"allowed_signer_fingerprints = [\"0123456789ABCDEF0123456789ABCDEF01234567\"]\n" +
		"allowed_share_routes = [\"stdout\"]\n" +
		"break_glass_enabled = true\n" +
		"break_glass_require_reason = true\n" +
		"break_glass_require_approver = true\n" +
		"break_glass_max_ttl_minutes = 60\n"
	if err := os.WriteFile(filepath.Join(repoRoot, "policy", "team_boundary.toml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	expiresAt := time.Now().UTC().Add(20 * time.Minute).Format(time.RFC3339)
	t.Setenv(teamBoundaryBreakGlassEnv, "incident=inc-env;approved_by=alice;expires_at="+expiresAt)
	checks, _ := buildTeamBoundarySetupChecks(repoRoot)
	c, ok := findSetupCheckByName(checks, teamBoundaryBreakGlassGuardrailCheckName)
	if !ok {
		t.Fatalf("missing check: %s", teamBoundaryBreakGlassGuardrailCheckName)
	}
	if c.Status != "fail" {
		t.Fatalf("status = %q, want fail", c.Status)
	}
	if c.Code != teamBoundaryBreakGlassEnvPresentCode {
		t.Fatalf("code = %q, want %q", c.Code, teamBoundaryBreakGlassEnvPresentCode)
	}
}

func TestBuildTeamBoundarySetupChecks_BreakGlassEnvPresentDetectedWhenDisabled(t *testing.T) {
	repoRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repoRoot, "policy"), 0o755); err != nil {
		t.Fatal(err)
	}
	content := "" +
		"enabled = true\n" +
		"tenant_id = \"corp-example\"\n" +
		"team_id = \"secops\"\n" +
		"boundary_policy_version = \"2026-02-26\"\n" +
		"allowed_recipients = [\"clientA\"]\n" +
		"allowed_signer_fingerprints = [\"0123456789ABCDEF0123456789ABCDEF01234567\"]\n" +
		"allowed_share_routes = [\"stdout\"]\n" +
		"break_glass_enabled = false\n"
	if err := os.WriteFile(filepath.Join(repoRoot, "policy", "team_boundary.toml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(teamBoundaryBreakGlassEnv, "incident=inc-env;approved_by=alice;expires_at=2099-01-01T00:00:00Z")
	checks, _ := buildTeamBoundarySetupChecks(repoRoot)
	c, ok := findSetupCheckByName(checks, teamBoundaryBreakGlassGuardrailCheckName)
	if !ok {
		t.Fatalf("missing check: %s", teamBoundaryBreakGlassGuardrailCheckName)
	}
	if c.Status != "fail" {
		t.Fatalf("status = %q, want fail", c.Status)
	}
	if c.Code != teamBoundaryBreakGlassEnvPresentCode {
		t.Fatalf("code = %q, want %q", c.Code, teamBoundaryBreakGlassEnvPresentCode)
	}
}

func writeTeamBoundaryPolicyFixture(t *testing.T, repoRoot, signerFingerprint string) {
	t.Helper()
	policyDir := filepath.Join(repoRoot, "policy")
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	content := "" +
		"enabled = true\n" +
		"tenant_id = \"corp-example\"\n" +
		"team_id = \"secops\"\n" +
		"boundary_policy_version = \"2026-02-26\"\n" +
		"allowed_recipients = [\"clientA\"]\n" +
		"allowed_signer_fingerprints = [\"" + signerFingerprint + "\"]\n" +
		"allowed_share_routes = [\"stdout\"]\n"
	if err := os.WriteFile(filepath.Join(policyDir, "team_boundary.toml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func findSetupCheckByName(checks []setupCheck, name string) (setupCheck, bool) {
	for _, c := range checks {
		if c.Name == name {
			return c, true
		}
	}
	return setupCheck{}, false
}
