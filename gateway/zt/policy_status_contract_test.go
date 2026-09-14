package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPolicyStatusContract_JSONRequiredFields(t *testing.T) {
	repoRoot := t.TempDir()
	stateDir := filepath.Join(repoRoot, ".zt-policy-state")
	t.Setenv("ZT_POLICY_STATE_DIR", stateDir)
	t.Setenv("ZT_POLICY_SYNC_INTERVAL_SECONDS", "300")

	store := &policyActivationStore{stateDir: stateDir}
	active := signedPolicyBundle{
		ManifestID:        "pmf_extension_internal_20260225_1111222233334444",
		Profile:           trustProfileInternal,
		Version:           "2026.02.25-120000z",
		SHA256:            sha256HexBytes([]byte("scan_only_extensions=[\".txt\"]\n")),
		EffectiveAt:       "2026-02-25T12:00:00Z",
		ExpiresAt:         "2026-02-26T12:00:00Z",
		KeyID:             "policy-key-v1",
		Signature:         "sig",
		ContentTOML:       "scan_only_extensions=[\".txt\"]\n",
		MinGatewayVersion: "v0.5f",
		DuplicateRule:     "manifest_id+profile+sha256",
		PolicySetID:       "set-a",
		FreshnessSLOSec:   86400,
	}
	if err := writeSignedPolicyBundleAtomic(store.activePath("extension"), active); err != nil {
		t.Fatalf("write active: %v", err)
	}
	if err := writeSignedPolicyBundleAtomic(store.stagedPath("extension"), active); err != nil {
		t.Fatalf("write staged: %v", err)
	}
	if err := writeSignedPolicyBundleAtomic(store.lastKnownGoodPath("extension"), active); err != nil {
		t.Fatalf("write lkg: %v", err)
	}
	if err := store.writeMeta("extension", policySyncMeta{
		ETagKeyset:  "\"sha256:keyset\"",
		ETagLatest:  "\"sha256:latest\"",
		LastFetchAt: time.Now().UTC().Add(-30 * time.Second).Format(time.RFC3339),
		LastSuccess: time.Now().UTC().Add(-30 * time.Second).Format(time.RFC3339),
		LastError:   policySyncErrorCodeNone,
	}); err != nil {
		t.Fatalf("write meta: %v", err)
	}

	out := captureStdout(t, func() {
		if err := runPolicyStatusCommand(repoRoot, []string{"--json"}); err != nil {
			t.Fatalf("runPolicyStatusCommand: %v", err)
		}
	})

	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("json.Unmarshal: %v\n%s", err, out)
	}
	assertPolicyStatusNestedFieldContract(t, got, "active", "manifest_id")
	assertPolicyStatusNestedFieldContract(t, got, "active", "expires_at")
	assertPolicyStatusNestedFieldContract(t, got, "staged", "manifest_id")
	assertPolicyStatusNestedFieldContract(t, got, "last_known_good", "manifest_id")
	if _, ok := got["last_sync_at"].(string); !ok {
		t.Fatalf("last_sync_at missing or not string: %#v", got["last_sync_at"])
	}
	if _, ok := got["next_sync_at"].(string); !ok {
		t.Fatalf("next_sync_at missing or not string: %#v", got["next_sync_at"])
	}
	if gotSyncErr, _ := got["sync_error_code"].(string); gotSyncErr == "" {
		t.Fatalf("sync_error_code is empty")
	}
	if gotSet, _ := got["set_consistency"].(string); gotSet == "" {
		t.Fatalf("set_consistency is empty")
	}
	if _, ok := got["last_sync_age_seconds"].(float64); !ok {
		t.Fatalf("last_sync_age_seconds missing or invalid: %#v", got["last_sync_age_seconds"])
	}
	if _, ok := got["freshness_slo_seconds"].(float64); !ok {
		t.Fatalf("freshness_slo_seconds missing or invalid: %#v", got["freshness_slo_seconds"])
	}
	if gotFreshness, _ := got["freshness_state"].(string); gotFreshness == "" {
		t.Fatalf("freshness_state is empty")
	}
}

func TestPolicyLoopHealthContract_DiagnosisBranches(t *testing.T) {
	repoRoot := t.TempDir()
	stateDir := filepath.Join(repoRoot, ".zt-policy-state")
	t.Setenv("ZT_POLICY_STATE_DIR", stateDir)
	store := &policyActivationStore{stateDir: stateDir}

	cases := []struct {
		errCode    string
		wantStatus string
		wantReason string
	}{
		{errCode: "policy_stale", wantStatus: "warn", wantReason: "stale"},
		{errCode: "policy_activation_verify_failed", wantStatus: "fail", wantReason: "verify_failed"},
		{errCode: policyErrorCodeGatewayVersionUnsupported, wantStatus: "fail", wantReason: "version_unsupported"},
	}
	for _, c := range cases {
		if err := store.writeMeta("extension", policySyncMeta{
			LastFetchAt: time.Now().UTC().Format(time.RFC3339),
			LastSuccess: "",
			LastError:   c.errCode,
		}); err != nil {
			t.Fatalf("write meta(%s): %v", c.errCode, err)
		}
		health, err := inspectPolicyLoopHealth(repoRoot, "extension")
		if err != nil {
			t.Fatalf("inspectPolicyLoopHealth(%s): %v", c.errCode, err)
		}
		if health.Status != c.wantStatus {
			t.Fatalf("status(%s)=%q, want %q", c.errCode, health.Status, c.wantStatus)
		}
		if health.Reason != c.wantReason {
			t.Fatalf("reason(%s)=%q, want %q", c.errCode, health.Reason, c.wantReason)
		}
	}
}

func TestPolicyStatus_SetConsistencyContract(t *testing.T) {
	repoRoot := t.TempDir()
	stateDir := filepath.Join(repoRoot, ".zt-policy-state")
	t.Setenv("ZT_POLICY_STATE_DIR", stateDir)
	store := &policyActivationStore{stateDir: stateDir}

	writeActive := func(kind, setID string) {
		t.Helper()
		bundle := signedPolicyBundle{
			ManifestID:        "pmf_" + kind + "_internal_20260225_aaaaaaaaaaaaaaaa",
			Profile:           trustProfileInternal,
			Version:           "2026.02.25-120000z",
			SHA256:            sha256HexBytes([]byte(kind + "_policy=true\n")),
			EffectiveAt:       time.Now().UTC().Add(-1 * time.Hour).Format(time.RFC3339),
			ExpiresAt:         time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
			KeyID:             "policy-key-v1",
			Signature:         "sig",
			ContentTOML:       kind + "_policy=true\n",
			MinGatewayVersion: "v0.5f",
			DuplicateRule:     "manifest_id+profile+sha256",
			PolicySetID:       setID,
		}
		if err := writeSignedPolicyBundleAtomic(store.activePath(kind), bundle); err != nil {
			t.Fatalf("write active(%s): %v", kind, err)
		}
		if err := store.writeMeta(kind, policySyncMeta{
			LastFetchAt: time.Now().UTC().Format(time.RFC3339),
			LastSuccess: time.Now().UTC().Format(time.RFC3339),
			LastError:   policySyncErrorCodeNone,
		}); err != nil {
			t.Fatalf("write meta(%s): %v", kind, err)
		}
	}

	writeActive("extension", "set-consistent")
	writeActive("scan", "set-consistent")
	gotConsistent := readPolicyStatusJSONContract(t, repoRoot, "--json", "--kind", "extension")
	if got, _ := gotConsistent["set_consistency"].(string); got != policySetConsistencyConsistent {
		t.Fatalf("set_consistency(consistent) = %q, want %q", got, policySetConsistencyConsistent)
	}

	writeActive("scan", "set-skewed")
	gotSkew := readPolicyStatusJSONContract(t, repoRoot, "--json", "--kind", "extension")
	if got, _ := gotSkew["set_consistency"].(string); got != policySetConsistencySkewDetected {
		t.Fatalf("set_consistency(skew) = %q, want %q", got, policySetConsistencySkewDetected)
	}
	if got, _ := gotSkew["sync_error_code"].(string); got != "policy_set_skew_detected" {
		t.Fatalf("sync_error_code(skew) = %q, want policy_set_skew_detected", got)
	}
	qfb, ok := gotSkew["quick_fix_bundle"].(map[string]any)
	if !ok {
		t.Fatalf("quick_fix_bundle(skew) missing: %#v", gotSkew["quick_fix_bundle"])
	}
	if got, _ := qfb["runbook_anchor"].(string); got != "#policy-set-consistency-reason" {
		t.Fatalf("runbook_anchor(skew) = %q, want #policy-set-consistency-reason", got)
	}
}

func TestPolicyStatus_FreshnessSLOContract(t *testing.T) {
	repoRoot := t.TempDir()
	stateDir := filepath.Join(repoRoot, ".zt-policy-state")
	t.Setenv("ZT_POLICY_STATE_DIR", stateDir)
	store := &policyActivationStore{stateDir: stateDir}

	active := signedPolicyBundle{
		ManifestID:        "pmf_extension_internal_20260225_freshness",
		Profile:           trustProfileInternal,
		Version:           "2026.02.25-120000z",
		SHA256:            sha256HexBytes([]byte("scan_only_extensions=[\".txt\"]\n")),
		EffectiveAt:       time.Now().UTC().Add(-1 * time.Hour).Format(time.RFC3339),
		ExpiresAt:         time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
		KeyID:             "policy-key-v1",
		Signature:         "sig",
		ContentTOML:       "scan_only_extensions=[\".txt\"]\n",
		MinGatewayVersion: "v0.5f",
		DuplicateRule:     "manifest_id+profile+sha256",
	}
	if err := writeSignedPolicyBundleAtomic(store.activePath("extension"), active); err != nil {
		t.Fatalf("write active: %v", err)
	}

	cases := []struct {
		name          string
		lastSync      time.Time
		wantFreshness string
		wantErrCode   string
	}{
		{
			name:          "fresh",
			lastSync:      time.Now().UTC().Add(-30 * time.Second),
			wantFreshness: policyFreshnessFresh,
			wantErrCode:   policySyncErrorCodeNone,
		},
		{
			name:          "stale",
			lastSync:      time.Now().UTC().Add(-25 * time.Hour),
			wantFreshness: policyFreshnessStale,
			wantErrCode:   policySyncErrorCodeNone,
		},
		{
			name:          "critical",
			lastSync:      time.Now().UTC().Add(-49 * time.Hour),
			wantFreshness: policyFreshnessCritical,
			wantErrCode:   "policy_sync_slo_breached",
		},
	}

	for _, tc := range cases {
		if err := store.writeMeta("extension", policySyncMeta{
			LastFetchAt: tc.lastSync.Format(time.RFC3339),
			LastSuccess: tc.lastSync.Format(time.RFC3339),
			LastError:   policySyncErrorCodeNone,
		}); err != nil {
			t.Fatalf("write meta(%s): %v", tc.name, err)
		}
		got := readPolicyStatusJSONContract(t, repoRoot, "--json")
		if gotFreshness, _ := got["freshness_state"].(string); gotFreshness != tc.wantFreshness {
			t.Fatalf("freshness_state(%s) = %q, want %q", tc.name, gotFreshness, tc.wantFreshness)
		}
		if gotErr, _ := got["sync_error_code"].(string); gotErr != tc.wantErrCode {
			t.Fatalf("sync_error_code(%s) = %q, want %q", tc.name, gotErr, tc.wantErrCode)
		}
	}
}

func TestPolicyStatus_AllKindsContract(t *testing.T) {
	repoRoot := t.TempDir()
	stateDir := filepath.Join(repoRoot, ".zt-policy-state")
	t.Setenv("ZT_POLICY_STATE_DIR", stateDir)
	store := &policyActivationStore{stateDir: stateDir}
	now := time.Now().UTC()

	writeActive := func(kind, setID string, profile string, freshnessSLO int64) {
		t.Helper()
		bundle := signedPolicyBundle{
			ManifestID:        "pmf_" + kind + "_contract_20260225_abcd1234abcd1234",
			Profile:           profile,
			Version:           "2026.02.25-120000z",
			SHA256:            sha256HexBytes([]byte(kind + "_policy=true\n")),
			EffectiveAt:       now.Add(-1 * time.Hour).Format(time.RFC3339),
			ExpiresAt:         now.Add(24 * time.Hour).Format(time.RFC3339),
			KeyID:             "policy-key-v1",
			Signature:         "sig",
			ContentTOML:       kind + "_policy=true\n",
			MinGatewayVersion: "v0.5f",
			DuplicateRule:     "manifest_id+profile+sha256",
			PolicySetID:       setID,
			FreshnessSLOSec:   freshnessSLO,
		}
		if err := writeSignedPolicyBundleAtomic(store.activePath(kind), bundle); err != nil {
			t.Fatalf("write active(%s): %v", kind, err)
		}
	}

	writeActive("extension", "set-all", trustProfileInternal, 86400)
	writeActive("scan", "set-all", trustProfileInternal, 86400)
	if err := store.writeMeta("extension", policySyncMeta{
		LastFetchAt: now.Add(-30 * time.Second).Format(time.RFC3339),
		LastSuccess: now.Add(-30 * time.Second).Format(time.RFC3339),
		LastError:   policySyncErrorCodeNone,
	}); err != nil {
		t.Fatalf("write meta(extension): %v", err)
	}
	if err := store.writeMeta("scan", policySyncMeta{
		LastFetchAt: now.Add(-49 * time.Hour).Format(time.RFC3339),
		LastSuccess: now.Add(-49 * time.Hour).Format(time.RFC3339),
		LastError:   policySyncErrorCodeNone,
	}); err != nil {
		t.Fatalf("write meta(scan): %v", err)
	}

	got := readPolicyStatusJSONContract(t, repoRoot, "--json", "--kind", "all")
	if kind, _ := got["kind"].(string); kind != "all" {
		t.Fatalf("kind = %q, want all", kind)
	}
	if overall, _ := got["overall_set_consistency"].(string); overall != policySetConsistencyConsistent {
		t.Fatalf("overall_set_consistency = %q, want %q", overall, policySetConsistencyConsistent)
	}
	if reason, _ := got["set_consistency_reason"].(string); reason != policySetConsistencyReasonNone {
		t.Fatalf("set_consistency_reason = %q, want %q", reason, policySetConsistencyReasonNone)
	}
	if freshness, _ := got["overall_freshness_state"].(string); freshness != policyFreshnessCritical {
		t.Fatalf("overall_freshness_state = %q, want %q", freshness, policyFreshnessCritical)
	}
	if syncErr, _ := got["sync_error_code"].(string); syncErr != "policy_sync_slo_breached" {
		t.Fatalf("sync_error_code = %q, want policy_sync_slo_breached", syncErr)
	}
	qfb, ok := got["quick_fix_bundle"].(map[string]any)
	if !ok {
		t.Fatalf("quick_fix_bundle missing: %#v", got["quick_fix_bundle"])
	}
	if gotAnchor, _ := qfb["runbook_anchor"].(string); gotAnchor != "#policy-sync-slo-breached" {
		t.Fatalf("runbook_anchor = %q, want #policy-sync-slo-breached", gotAnchor)
	}
	extension, ok := got["extension"].(map[string]any)
	if !ok {
		t.Fatalf("extension missing or invalid: %#v", got["extension"])
	}
	if extensionKind, _ := extension["kind"].(string); extensionKind != "extension" {
		t.Fatalf("extension.kind = %q, want extension", extensionKind)
	}
	scan, ok := got["scan"].(map[string]any)
	if !ok {
		t.Fatalf("scan missing or invalid: %#v", got["scan"])
	}
	if scanKind, _ := scan["kind"].(string); scanKind != "scan" {
		t.Fatalf("scan.kind = %q, want scan", scanKind)
	}
	criticalKinds, ok := got["critical_kinds"].([]any)
	if !ok {
		t.Fatalf("critical_kinds missing or invalid: %#v", got["critical_kinds"])
	}
	if len(criticalKinds) != 1 || criticalKinds[0] != "scan" {
		t.Fatalf("critical_kinds = %#v, want [scan]", criticalKinds)
	}
}

func TestPolicyStatusContract_JSONFailureIncludesRunbookBundle(t *testing.T) {
	repoRoot := t.TempDir()
	stateDir := filepath.Join(repoRoot, ".zt-policy-state")
	t.Setenv("ZT_POLICY_STATE_DIR", stateDir)
	store := &policyActivationStore{stateDir: stateDir}
	if err := os.MkdirAll(filepath.Dir(store.activePath("extension")), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(store.activePath("extension"), []byte("{broken json"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	out := captureStdout(t, func() {
		if err := runPolicyStatusCommand(repoRoot, []string{"--json"}); err == nil {
			t.Fatalf("runPolicyStatusCommand returned nil error")
		}
	})
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	qfb, ok := got["quick_fix_bundle"].(map[string]any)
	if !ok {
		t.Fatalf("quick_fix_bundle missing: %#v", got["quick_fix_bundle"])
	}
	if runbook, _ := qfb["runbook"].(string); runbook == "" {
		t.Fatalf("quick_fix_bundle.runbook is empty")
	}
}

func readPolicyStatusJSONContract(t *testing.T, repoRoot string, args ...string) map[string]any {
	t.Helper()
	out := captureStdout(t, func() {
		if err := runPolicyStatusCommand(repoRoot, args); err != nil {
			t.Fatalf("runPolicyStatusCommand: %v", err)
		}
	})
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("json.Unmarshal: %v\n%s", err, out)
	}
	return got
}

func assertPolicyStatusNestedFieldContract(t *testing.T, payload map[string]any, parent, child string) {
	t.Helper()
	obj, ok := payload[parent].(map[string]any)
	if !ok {
		t.Fatalf("%s missing or not object: %#v", parent, payload[parent])
	}
	v, ok := obj[child].(string)
	if !ok || v == "" {
		t.Fatalf("%s.%s missing or empty: %#v", parent, child, obj[child])
	}
}
