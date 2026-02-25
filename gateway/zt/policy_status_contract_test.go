package main

import (
	"encoding/json"
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
		LastFetchAt: "2026-02-25T13:00:00Z",
		LastSuccess: "2026-02-25T13:00:00Z",
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
