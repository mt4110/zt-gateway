package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPolicyRolloutContract_SameGatewayDeterministicResult(t *testing.T) {
	t.Setenv("ZT_CP_POLICY_ROLLOUT_ID", "rollout-a")
	t.Setenv("ZT_CP_POLICY_ROLLOUT_CANARY_PERCENT", "35")

	signer := newPolicyBundleSignerContract(201, 24*time.Hour)
	policyDir := t.TempDir()
	policyPath := filepath.Join(policyDir, "extension_policy.toml")
	if err := os.WriteFile(policyPath, []byte("scan_only_extensions=[\".txt\"]\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	srv := &server{policyDir: policyDir, policySigner: signer}

	first := fetchPolicyLatestRolloutContract(t, srv, "extension_policy.toml", "/v1/policies/extension/latest?profile=internal&gateway_id=gw-001&channel=canary")
	second := fetchPolicyLatestRolloutContract(t, srv, "extension_policy.toml", "/v1/policies/extension/latest?profile=internal&gateway_id=gw-001&channel=canary")
	if first.RolloutChannel != second.RolloutChannel {
		t.Fatalf("rollout_channel not deterministic: first=%q second=%q", first.RolloutChannel, second.RolloutChannel)
	}
	if first.RolloutID != "rollout-a" {
		t.Fatalf("rollout_id = %q, want rollout-a", first.RolloutID)
	}
	if first.RolloutRule == "" {
		t.Fatalf("rollout_rule is empty")
	}
}

func TestPolicyRolloutContract_ChangingPercentCanChangeDecision(t *testing.T) {
	t.Setenv("ZT_CP_POLICY_ROLLOUT_ID", "rollout-b")

	signer := newPolicyBundleSignerContract(211, 24*time.Hour)
	policyDir := t.TempDir()
	policyPath := filepath.Join(policyDir, "extension_policy.toml")
	if err := os.WriteFile(policyPath, []byte("scan_only_extensions=[\".txt\"]\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	srv := &server{policyDir: policyDir, policySigner: signer}

	t.Setenv("ZT_CP_POLICY_ROLLOUT_CANARY_PERCENT", "0")
	zero := fetchPolicyLatestRolloutContract(t, srv, "extension_policy.toml", "/v1/policies/extension/latest?profile=internal&gateway_id=gw-002&channel=canary")
	if zero.RolloutChannel != "stable" {
		t.Fatalf("channel with 0%% = %q, want stable", zero.RolloutChannel)
	}

	t.Setenv("ZT_CP_POLICY_ROLLOUT_CANARY_PERCENT", "100")
	full := fetchPolicyLatestRolloutContract(t, srv, "extension_policy.toml", "/v1/policies/extension/latest?profile=internal&gateway_id=gw-002&channel=canary")
	if full.RolloutChannel != "canary" {
		t.Fatalf("channel with 100%% = %q, want canary", full.RolloutChannel)
	}
}

func TestPolicyRolloutContract_BoundaryReproducible(t *testing.T) {
	t.Setenv("ZT_CP_POLICY_ROLLOUT_ID", "rollout-c")
	t.Setenv("ZT_CP_POLICY_ROLLOUT_CANARY_PERCENT", "50")

	signer := newPolicyBundleSignerContract(221, 24*time.Hour)
	policyDir := t.TempDir()
	policyPath := filepath.Join(policyDir, "scan_policy.toml")
	if err := os.WriteFile(policyPath, []byte("required_scanners=[]\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	srv := &server{policyDir: policyDir, policySigner: signer}

	var stableID, canaryID string
	for i := 0; i < 5000; i++ {
		gw := fmt.Sprintf("gw-boundary-%d", i)
		if rolloutCanaryEligible(gw, "rollout-c", 50) {
			if canaryID == "" {
				canaryID = gw
			}
		} else if stableID == "" {
			stableID = gw
		}
		if stableID != "" && canaryID != "" {
			break
		}
	}
	if stableID == "" || canaryID == "" {
		t.Fatalf("failed to find both stable and canary IDs")
	}

	stableResp := fetchPolicyLatestRolloutContract(t, srv, "scan_policy.toml", "/v1/policies/scan/latest?profile=internal&gateway_id="+stableID+"&channel=canary")
	canaryResp := fetchPolicyLatestRolloutContract(t, srv, "scan_policy.toml", "/v1/policies/scan/latest?profile=internal&gateway_id="+canaryID+"&channel=canary")
	if stableResp.RolloutChannel != "stable" {
		t.Fatalf("stable boundary channel = %q, want stable", stableResp.RolloutChannel)
	}
	if canaryResp.RolloutChannel != "canary" {
		t.Fatalf("canary boundary channel = %q, want canary", canaryResp.RolloutChannel)
	}
}

func fetchPolicyLatestRolloutContract(t *testing.T, srv *server, fileName, rawURL string) policyBundle {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, rawURL, nil)
	srv.handlePolicyLatest(fileName).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var bundle policyBundle
	if err := json.Unmarshal(rr.Body.Bytes(), &bundle); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	return bundle
}
