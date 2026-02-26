package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestPolicyRotateFetchDecisionSyncAuditReceipt_E2EContract(t *testing.T) {
	priv, pub := policyBundleKeyPairContract(140)
	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)

	bundleAllow := signPolicyBundleContract(t, signedPolicyBundle{
		ManifestID:        "pmf_extension_internal_20260225_aaaa1111aaaa1111",
		Profile:           trustProfileInternal,
		Version:           "2026.02.25-120000z",
		SHA256:            sha256HexBytes([]byte("scan_only_extensions=[\".txt\"]\n")),
		EffectiveAt:       now.Add(-1 * time.Hour).Format(time.RFC3339),
		ExpiresAt:         now.Add(24 * time.Hour).Format(time.RFC3339),
		KeyID:             "policy-key-v1",
		ContentTOML:       "scan_only_extensions=[\".txt\"]\n",
		MinGatewayVersion: "v0.5f",
		DuplicateRule:     "manifest_id+profile+sha256",
	}, priv)
	bundleDeny := signPolicyBundleContract(t, signedPolicyBundle{
		ManifestID:        "pmf_extension_internal_20260225_bbbb2222bbbb2222",
		Profile:           trustProfileInternal,
		Version:           "2026.02.25-121000z",
		SHA256:            sha256HexBytes([]byte("deny_extensions=[\".txt\"]\n")),
		EffectiveAt:       now.Add(-1 * time.Hour).Format(time.RFC3339),
		ExpiresAt:         now.Add(24 * time.Hour).Format(time.RFC3339),
		KeyID:             "policy-key-v1",
		ContentTOML:       "deny_extensions=[\".txt\"]\n",
		MinGatewayVersion: "v0.5f",
		DuplicateRule:     "manifest_id+profile+sha256",
	}, priv)

	var postedDecision atomic.Value
	postedDecision.Store(policyDecision{})
	serveDeny := atomic.Bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/policies/keyset":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"schema_version": "zt-policy-keyset-v1",
				"generated_at":   now.Format(time.RFC3339),
				"keys": []any{map[string]any{
					"key_id":         "policy-key-v1",
					"alg":            "Ed25519",
					"public_key_b64": base64.StdEncoding.EncodeToString(pub),
					"status":         "active",
				}},
			})
			return
		case "/v1/policies/extension/latest":
			bundle := bundleAllow
			if serveDeny.Load() {
				bundle = bundleDeny
			}
			etag := fmt.Sprintf("\"sha256:%s\"", bundle.SHA256)
			w.Header().Set("ETag", etag)
			if r.Header.Get("If-None-Match") == etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			_ = json.NewEncoder(w).Encode(bundle)
			return
		case "/v1/events/verify":
			rawBody, _ := io.ReadAll(r.Body)
			var payload map[string]any
			if err := json.Unmarshal(rawBody, &payload); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if pd, ok := payload["policy_decision"].(map[string]any); ok {
				postedDecision.Store(normalizePolicyDecision(policyDecision{
					Decision:   anyString(pd["decision"]),
					ReasonCode: anyString(pd["reason_code"]),
					ManifestID: anyString(pd["manifest_id"]),
					Profile:    anyString(pd["profile"]),
					RuleHash:   anyString(pd["rule_hash"]),
					ErrorClass: anyString(pd["error_class"]),
					ErrorCode:  anyString(pd["error_code"]),
				}))
			}
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":         "accepted",
				"endpoint":       r.URL.Path,
				"payload_sha256": canonicalEventPayloadSHA(rawBody),
				"accepted_at":    time.Now().UTC().Format(time.RFC3339),
			})
			return
		default:
			http.NotFound(w, r)
			return
		}
	}))
	defer srv.Close()

	keys, err := fetchControlPlanePolicyTrustedKeys(srv.URL, "")
	if err != nil {
		t.Fatalf("fetchControlPlanePolicyTrustedKeys: %v", err)
	}
	store := &policyActivationStore{stateDir: t.TempDir()}

	first, err := fetchControlPlanePolicyLatest(srv.URL, "", "extension", trustProfileInternal, "")
	if err != nil {
		t.Fatalf("fetchControlPlanePolicyLatest(first): %v", err)
	}
	if err := store.stage("extension", first.Bundle); err != nil {
		t.Fatalf("stage(first): %v", err)
	}
	if _, err := store.activateStaged("extension", keys, now); err != nil {
		t.Fatalf("activateStaged(first): %v", err)
	}
	active1, err := store.readActive("extension")
	if err != nil {
		t.Fatalf("readActive(first): %v", err)
	}
	pol1 := loadExtensionPolicyFromContentContract(t, active1.ContentTOML)
	mode1, _ := resolveExtensionMode("/tmp/sample.txt", pol1)
	if mode1 != ExtModeScanOnly {
		t.Fatalf("mode1 = %q, want %q", mode1, ExtModeScanOnly)
	}

	serveDeny.Store(true)
	second, err := fetchControlPlanePolicyLatest(srv.URL, "", "extension", trustProfileInternal, first.ETag)
	if err != nil {
		t.Fatalf("fetchControlPlanePolicyLatest(second): %v", err)
	}
	if second.NotModified {
		t.Fatalf("second.NotModified = true, want false")
	}
	if err := store.stage("extension", second.Bundle); err != nil {
		t.Fatalf("stage(second): %v", err)
	}
	if _, err := store.activateStaged("extension", keys, now); err != nil {
		t.Fatalf("activateStaged(second): %v", err)
	}
	active2, err := store.readActive("extension")
	if err != nil {
		t.Fatalf("readActive(second): %v", err)
	}
	pol2 := loadExtensionPolicyFromContentContract(t, active2.ContentTOML)
	mode2, _ := resolveExtensionMode("/tmp/sample.txt", pol2)
	if mode2 != ExtModeDeny {
		t.Fatalf("mode2 = %q, want %q", mode2, ExtModeDeny)
	}
	if active1.ManifestID == active2.ManifestID {
		t.Fatalf("manifest_id should rotate")
	}

	decision := normalizePolicyDecision(policyDecision{
		Decision:   policyDecisionDeny,
		ReasonCode: "policy_extension_denied",
		ManifestID: active2.ManifestID,
		Profile:    active2.Profile,
		RuleHash:   "none",
	})

	repoRoot := t.TempDir()
	packet := filepath.Join(repoRoot, "bundle_clientA_20260225T000000Z.spkg.tgz")
	if err := os.WriteFile(packet, []byte("packet"), 0o644); err != nil {
		t.Fatalf("os.WriteFile(packet): %v", err)
	}
	receipt, err := buildVerificationReceipt(packet, decision, "0123456789ABCDEF0123456789ABCDEF01234567")
	if err != nil {
		t.Fatalf("buildVerificationReceipt: %v", err)
	}
	if receipt.Verification.PolicyDecision.Decision != decision.Decision {
		t.Fatalf("receipt decision mismatch")
	}

	prevEvents := cpEvents
	cpEvents = newEventSpool(repoRoot)
	cpEvents.SetAutoSync(false)
	cpEvents.SetControlPlaneURL(srv.URL)
	defer func() { cpEvents = prevEvents }()

	emitVerifyEvent(packet, false, "policy.blocked", "blocked by rotated policy", decision)
	if _, err := cpEvents.Sync(true); err != nil {
		t.Fatalf("cpEvents.Sync: %v", err)
	}

	auditRecords := readAuditEventRecordsWithDecisionContract(t, cpEvents.auditPath())
	if len(auditRecords) == 0 {
		t.Fatalf("audit records are empty")
	}
	auditDecision := auditRecords[len(auditRecords)-1].PolicyDecision
	if auditDecision.Decision != decision.Decision || auditDecision.ReasonCode != decision.ReasonCode {
		t.Fatalf("audit decision mismatch: got=%+v want=%+v", auditDecision, decision)
	}

	posted := postedDecision.Load().(policyDecision)
	if posted.Decision != decision.Decision || posted.ReasonCode != decision.ReasonCode {
		t.Fatalf("synced decision mismatch: got=%+v want=%+v", posted, decision)
	}
}

func loadExtensionPolicyFromContentContract(t *testing.T, content string) extensionPolicy {
	t.Helper()
	tmp := t.TempDir()
	path := filepath.Join(tmp, "extension_policy.toml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}
	pol, err := loadExtensionPolicy(path)
	if err != nil {
		t.Fatalf("loadExtensionPolicy: %v", err)
	}
	return pol
}

func anyString(v any) string {
	s, _ := v.(string)
	return s
}
