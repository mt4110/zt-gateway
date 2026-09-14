package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func TestPolicySyncLoopContract_NotModifiedDoesNotReapply(t *testing.T) {
	priv, pub := policyBundleKeyPairContract(201)
	now := time.Date(2026, 2, 25, 10, 0, 0, 0, time.UTC)
	bundle := signPolicyBundleContract(t, signedPolicyBundle{
		ManifestID:        "pmf_extension_internal_20260225_abab1111abab1111",
		Profile:           trustProfileInternal,
		Version:           "2026.02.25-100000z",
		SHA256:            sha256HexBytes([]byte("scan_only_extensions=[\".txt\"]\n")),
		EffectiveAt:       now.Add(-1 * time.Hour).Format(time.RFC3339),
		ExpiresAt:         now.Add(24 * time.Hour).Format(time.RFC3339),
		KeyID:             "policy-key-v1",
		ContentTOML:       "scan_only_extensions=[\".txt\"]\n",
		MinGatewayVersion: "v0.5f",
		DuplicateRule:     "manifest_id+profile+sha256",
	}, priv)

	keysetETag := "\"sha256:keyset-static\""
	latestETag := "\"sha256:bundle-static\""
	var latestIfNoneMatchSeen atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/policies/keyset":
			w.Header().Set("ETag", keysetETag)
			if r.Header.Get("If-None-Match") == keysetETag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
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
		case "/v1/policies/extension/latest":
			w.Header().Set("ETag", latestETag)
			if r.Header.Get("If-None-Match") == latestETag {
				latestIfNoneMatchSeen.Store(true)
				w.WriteHeader(http.StatusNotModified)
				return
			}
			_ = json.NewEncoder(w).Encode(bundle)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	store := &policyActivationStore{stateDir: t.TempDir()}
	cfg := policySyncConfig{
		BaseURL:  srv.URL,
		Profile:  trustProfileInternal,
		Kind:     "extension",
		Store:    store,
		VerifyAt: now,
	}
	if _, err := runPolicySyncOnce(cfg); err != nil {
		t.Fatalf("runPolicySyncOnce(first): %v", err)
	}
	info1, err := os.Stat(store.activePath("extension"))
	if err != nil {
		t.Fatalf("Stat(active first): %v", err)
	}

	time.Sleep(10 * time.Millisecond)
	second, err := runPolicySyncOnce(cfg)
	if err != nil {
		t.Fatalf("runPolicySyncOnce(second): %v", err)
	}
	if !second.NotModified {
		t.Fatalf("second.NotModified = false, want true")
	}
	info2, err := os.Stat(store.activePath("extension"))
	if err != nil {
		t.Fatalf("Stat(active second): %v", err)
	}
	if !info1.ModTime().Equal(info2.ModTime()) {
		t.Fatalf("active policy was rewritten on 304 response")
	}
	if !latestIfNoneMatchSeen.Load() {
		t.Fatalf("latest endpoint did not receive If-None-Match on second sync")
	}
}

func TestPolicySyncLoopContract_SameManifestReFetchKeepsActiveUnchanged(t *testing.T) {
	priv, pub := policyBundleKeyPairContract(211)
	now := time.Date(2026, 2, 25, 11, 0, 0, 0, time.UTC)
	bundle := signPolicyBundleContract(t, signedPolicyBundle{
		ManifestID:        "pmf_extension_internal_20260225_cdcd2222cdcd2222",
		Profile:           trustProfileInternal,
		Version:           "2026.02.25-110000z",
		SHA256:            sha256HexBytes([]byte("scan_only_extensions=[\".txt\"]\n")),
		EffectiveAt:       now.Add(-1 * time.Hour).Format(time.RFC3339),
		ExpiresAt:         now.Add(24 * time.Hour).Format(time.RFC3339),
		KeyID:             "policy-key-v1",
		ContentTOML:       "scan_only_extensions=[\".txt\"]\n",
		MinGatewayVersion: "v0.5f",
		DuplicateRule:     "manifest_id+profile+sha256",
	}, priv)

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
		case "/v1/policies/extension/latest":
			w.Header().Set("ETag", fmt.Sprintf("\"sha256:%s\"", bundle.SHA256))
			_ = json.NewEncoder(w).Encode(bundle)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	store := &policyActivationStore{stateDir: t.TempDir()}
	cfg := policySyncConfig{
		BaseURL:  srv.URL,
		Profile:  trustProfileInternal,
		Kind:     "extension",
		Store:    store,
		VerifyAt: now,
	}
	if _, err := runPolicySyncOnce(cfg); err != nil {
		t.Fatalf("runPolicySyncOnce(first): %v", err)
	}
	info1, err := os.Stat(store.activePath("extension"))
	if err != nil {
		t.Fatalf("Stat(active first): %v", err)
	}

	time.Sleep(10 * time.Millisecond)
	second, err := runPolicySyncOnce(cfg)
	if err != nil {
		t.Fatalf("runPolicySyncOnce(second): %v", err)
	}
	if !second.NotModified {
		t.Fatalf("second.NotModified = false, want true for same manifest")
	}
	info2, err := os.Stat(store.activePath("extension"))
	if err != nil {
		t.Fatalf("Stat(active second): %v", err)
	}
	if !info1.ModTime().Equal(info2.ModTime()) {
		t.Fatalf("active policy was rewritten on same manifest response")
	}
}

func TestPolicySyncLoopContract_SameManifestMetadataChangedReapplies(t *testing.T) {
	priv, pub := policyBundleKeyPairContract(215)
	now := time.Date(2026, 2, 25, 11, 30, 0, 0, time.UTC)
	bundle := signPolicyBundleContract(t, signedPolicyBundle{
		ManifestID:        "pmf_extension_internal_20260225_meta1234meta1234",
		Profile:           trustProfileInternal,
		Version:           "2026.02.25-113000z",
		SHA256:            sha256HexBytes([]byte("scan_only_extensions=[\".txt\"]\n")),
		EffectiveAt:       now.Add(-1 * time.Hour).Format(time.RFC3339),
		ExpiresAt:         now.Add(24 * time.Hour).Format(time.RFC3339),
		KeyID:             "policy-key-v1",
		ContentTOML:       "scan_only_extensions=[\".txt\"]\n",
		MinGatewayVersion: "v0.5f",
		DuplicateRule:     "manifest_id+profile+sha256",
		PolicySetID:       "set-a",
		FreshnessSLOSec:   86400,
	}, priv)

	useSetB := atomic.Bool{}
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
		case "/v1/policies/extension/latest":
			out := bundle
			if useSetB.Load() {
				out.PolicySetID = "set-b"
				out.FreshnessSLOSec = 21600
				out = signPolicyBundleContract(t, out, priv)
				w.Header().Set("ETag", "\"sha256:meta-set-b\"")
			} else {
				w.Header().Set("ETag", "\"sha256:meta-set-a\"")
			}
			_ = json.NewEncoder(w).Encode(out)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	store := &policyActivationStore{stateDir: t.TempDir()}
	cfg := policySyncConfig{
		BaseURL:  srv.URL,
		Profile:  trustProfileInternal,
		Kind:     "extension",
		Store:    store,
		VerifyAt: now,
	}
	if _, err := runPolicySyncOnce(cfg); err != nil {
		t.Fatalf("runPolicySyncOnce(first): %v", err)
	}
	activeFirst, err := store.readActive("extension")
	if err != nil {
		t.Fatalf("readActive(first): %v", err)
	}
	if activeFirst.PolicySetID != "set-a" {
		t.Fatalf("policy_set_id(first) = %q, want set-a", activeFirst.PolicySetID)
	}

	useSetB.Store(true)
	second, err := runPolicySyncOnce(cfg)
	if err != nil {
		t.Fatalf("runPolicySyncOnce(second): %v", err)
	}
	if second.NotModified {
		t.Fatalf("second.NotModified = true, want false")
	}
	activeSecond, err := store.readActive("extension")
	if err != nil {
		t.Fatalf("readActive(second): %v", err)
	}
	if activeSecond.PolicySetID != "set-b" {
		t.Fatalf("policy_set_id(second) = %q, want set-b", activeSecond.PolicySetID)
	}
	if activeSecond.FreshnessSLOSec != 21600 {
		t.Fatalf("freshness_slo_seconds(second) = %d, want 21600", activeSecond.FreshnessSLOSec)
	}
}

func TestPolicySyncLoopContract_SyncFailureKeepsActivePolicy(t *testing.T) {
	priv, pub := policyBundleKeyPairContract(221)
	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	bundle := signPolicyBundleContract(t, signedPolicyBundle{
		ManifestID:        "pmf_extension_internal_20260225_efef3333efef3333",
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

	failLatest := atomic.Bool{}
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
		case "/v1/policies/extension/latest":
			if failLatest.Load() {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"error":"temporary_unavailable"}`))
				return
			}
			_ = json.NewEncoder(w).Encode(bundle)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	store := &policyActivationStore{stateDir: t.TempDir()}
	cfg := policySyncConfig{
		BaseURL:  srv.URL,
		Profile:  trustProfileInternal,
		Kind:     "extension",
		Store:    store,
		VerifyAt: now,
	}
	if _, err := runPolicySyncOnce(cfg); err != nil {
		t.Fatalf("runPolicySyncOnce(first): %v", err)
	}
	activeBefore, err := store.readActive("extension")
	if err != nil {
		t.Fatalf("readActive(first): %v", err)
	}

	failLatest.Store(true)
	if _, err := runPolicySyncOnce(cfg); err == nil {
		t.Fatalf("runPolicySyncOnce(second) returned nil error, want failure")
	}
	activeAfter, err := store.readActive("extension")
	if err != nil {
		t.Fatalf("readActive(second): %v", err)
	}
	if activeAfter.ManifestID != activeBefore.ManifestID {
		t.Fatalf("active manifest changed on sync failure: got=%q want=%q", activeAfter.ManifestID, activeBefore.ManifestID)
	}
	meta, err := store.readMeta("extension")
	if err != nil {
		t.Fatalf("readMeta: %v", err)
	}
	if meta.LastError != policySyncErrorCodeHTTP5xx {
		t.Fatalf("last_error_code = %q, want %q", meta.LastError, policySyncErrorCodeHTTP5xx)
	}
}

func TestPolicySyncLoopContract_BrokenBundleKeepsActiveAndLKG(t *testing.T) {
	priv, pub := policyBundleKeyPairContract(231)
	now := time.Date(2026, 2, 25, 13, 0, 0, 0, time.UTC)
	good := signPolicyBundleContract(t, signedPolicyBundle{
		ManifestID:        "pmf_extension_internal_20260225_good0000good0000",
		Profile:           trustProfileInternal,
		Version:           "2026.02.25-130000z",
		SHA256:            sha256HexBytes([]byte("scan_only_extensions=[\".txt\"]\n")),
		EffectiveAt:       now.Add(-1 * time.Hour).Format(time.RFC3339),
		ExpiresAt:         now.Add(24 * time.Hour).Format(time.RFC3339),
		KeyID:             "policy-key-v1",
		ContentTOML:       "scan_only_extensions=[\".txt\"]\n",
		MinGatewayVersion: "v0.5f",
		DuplicateRule:     "manifest_id+profile+sha256",
	}, priv)
	broken := good
	broken.ManifestID = "pmf_extension_internal_20260225_bad00000bad0000"
	broken.ContentTOML = "deny_extensions=[\".txt\"]\n"
	broken.SHA256 = sha256HexBytes([]byte(broken.ContentTOML))
	// intentionally keep old signature to simulate broken canary publish.

	serveBroken := atomic.Bool{}
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
		case "/v1/policies/extension/latest":
			if serveBroken.Load() {
				_ = json.NewEncoder(w).Encode(broken)
				return
			}
			_ = json.NewEncoder(w).Encode(good)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	store := &policyActivationStore{stateDir: t.TempDir()}
	cfg := policySyncConfig{
		BaseURL:  srv.URL,
		Profile:  trustProfileInternal,
		Kind:     "extension",
		Store:    store,
		VerifyAt: now,
	}
	if _, err := runPolicySyncOnce(cfg); err != nil {
		t.Fatalf("runPolicySyncOnce(good): %v", err)
	}
	activeBefore, err := store.readActive("extension")
	if err != nil {
		t.Fatalf("readActive(before): %v", err)
	}
	lkgBefore, err := store.readLastKnownGood("extension")
	if err != nil {
		t.Fatalf("readLastKnownGood(before): %v", err)
	}

	serveBroken.Store(true)
	if _, err := runPolicySyncOnce(cfg); err == nil {
		t.Fatalf("runPolicySyncOnce(broken) returned nil error")
	}
	activeAfter, err := store.readActive("extension")
	if err != nil {
		t.Fatalf("readActive(after): %v", err)
	}
	lkgAfter, err := store.readLastKnownGood("extension")
	if err != nil {
		t.Fatalf("readLastKnownGood(after): %v", err)
	}
	if activeAfter.ManifestID != activeBefore.ManifestID {
		t.Fatalf("active changed on broken bundle: got=%q want=%q", activeAfter.ManifestID, activeBefore.ManifestID)
	}
	if lkgAfter.ManifestID != lkgBefore.ManifestID {
		t.Fatalf("LKG changed on broken bundle: got=%q want=%q", lkgAfter.ManifestID, lkgBefore.ManifestID)
	}
}

func TestPolicySyncLoopContract_CanaryNotEligibleKeepsActive(t *testing.T) {
	t.Setenv("ZT_POLICY_ROLLOUT_CHANNEL", "canary")
	priv, pub := policyBundleKeyPairContract(241)
	now := time.Date(2026, 2, 25, 14, 0, 0, 0, time.UTC)
	good := signPolicyBundleContract(t, signedPolicyBundle{
		ManifestID:        "pmf_extension_internal_20260225_keep1111keep1111",
		Profile:           trustProfileInternal,
		Version:           "2026.02.25-140000z",
		SHA256:            sha256HexBytes([]byte("scan_only_extensions=[\".txt\"]\n")),
		EffectiveAt:       now.Add(-1 * time.Hour).Format(time.RFC3339),
		ExpiresAt:         now.Add(24 * time.Hour).Format(time.RFC3339),
		KeyID:             "policy-key-v1",
		ContentTOML:       "scan_only_extensions=[\".txt\"]\n",
		MinGatewayVersion: "v0.5f",
		DuplicateRule:     "manifest_id+profile+sha256",
	}, priv)
	canary := signPolicyBundleContract(t, signedPolicyBundle{
		ManifestID:        "pmf_extension_internal_20260225_canary2222canary2",
		Profile:           trustProfileInternal,
		Version:           "2026.02.25-141000z",
		SHA256:            sha256HexBytes([]byte("deny_extensions=[\".txt\"]\n")),
		EffectiveAt:       now.Add(-30 * time.Minute).Format(time.RFC3339),
		ExpiresAt:         now.Add(24 * time.Hour).Format(time.RFC3339),
		KeyID:             "policy-key-v1",
		ContentTOML:       "deny_extensions=[\".txt\"]\n",
		MinGatewayVersion: "v0.5f",
		DuplicateRule:     "manifest_id+profile+sha256",
		RolloutID:         "rollout-1",
		RolloutChannel:    "stable",
		RolloutRule:       "sha256(gateway_id+rollout_id)%100<5",
	}, priv)
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
		case "/v1/policies/extension/latest":
			_ = json.NewEncoder(w).Encode(canary)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	store := &policyActivationStore{stateDir: t.TempDir()}
	if err := writeSignedPolicyBundleAtomic(store.activePath("extension"), good); err != nil {
		t.Fatalf("seed active: %v", err)
	}
	if err := writeSignedPolicyBundleAtomic(store.lastKnownGoodPath("extension"), good); err != nil {
		t.Fatalf("seed lkg: %v", err)
	}
	cfg := policySyncConfig{
		BaseURL:  srv.URL,
		Profile:  trustProfileInternal,
		Kind:     "extension",
		Store:    store,
		VerifyAt: now,
	}
	got, err := runPolicySyncOnce(cfg)
	if err != nil {
		t.Fatalf("runPolicySyncOnce: %v", err)
	}
	if got.ErrorCode != "policy_rollout_not_eligible" {
		t.Fatalf("error_code = %q, want policy_rollout_not_eligible", got.ErrorCode)
	}
	activeAfter, err := store.readActive("extension")
	if err != nil {
		t.Fatalf("readActive: %v", err)
	}
	if activeAfter.ManifestID != good.ManifestID {
		t.Fatalf("active changed for not-eligible canary: got=%q want=%q", activeAfter.ManifestID, good.ManifestID)
	}
}
