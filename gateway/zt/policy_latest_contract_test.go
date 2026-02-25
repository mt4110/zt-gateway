package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPolicyLatestContract_IfNoneMatchAndETag(t *testing.T) {
	priv, _ := policyBundleKeyPairContract(101)
	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	bundle := signedPolicyBundle{
		ManifestID:        "pmf_extension_internal_20260225_ffffffffffffffff",
		Profile:           "internal",
		Version:           "2026.02.25-120000z",
		SHA256:            sha256HexBytes([]byte("scan_only_extensions=[\".txt\"]\n")),
		EffectiveAt:       now.Add(-1 * time.Hour).Format(time.RFC3339),
		ExpiresAt:         now.Add(24 * time.Hour).Format(time.RFC3339),
		KeyID:             "policy-key-v1",
		ContentTOML:       "scan_only_extensions=[\".txt\"]\n",
		MinGatewayVersion: "v0.5f",
		DuplicateRule:     "manifest_id+profile+sha256",
	}
	bundle = signPolicyBundleContract(t, bundle, priv)
	etag := "\"sha256:" + bundle.SHA256 + "\""

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/policies/extension/latest" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("ETag", etag)
		if strings.TrimSpace(r.Header.Get("If-None-Match")) == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"manifest_id":%q,"profile":%q,"version":%q,"sha256":%q,"effective_at":%q,"expires_at":%q,"key_id":%q,"signature":%q,"content_toml":%q,"min_gateway_version":%q,"duplicate_rule":%q}`,
			bundle.ManifestID, bundle.Profile, bundle.Version, bundle.SHA256, bundle.EffectiveAt, bundle.ExpiresAt, bundle.KeyID, bundle.Signature, bundle.ContentTOML, bundle.MinGatewayVersion, bundle.DuplicateRule)
	}))
	defer srv.Close()

	first, err := fetchControlPlanePolicyLatest(srv.URL, "", "extension", "internal", "")
	if err != nil {
		t.Fatalf("fetchControlPlanePolicyLatest(first): %v", err)
	}
	if first.NotModified {
		t.Fatalf("first.NotModified = true, want false")
	}
	if first.ETag != etag {
		t.Fatalf("first.ETag = %q, want %q", first.ETag, etag)
	}

	second, err := fetchControlPlanePolicyLatest(srv.URL, "", "extension", "internal", first.ETag)
	if err != nil {
		t.Fatalf("fetchControlPlanePolicyLatest(second): %v", err)
	}
	if !second.NotModified {
		t.Fatalf("second.NotModified = false, want true")
	}
}

func TestPolicyLatestContract_InvalidBundleFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"manifest_id":"","profile":"internal"}`))
	}))
	defer srv.Close()

	_, err := fetchControlPlanePolicyLatest(srv.URL, "", "extension", "internal", "")
	if err == nil {
		t.Fatalf("fetchControlPlanePolicyLatest returned nil error")
	}
	if !strings.Contains(err.Error(), "invalid_bundle") {
		t.Fatalf("error = %q, want contains invalid_bundle", err.Error())
	}
}

func TestPolicyLatestContract_VerifyFetchedBundle(t *testing.T) {
	priv, pub := policyBundleKeyPairContract(111)
	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	bundle := signPolicyBundleContract(t, signedPolicyBundle{
		ManifestID:        "pmf_scan_internal_20260225_9999999999999999",
		Profile:           "internal",
		Version:           "2026.02.25-120000z",
		SHA256:            sha256HexBytes([]byte("required_scanners=[\"ClamAV\"]\n")),
		EffectiveAt:       now.Add(-1 * time.Hour).Format(time.RFC3339),
		ExpiresAt:         now.Add(24 * time.Hour).Format(time.RFC3339),
		KeyID:             "policy-key-v1",
		ContentTOML:       "required_scanners=[\"ClamAV\"]\n",
		MinGatewayVersion: "v0.5f",
		DuplicateRule:     "manifest_id+profile+sha256",
	}, priv)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"manifest_id":%q,"profile":%q,"version":%q,"sha256":%q,"effective_at":%q,"expires_at":%q,"key_id":%q,"signature":%q,"content_toml":%q,"min_gateway_version":%q,"duplicate_rule":%q}`,
			bundle.ManifestID, bundle.Profile, bundle.Version, bundle.SHA256, bundle.EffectiveAt, bundle.ExpiresAt, bundle.KeyID, bundle.Signature, bundle.ContentTOML, bundle.MinGatewayVersion, bundle.DuplicateRule)
	}))
	defer srv.Close()

	got, err := fetchControlPlanePolicyLatest(srv.URL, "", "scan", "internal", "")
	if err != nil {
		t.Fatalf("fetchControlPlanePolicyLatest: %v", err)
	}
	if got.NotModified {
		t.Fatalf("NotModified = true, want false")
	}
	if err := verifySignedPolicyBundle(got.Bundle, now, map[string]ed25519.PublicKey{"policy-key-v1": pub}); err != nil {
		t.Fatalf("verifySignedPolicyBundle: %v", err)
	}
}

func TestPolicyLatestContract_DuplicateRulePresent(t *testing.T) {
	priv, _ := policyBundleKeyPairContract(121)
	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	bundle := signPolicyBundleContract(t, signedPolicyBundle{
		ManifestID:        "pmf_extension_public_20260225_abababababababab",
		Profile:           "public",
		Version:           "2026.02.25-120000z",
		SHA256:            sha256HexBytes([]byte("scan_only_extensions=[\".txt\"]\n")),
		EffectiveAt:       now.Add(-1 * time.Hour).Format(time.RFC3339),
		ExpiresAt:         now.Add(24 * time.Hour).Format(time.RFC3339),
		KeyID:             "policy-key-v1",
		ContentTOML:       "scan_only_extensions=[\".txt\"]\n",
		MinGatewayVersion: "v0.5f",
		DuplicateRule:     "manifest_id+profile+sha256",
	}, priv)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"manifest_id":%q,"profile":%q,"version":%q,"sha256":%q,"effective_at":%q,"expires_at":%q,"key_id":%q,"signature":%q,"content_toml":%q,"min_gateway_version":%q,"duplicate_rule":%q}`,
			bundle.ManifestID, bundle.Profile, bundle.Version, bundle.SHA256, bundle.EffectiveAt, bundle.ExpiresAt, bundle.KeyID, bundle.Signature, bundle.ContentTOML, bundle.MinGatewayVersion, bundle.DuplicateRule)
	}))
	defer srv.Close()

	got, err := fetchControlPlanePolicyLatest(srv.URL, "", "extension", "public", "")
	if err != nil {
		t.Fatalf("fetchControlPlanePolicyLatest: %v", err)
	}
	if got.Bundle.DuplicateRule != "manifest_id+profile+sha256" {
		t.Fatalf("duplicate_rule = %q, want manifest_id+profile+sha256", got.Bundle.DuplicateRule)
	}
}

func TestPolicyLatestContract_DecodeSignatureB64Sanity(t *testing.T) {
	priv, _ := policyBundleKeyPairContract(131)
	bundle := signPolicyBundleContract(t, signedPolicyBundle{
		ManifestID:        "pmf_extension_internal_20260225_1212121212121212",
		Profile:           "internal",
		Version:           "2026.02.25-120000z",
		SHA256:            sha256HexBytes([]byte("max_size_mb = 50\n")),
		EffectiveAt:       "2026-02-25T11:00:00Z",
		ExpiresAt:         "2026-02-26T12:00:00Z",
		KeyID:             "policy-key-v1",
		ContentTOML:       "max_size_mb = 50\n",
		MinGatewayVersion: "v0.5f",
		DuplicateRule:     "manifest_id+profile+sha256",
	}, priv)
	if _, err := base64.StdEncoding.DecodeString(bundle.Signature); err != nil {
		t.Fatalf("signature should be base64: %v", err)
	}
}

func TestPolicyLatestContract_SendsGatewayIDAndChannelQuery(t *testing.T) {
	t.Setenv("ZT_GATEWAY_ID", "gw-contract-1")
	t.Setenv("ZT_POLICY_ROLLOUT_CHANNEL", "canary")
	priv, _ := policyBundleKeyPairContract(141)
	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	bundle := signPolicyBundleContract(t, signedPolicyBundle{
		ManifestID:        "pmf_extension_internal_20260225_1313131313131313",
		Profile:           "internal",
		Version:           "2026.02.25-120000z",
		SHA256:            sha256HexBytes([]byte("max_size_mb = 50\n")),
		EffectiveAt:       now.Add(-1 * time.Hour).Format(time.RFC3339),
		ExpiresAt:         now.Add(24 * time.Hour).Format(time.RFC3339),
		KeyID:             "policy-key-v1",
		ContentTOML:       "max_size_mb = 50\n",
		MinGatewayVersion: "v0.5f",
		DuplicateRule:     "manifest_id+profile+sha256",
		RolloutID:         "rollout-x",
		RolloutChannel:    "canary",
		RolloutRule:       "sha256(gateway_id+rollout_id)%100<25",
	}, priv)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("gateway_id"); got != "gw-contract-1" {
			t.Fatalf("gateway_id query = %q, want gw-contract-1", got)
		}
		if got := r.URL.Query().Get("channel"); got != "canary" {
			t.Fatalf("channel query = %q, want canary", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"manifest_id":%q,"profile":%q,"version":%q,"sha256":%q,"effective_at":%q,"expires_at":%q,"key_id":%q,"signature":%q,"content_toml":%q,"min_gateway_version":%q,"duplicate_rule":%q,"rollout_id":%q,"rollout_channel":%q,"rollout_rule":%q}`,
			bundle.ManifestID, bundle.Profile, bundle.Version, bundle.SHA256, bundle.EffectiveAt, bundle.ExpiresAt, bundle.KeyID, bundle.Signature, bundle.ContentTOML, bundle.MinGatewayVersion, bundle.DuplicateRule, bundle.RolloutID, bundle.RolloutChannel, bundle.RolloutRule)
	}))
	defer srv.Close()

	got, err := fetchControlPlanePolicyLatest(srv.URL, "", "extension", "internal", "")
	if err != nil {
		t.Fatalf("fetchControlPlanePolicyLatest: %v", err)
	}
	if got.Bundle.RolloutChannel != "canary" {
		t.Fatalf("rollout_channel = %q, want canary", got.Bundle.RolloutChannel)
	}
}
