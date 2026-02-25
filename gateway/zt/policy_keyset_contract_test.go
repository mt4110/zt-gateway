package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPolicyKeysetContract_FetchAndDecodeTrustedKeys(t *testing.T) {
	pub := policyKeysetPublicKeyContract(51)
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/policies/keyset" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fmt.Sprintf(`{
  "schema_version": "zt-policy-keyset-v1",
  "generated_at": "2026-02-25T12:00:00Z",
  "keys": [{
    "key_id": "cp-policy-key-v1",
    "alg": "Ed25519",
    "public_key_b64": %q,
    "status": "active"
  }]
}`, pubB64)))
	}))
	defer srv.Close()

	keys, err := fetchControlPlanePolicyTrustedKeys(srv.URL, "")
	if err != nil {
		t.Fatalf("fetchControlPlanePolicyTrustedKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("len(keys) = %d, want 1", len(keys))
	}
	if string(keys["cp-policy-key-v1"]) != string(pub) {
		t.Fatalf("decoded public key mismatch")
	}
}

func TestPolicyKeysetContract_UnsupportedAlgFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{
  "schema_version": "zt-policy-keyset-v1",
  "keys": [{"key_id":"cp-policy-key-v1","alg":"RSA","public_key_b64":"QUFBQQ==","status":"active"}]
}`))
	}))
	defer srv.Close()

	_, err := fetchControlPlanePolicyTrustedKeys(srv.URL, "")
	if err == nil {
		t.Fatalf("fetchControlPlanePolicyTrustedKeys returned nil, want error")
	}
	if !strings.Contains(err.Error(), "unsupported_alg") {
		t.Fatalf("error = %q, want contains unsupported_alg", err.Error())
	}
}

func TestPolicyKeysetContract_NoActiveKeysFailsClosed(t *testing.T) {
	pub := policyKeysetPublicKeyContract(61)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(fmt.Sprintf(`{
  "schema_version": "zt-policy-keyset-v1",
  "keys": [{"key_id":"cp-policy-key-v1","alg":"Ed25519","public_key_b64":%q,"status":"retired"}]
}`, base64.StdEncoding.EncodeToString(pub))))
	}))
	defer srv.Close()

	_, err := fetchControlPlanePolicyTrustedKeys(srv.URL, "")
	if err == nil {
		t.Fatalf("fetchControlPlanePolicyTrustedKeys returned nil, want error")
	}
	if !strings.Contains(err.Error(), "no_active_keys") {
		t.Fatalf("error = %q, want contains no_active_keys", err.Error())
	}
}

func TestPolicyKeysetContract_HTTPErrorIsReported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"not_found"}`))
	}))
	defer srv.Close()

	_, err := fetchControlPlanePolicyTrustedKeys(srv.URL, "")
	if err == nil {
		t.Fatalf("fetchControlPlanePolicyTrustedKeys returned nil, want error")
	}
	if !strings.Contains(err.Error(), "http_404:not_found") {
		t.Fatalf("error = %q, want contains http_404:not_found", err.Error())
	}
}

func policyKeysetPublicKeyContract(seedStart byte) ed25519.PublicKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = seedStart + byte(i)
	}
	return ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
}
