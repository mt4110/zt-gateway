package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type policyKeysetContractResponse struct {
	SchemaVersion string                       `json:"schema_version"`
	GeneratedAt   string                       `json:"generated_at"`
	Keys          []policyKeysetContractRecord `json:"keys"`
}

type policyKeysetContractRecord struct {
	KeyID        string `json:"key_id"`
	Alg          string `json:"alg"`
	PublicKeyB64 string `json:"public_key_b64"`
	Status       string `json:"status"`
}

func TestPolicyKeysetContract_ReturnsActiveEd25519Key(t *testing.T) {
	signer := newPolicyBundleSignerContract(71, 24*time.Hour)
	srv := &server{policySigner: signer}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/policies/keyset", nil)
	srv.handlePolicyKeyset(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("ETag") == "" {
		t.Fatalf("ETag is empty")
	}
	var got policyKeysetContractResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.SchemaVersion != "zt-policy-keyset-v1" {
		t.Fatalf("schema_version = %q, want zt-policy-keyset-v1", got.SchemaVersion)
	}
	if len(got.Keys) != 1 {
		t.Fatalf("keys len = %d, want 1", len(got.Keys))
	}
	k := got.Keys[0]
	if k.KeyID != signer.KeyID {
		t.Fatalf("key_id = %q, want %q", k.KeyID, signer.KeyID)
	}
	if k.Alg != "Ed25519" {
		t.Fatalf("alg = %q, want Ed25519", k.Alg)
	}
	if k.Status != "active" {
		t.Fatalf("status = %q, want active", k.Status)
	}
	pubDecoded, err := base64.StdEncoding.DecodeString(k.PublicKeyB64)
	if err != nil {
		t.Fatalf("DecodeString(public_key_b64): %v", err)
	}
	wantPub := signer.Priv.Public().(ed25519.PublicKey)
	if string(pubDecoded) != string(wantPub) {
		t.Fatalf("public_key_b64 does not match signer public key")
	}
}

func TestPolicyKeysetContract_ETagNotModified(t *testing.T) {
	signer := newPolicyBundleSignerContract(81, 24*time.Hour)
	srv := &server{policySigner: signer}

	first := httptest.NewRecorder()
	srv.handlePolicyKeyset(first, httptest.NewRequest(http.MethodGet, "/v1/policies/keyset", nil))
	if first.Code != http.StatusOK {
		t.Fatalf("first status = %d, want 200", first.Code)
	}
	etag := first.Header().Get("ETag")
	if etag == "" {
		t.Fatalf("ETag is empty")
	}

	second := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/policies/keyset", nil)
	req.Header.Set("If-None-Match", etag)
	srv.handlePolicyKeyset(second, req)
	if second.Code != http.StatusNotModified {
		t.Fatalf("second status = %d, want 304", second.Code)
	}
}

func TestPolicyKeysetContract_MissingSignerFailsClosed(t *testing.T) {
	srv := &server{policySigner: nil}
	rr := httptest.NewRecorder()
	srv.handlePolicyKeyset(rr, httptest.NewRequest(http.MethodGet, "/v1/policies/keyset", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got, _ := resp["error"].(string); got != "policy_signing_not_configured" {
		t.Fatalf("error = %q, want policy_signing_not_configured", got)
	}
}
