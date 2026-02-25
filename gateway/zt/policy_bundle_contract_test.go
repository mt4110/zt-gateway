package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

func TestPolicyBundleSignatureContract_VerifyNormal(t *testing.T) {
	priv, pub := policyBundleKeyPairContract(10)
	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	bundle := signedPolicyBundle{
		ManifestID:  "pmf_extension_internal_20260225_aaaaaaaaaaaaaaaa",
		Profile:     "internal",
		Version:     "2026.02.25-120000z",
		ContentTOML: "max_size_mb = 50\n",
		SHA256:      sha256HexBytes([]byte("max_size_mb = 50\n")),
		EffectiveAt: now.Add(-1 * time.Hour).Format(time.RFC3339),
		ExpiresAt:   now.Add(24 * time.Hour).Format(time.RFC3339),
		KeyID:       "policy-key-v1",
	}
	bundle = signPolicyBundleContract(t, bundle, priv)

	err := verifySignedPolicyBundle(bundle, now, map[string]ed25519.PublicKey{"policy-key-v1": pub})
	if err != nil {
		t.Fatalf("verifySignedPolicyBundle returned error: %v", err)
	}
}

func TestPolicyBundleSignatureContract_TamperFailsClosed(t *testing.T) {
	priv, pub := policyBundleKeyPairContract(20)
	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	bundle := signedPolicyBundle{
		ManifestID:  "pmf_scan_internal_20260225_bbbbbbbbbbbbbbbb",
		Profile:     "internal",
		Version:     "2026.02.25-120000z",
		ContentTOML: "required_scanners=[\"ClamAV\"]\n",
		SHA256:      sha256HexBytes([]byte("required_scanners=[\"ClamAV\"]\n")),
		EffectiveAt: now.Add(-1 * time.Hour).Format(time.RFC3339),
		ExpiresAt:   now.Add(24 * time.Hour).Format(time.RFC3339),
		KeyID:       "policy-key-v1",
	}
	bundle = signPolicyBundleContract(t, bundle, priv)
	bundle.ContentTOML = "required_scanners=[]\n"

	err := verifySignedPolicyBundle(bundle, now, map[string]ed25519.PublicKey{"policy-key-v1": pub})
	if err == nil {
		t.Fatalf("verifySignedPolicyBundle returned nil, want fail-closed")
	}
	if !isPolicyBundleFailClosedError(err) {
		t.Fatalf("error should be fail-closed: %v", err)
	}
	assertPolicyBundleErrorCodeContract(t, err, policyErrorCodeVerifyFailed)
}

func TestPolicyBundleSignatureContract_ExpiredFailsClosed(t *testing.T) {
	priv, pub := policyBundleKeyPairContract(30)
	now := time.Date(2026, 2, 26, 12, 0, 0, 0, time.UTC)
	bundle := signedPolicyBundle{
		ManifestID:  "pmf_extension_regulated_20260225_cccccccccccccccc",
		Profile:     "regulated",
		Version:     "2026.02.25-120000z",
		ContentTOML: "deny_extensions=[\".exe\"]\n",
		SHA256:      sha256HexBytes([]byte("deny_extensions=[\".exe\"]\n")),
		EffectiveAt: now.Add(-26 * time.Hour).Format(time.RFC3339),
		ExpiresAt:   now.Add(-2 * time.Hour).Format(time.RFC3339),
		KeyID:       "policy-key-v1",
	}
	bundle = signPolicyBundleContract(t, bundle, priv)

	err := verifySignedPolicyBundle(bundle, now, map[string]ed25519.PublicKey{"policy-key-v1": pub})
	if err == nil {
		t.Fatalf("verifySignedPolicyBundle returned nil, want fail-closed")
	}
	if !isPolicyBundleFailClosedError(err) {
		t.Fatalf("error should be fail-closed: %v", err)
	}
	assertPolicyBundleErrorCodeContract(t, err, policyErrorCodeStale)
}

func TestPolicyBundleSignatureContract_KeyMismatchFailsClosed(t *testing.T) {
	priv, _ := policyBundleKeyPairContract(40)
	_, otherPub := policyBundleKeyPairContract(90)
	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	bundle := signedPolicyBundle{
		ManifestID:  "pmf_extension_internal_20260225_dddddddddddddddd",
		Profile:     "internal",
		Version:     "2026.02.25-120000z",
		ContentTOML: "scan_only_extensions=[\".txt\"]\n",
		SHA256:      sha256HexBytes([]byte("scan_only_extensions=[\".txt\"]\n")),
		EffectiveAt: now.Add(-1 * time.Hour).Format(time.RFC3339),
		ExpiresAt:   now.Add(24 * time.Hour).Format(time.RFC3339),
		KeyID:       "policy-key-v1",
	}
	bundle = signPolicyBundleContract(t, bundle, priv)

	err := verifySignedPolicyBundle(bundle, now, map[string]ed25519.PublicKey{"policy-key-v1": otherPub})
	if err == nil {
		t.Fatalf("verifySignedPolicyBundle returned nil, want fail-closed")
	}
	if !isPolicyBundleFailClosedError(err) {
		t.Fatalf("error should be fail-closed: %v", err)
	}
	assertPolicyBundleErrorCodeContract(t, err, policyErrorCodeVerifyFailed)
}

func policyBundleKeyPairContract(seedStart byte) (ed25519.PrivateKey, ed25519.PublicKey) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = seedStart + byte(i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return priv, priv.Public().(ed25519.PublicKey)
}

func signPolicyBundleContract(t *testing.T, bundle signedPolicyBundle, priv ed25519.PrivateKey) signedPolicyBundle {
	t.Helper()
	signingBytes, err := policyBundleSigningBytes(bundle)
	if err != nil {
		t.Fatalf("policyBundleSigningBytes: %v", err)
	}
	bundle.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, signingBytes))
	return bundle
}

func assertPolicyBundleErrorCodeContract(t *testing.T, err error, wantCode string) {
	t.Helper()
	var verr *policyBundleVerifyError
	if !errors.As(err, &verr) {
		t.Fatalf("error type = %T, want *policyBundleVerifyError", err)
	}
	if verr.ErrorCode != wantCode {
		t.Fatalf("error_code = %q, want %q (err=%v)", verr.ErrorCode, wantCode, err)
	}
}
