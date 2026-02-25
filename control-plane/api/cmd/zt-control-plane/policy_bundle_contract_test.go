package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPolicyBundleSignatureContract_LatestEndpointReturnsSignedBundle(t *testing.T) {
	signer := newPolicyBundleSignerContract(11, 24*time.Hour)
	policyDir := t.TempDir()
	policyPath := filepath.Join(policyDir, "extension_policy.toml")
	content := "scan_only_extensions=[\".txt\"]\n"
	if err := os.WriteFile(policyPath, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	mod := time.Date(2026, 2, 25, 9, 0, 0, 0, time.UTC)
	if err := os.Chtimes(policyPath, mod, mod); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}

	srv := &server{policyDir: policyDir, policySigner: signer}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/policies/extension/latest?profile=internal&gateway_id=gw-a", nil)
	srv.handlePolicyLatest("extension_policy.toml").ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	var bundle policyBundle
	if err := json.Unmarshal(rr.Body.Bytes(), &bundle); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	assertPolicyBundleRequiredFieldsContract(t, bundle)
	if bundle.Profile != "internal" {
		t.Fatalf("profile = %q, want internal", bundle.Profile)
	}
	if bundle.SHA256 != sha256Hex([]byte(bundle.ContentTOML)) {
		t.Fatalf("sha256 mismatch in response")
	}
	if rr.Header().Get("ETag") != "\"sha256:"+bundle.SHA256+"\"" {
		t.Fatalf("ETag = %q, want sha256 etag", rr.Header().Get("ETag"))
	}
	if !verifyPolicyBundleSignatureContract(t, bundle, signer.Priv.Public().(ed25519.PublicKey)) {
		t.Fatalf("signature verification failed")
	}
}

func TestPolicyBundleSignatureContract_ProfilePolicyPathSelection(t *testing.T) {
	signer := newPolicyBundleSignerContract(21, 12*time.Hour)
	policyDir := t.TempDir()
	profileDir := filepath.Join(policyDir, "profiles", "regulated")
	if err := os.MkdirAll(profileDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	path := filepath.Join(profileDir, "scan_policy.toml")
	if err := os.WriteFile(path, []byte("required_scanners=[\"ClamAV\"]\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	srv := &server{policyDir: policyDir, policySigner: signer}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/policies/scan/latest?profile=regulated&gateway_id=gw-a", nil)
	srv.handlePolicyLatest("scan_policy.toml").ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	var bundle policyBundle
	if err := json.Unmarshal(rr.Body.Bytes(), &bundle); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if bundle.Profile != "regulated" {
		t.Fatalf("profile = %q, want regulated", bundle.Profile)
	}
	if !verifyPolicyBundleSignatureContract(t, bundle, signer.Priv.Public().(ed25519.PublicKey)) {
		t.Fatalf("signature verification failed")
	}
}

func TestPolicyBundleSignatureContract_MissingSignerFailsClosed(t *testing.T) {
	srv := &server{policyDir: t.TempDir(), policySigner: nil}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/policies/extension/latest", nil)
	srv.handlePolicyLatest("extension_policy.toml").ServeHTTP(rr, req)

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

func TestPolicyBundleSignatureContract_GatewayIDRequired(t *testing.T) {
	signer := newPolicyBundleSignerContract(29, 24*time.Hour)
	policyDir := t.TempDir()
	policyPath := filepath.Join(policyDir, "extension_policy.toml")
	if err := os.WriteFile(policyPath, []byte("scan_only_extensions=[\".txt\"]\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	srv := &server{policyDir: policyDir, policySigner: signer}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/policies/extension/latest?profile=internal", nil)
	srv.handlePolicyLatest("extension_policy.toml").ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got, _ := resp["error"].(string); got != "gateway_id_required" {
		t.Fatalf("error = %q, want gateway_id_required", got)
	}
}

func TestPolicyBundleSignatureContract_TamperBreaksVerification(t *testing.T) {
	signer := newPolicyBundleSignerContract(31, 24*time.Hour)
	bundle, err := signer.Sign(policyBundle{
		ManifestID:        "pmf_extension_internal_test_aaaaaaaaaaaaaaaa",
		Profile:           "internal",
		Version:           "2026.02.25-090000z",
		SHA256:            sha256Hex([]byte("max_size_mb = 10\n")),
		EffectiveAt:       "2026-02-25T09:00:00Z",
		ExpiresAt:         "2026-02-26T09:00:00Z",
		KeyID:             signer.KeyID,
		ContentTOML:       "max_size_mb = 10\n",
		MinGatewayVersion: "v0.5f",
		DuplicateRule:     "manifest_id+profile+sha256",
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !verifyPolicyBundleSignatureContract(t, bundle, signer.Priv.Public().(ed25519.PublicKey)) {
		t.Fatalf("signature verification failed before tamper")
	}
	bundle.ContentTOML = "max_size_mb = 99\n"
	if verifyPolicyBundleSignatureContract(t, bundle, signer.Priv.Public().(ed25519.PublicKey)) {
		t.Fatalf("tampered bundle unexpectedly verified")
	}
}

func TestPolicyBundleSignatureContract_LoadSignerAutoProvisionedFromDataDir(t *testing.T) {
	t.Setenv("ZT_CP_POLICY_SIGNING_ED25519_PRIV_B64", "")
	t.Setenv("ZT_CP_POLICY_SIGNING_KEY_ID", "")
	t.Setenv("ZT_CP_POLICY_SIGNING_KEY_FILE", "")
	t.Setenv("ZT_CP_POLICY_BUNDLE_TTL_HOURS", "")

	dataDir := t.TempDir()
	signer1, err := loadPolicyBundleSigner(dataDir)
	if err != nil {
		t.Fatalf("loadPolicyBundleSigner(first): %v", err)
	}
	if signer1 == nil {
		t.Fatalf("signer1 = nil")
	}
	if !strings.HasPrefix(signer1.KeyID, defaultPolicyKeyIDPrefix+"-") {
		t.Fatalf("key_id = %q, want %q prefix", signer1.KeyID, defaultPolicyKeyIDPrefix+"-")
	}
	keyPath := filepath.Join(dataDir, defaultPolicySigningKeyFileRel)
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("os.Stat(%s): %v", keyPath, err)
	}

	signer2, err := loadPolicyBundleSigner(dataDir)
	if err != nil {
		t.Fatalf("loadPolicyBundleSigner(second): %v", err)
	}
	if signer2 == nil {
		t.Fatalf("signer2 = nil")
	}
	if signer2.KeyID != signer1.KeyID {
		t.Fatalf("key_id changed: %q -> %q", signer1.KeyID, signer2.KeyID)
	}
	if string(signer2.Priv) != string(signer1.Priv) {
		t.Fatalf("private key changed between loads")
	}
}

func TestPolicyBundleSignatureContract_LoadSignerEnvOverride(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(90 + i)
	}
	t.Setenv("ZT_CP_POLICY_SIGNING_ED25519_PRIV_B64", base64.StdEncoding.EncodeToString(seed))
	t.Setenv("ZT_CP_POLICY_SIGNING_KEY_ID", "ops-policy-key")
	t.Setenv("ZT_CP_POLICY_SIGNING_KEY_FILE", "custom/policy.seed.b64")
	t.Setenv("ZT_CP_POLICY_BUNDLE_TTL_HOURS", "48")

	signer, err := loadPolicyBundleSigner(t.TempDir())
	if err != nil {
		t.Fatalf("loadPolicyBundleSigner: %v", err)
	}
	if signer == nil {
		t.Fatalf("signer = nil")
	}
	if signer.KeyID != "ops-policy-key" {
		t.Fatalf("key_id = %q, want ops-policy-key", signer.KeyID)
	}
	if signer.TTL != 48*time.Hour {
		t.Fatalf("ttl = %s, want 48h", signer.TTL)
	}
	wantPriv := ed25519.NewKeyFromSeed(seed)
	if string(signer.Priv) != string(wantPriv) {
		t.Fatalf("private key mismatch for env override")
	}
}

func TestPolicyBundleSignatureContract_LoadSignerModeEnvRequiresEnvKey(t *testing.T) {
	t.Setenv("ZT_CP_POLICY_SIGNING_MODE", policySigningModeEnv)
	t.Setenv("ZT_CP_POLICY_SIGNING_ED25519_PRIV_B64", "")
	t.Setenv("ZT_CP_POLICY_SIGNING_KEY_FILE", "")

	_, err := loadPolicyBundleSigner(t.TempDir())
	if err == nil {
		t.Fatalf("loadPolicyBundleSigner returned nil error, want fail-fast")
	}
	if !strings.Contains(err.Error(), "policy_signing_env_required") {
		t.Fatalf("error = %q, want contains policy_signing_env_required", err.Error())
	}
}

func TestPolicyBundleSignatureContract_LoadSignerModeFilePrefersFileOverEnv(t *testing.T) {
	envSeed := makePolicyBundleSeedContract(130)
	fileSeed := makePolicyBundleSeedContract(150)

	dataDir := t.TempDir()
	keyPath := filepath.Join(dataDir, "keys", "ops.seed.b64")
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(fileSeed)+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(keyPath): %v", err)
	}

	t.Setenv("ZT_CP_POLICY_SIGNING_MODE", policySigningModeFile)
	t.Setenv("ZT_CP_POLICY_SIGNING_ED25519_PRIV_B64", base64.StdEncoding.EncodeToString(envSeed))
	t.Setenv("ZT_CP_POLICY_SIGNING_KEY_FILE", "keys/ops.seed.b64")

	signer, err := loadPolicyBundleSigner(dataDir)
	if err != nil {
		t.Fatalf("loadPolicyBundleSigner: %v", err)
	}
	wantFromFile := ed25519.NewKeyFromSeed(fileSeed)
	if string(signer.Priv) != string(wantFromFile) {
		t.Fatalf("mode=file should load key from file, env key must not override")
	}
}

func TestPolicyBundleSignatureContract_LoadSignerModeEnvPrefersEnvOverFile(t *testing.T) {
	envSeed := makePolicyBundleSeedContract(160)
	fileSeed := makePolicyBundleSeedContract(170)

	dataDir := t.TempDir()
	keyPath := filepath.Join(dataDir, "keys", "ops.seed.b64")
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(fileSeed)+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(keyPath): %v", err)
	}

	t.Setenv("ZT_CP_POLICY_SIGNING_MODE", policySigningModeEnv)
	t.Setenv("ZT_CP_POLICY_SIGNING_ED25519_PRIV_B64", base64.StdEncoding.EncodeToString(envSeed))
	t.Setenv("ZT_CP_POLICY_SIGNING_KEY_FILE", "keys/ops.seed.b64")

	signer, err := loadPolicyBundleSigner(dataDir)
	if err != nil {
		t.Fatalf("loadPolicyBundleSigner: %v", err)
	}
	wantFromEnv := ed25519.NewKeyFromSeed(envSeed)
	if string(signer.Priv) != string(wantFromEnv) {
		t.Fatalf("mode=env should load key from env, file key must not override")
	}
}

func TestPolicyBundleSignatureContract_LoadSignerModeFileMissingFailsFast(t *testing.T) {
	t.Setenv("ZT_CP_POLICY_SIGNING_MODE", policySigningModeFile)
	t.Setenv("ZT_CP_POLICY_SIGNING_KEY_FILE", "keys/missing.seed.b64")
	t.Setenv("ZT_CP_POLICY_SIGNING_ED25519_PRIV_B64", base64.StdEncoding.EncodeToString(makePolicyBundleSeedContract(180)))

	_, err := loadPolicyBundleSigner(t.TempDir())
	if err == nil {
		t.Fatalf("loadPolicyBundleSigner returned nil error, want fail-fast")
	}
	if !strings.Contains(err.Error(), "policy_signing_file_missing") {
		t.Fatalf("error = %q, want contains policy_signing_file_missing", err.Error())
	}
}

func TestPolicyBundleSignatureContract_LoadSignerInvalidModeFailsFast(t *testing.T) {
	t.Setenv("ZT_CP_POLICY_SIGNING_MODE", "invalid-mode")

	_, err := loadPolicyBundleSigner(t.TempDir())
	if err == nil {
		t.Fatalf("loadPolicyBundleSigner returned nil error, want fail-fast")
	}
	if !strings.Contains(err.Error(), "policy_signing_mode_invalid") {
		t.Fatalf("error = %q, want contains policy_signing_mode_invalid", err.Error())
	}
}

func makePolicyBundleSeedContract(seedStart byte) []byte {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = seedStart + byte(i)
	}
	return seed
}

func newPolicyBundleSignerContract(seedStart byte, ttl time.Duration) *policyBundleSigner {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = seedStart + byte(i)
	}
	return &policyBundleSigner{
		KeyID: "cp-policy-key-v1",
		Priv:  ed25519.NewKeyFromSeed(seed),
		TTL:   ttl,
	}
}

func verifyPolicyBundleSignatureContract(t *testing.T, bundle policyBundle, pub ed25519.PublicKey) bool {
	t.Helper()
	sig, err := base64.StdEncoding.DecodeString(bundle.Signature)
	if err != nil {
		t.Fatalf("DecodeString(signature): %v", err)
	}
	signingBytes, err := policyBundleSigningBytes(bundle)
	if err != nil {
		t.Fatalf("policyBundleSigningBytes: %v", err)
	}
	return ed25519.Verify(pub, signingBytes, sig)
}

func assertPolicyBundleRequiredFieldsContract(t *testing.T, bundle policyBundle) {
	t.Helper()
	if bundle.ManifestID == "" {
		t.Fatalf("manifest_id is empty")
	}
	if bundle.Profile == "" {
		t.Fatalf("profile is empty")
	}
	if bundle.Version == "" {
		t.Fatalf("version is empty")
	}
	if bundle.SHA256 == "" {
		t.Fatalf("sha256 is empty")
	}
	if bundle.EffectiveAt == "" {
		t.Fatalf("effective_at is empty")
	}
	if bundle.ExpiresAt == "" {
		t.Fatalf("expires_at is empty")
	}
	if bundle.KeyID == "" {
		t.Fatalf("key_id is empty")
	}
	if bundle.Signature == "" {
		t.Fatalf("signature is empty")
	}
	if bundle.ContentTOML == "" {
		t.Fatalf("content_toml is empty")
	}
	if bundle.MinGatewayVersion == "" {
		t.Fatalf("min_gateway_version is empty")
	}
	if bundle.DuplicateRule == "" {
		t.Fatalf("duplicate_rule is empty")
	}
	if strings.TrimSpace(bundle.PolicySetID) == "" {
		t.Fatalf("policy_set_id is empty")
	}
	if bundle.FreshnessSLOSec <= 0 {
		t.Fatalf("freshness_slo_seconds = %d, want > 0", bundle.FreshnessSLOSec)
	}
}
