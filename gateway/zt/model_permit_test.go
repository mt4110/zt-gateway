package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRuntimePermitValidatesForManifest(t *testing.T) {
	manifest := testRuntimePermitManifest(t)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 5, 26, 0, 0, 0, 0, time.UTC)
	permit, err := newRuntimePermitForManifest(manifest, "dev-a", "llama.cpp", "", now, time.Hour)
	if err != nil {
		t.Fatalf("newRuntimePermitForManifest: %v", err)
	}
	permit, err = signRuntimePermit(permit, "rtp_test", priv)
	if err != nil {
		t.Fatalf("signRuntimePermit: %v", err)
	}
	if err := validateRuntimePermitForManifest(permit, manifest, "dev-a", "llama.cpp", now.Add(time.Minute), pub); err != nil {
		t.Fatalf("validateRuntimePermitForManifest: %v", err)
	}
}

func TestRuntimePermitValidationCanonicalizesExpectedRuntime(t *testing.T) {
	manifest := testRuntimePermitManifest(t)
	pub, priv := generateRuntimePermitKey(t)
	now := time.Date(2026, 5, 26, 0, 0, 0, 0, time.UTC)
	permit, err := newRuntimePermitForManifest(manifest, "dev-a", "fake", "", now, time.Hour)
	if err != nil {
		t.Fatalf("newRuntimePermitForManifest: %v", err)
	}
	permit, err = signRuntimePermit(permit, "rtp_test", priv)
	if err != nil {
		t.Fatalf("signRuntimePermit: %v", err)
	}
	if err := validateRuntimePermitForManifest(permit, manifest, "dev-a", "Fake", now.Add(time.Minute), pub); err != nil {
		t.Fatalf("validateRuntimePermitForManifest: %v", err)
	}
}

func TestRuntimePermitIssueRejectsDisallowedRuntime(t *testing.T) {
	manifest := testRuntimePermitManifest(t)
	now := time.Date(2026, 5, 26, 0, 0, 0, 0, time.UTC)
	_, err := newRuntimePermitForManifest(manifest, "dev-a", "ollama", "", now, time.Hour)
	if err == nil || !strings.Contains(err.Error(), "not allowed by model policy") {
		t.Fatalf("err=%v, want policy deny", err)
	}
}

func TestRuntimePermitIssueAllowsDefaultFakeRuntime(t *testing.T) {
	manifest := testRuntimePermitManifest(t)
	now := time.Date(2026, 5, 26, 0, 0, 0, 0, time.UTC)
	permit, err := newRuntimePermitForManifest(manifest, "dev-a", "Fake", "", now, time.Hour)
	if err != nil {
		t.Fatalf("newRuntimePermitForManifest: %v", err)
	}
	if permit.Runtime.Name != "fake" {
		t.Fatalf("runtime=%q, want fake", permit.Runtime.Name)
	}
}

func TestRuntimePermitIssueUsesKernelShieldTierWhenRequired(t *testing.T) {
	manifest := testRuntimePermitManifest(t)
	manifest.Policy.RequireKernelShield = true
	now := time.Date(2026, 5, 26, 0, 0, 0, 0, time.UTC)
	permit, err := newRuntimePermitForManifest(manifest, "dev-a", "llama.cpp", "", now, time.Hour)
	if err != nil {
		t.Fatalf("newRuntimePermitForManifest: %v", err)
	}
	if permit.Policy.ShieldMinTier != runtimePermitShieldTierKernelMode {
		t.Fatalf("shield_min_tier=%q, want %q", permit.Policy.ShieldMinTier, runtimePermitShieldTierKernelMode)
	}
}

func TestRuntimePermitIssueRejectsAttestationRequiredPolicy(t *testing.T) {
	manifest := testRuntimePermitManifest(t)
	manifest.Policy.RequireAttestation = true
	now := time.Date(2026, 5, 26, 0, 0, 0, 0, time.UTC)
	_, err := newRuntimePermitForManifest(manifest, "dev-a", "llama.cpp", "", now, time.Hour)
	if err == nil || !strings.Contains(err.Error(), "attestation policy") {
		t.Fatalf("err=%v, want attestation policy deny", err)
	}
}

func TestRuntimePermitIssueRejectsHashRestrictedPolicy(t *testing.T) {
	manifest := testRuntimePermitManifest(t)
	manifest.Policy.RuntimeBinaryHashes = []string{strings.Repeat("a", 64)}
	now := time.Date(2026, 5, 26, 0, 0, 0, 0, time.UTC)
	_, err := newRuntimePermitForManifest(manifest, "dev-a", "llama.cpp", "", now, time.Hour)
	if err == nil || !strings.Contains(err.Error(), "binary_sha256 is required") {
		t.Fatalf("err=%v, want binary hash required", err)
	}
}

func TestRuntimePermitIssueAllowsHashRestrictedPolicyWithAllowedHash(t *testing.T) {
	manifest := testRuntimePermitManifest(t)
	allowedHash := strings.Repeat("a", 64)
	manifest.Policy.RuntimeBinaryHashes = []string{allowedHash}
	now := time.Date(2026, 5, 26, 0, 0, 0, 0, time.UTC)
	permit, err := newRuntimePermitForManifest(manifest, "dev-a", "llama.cpp", allowedHash, now, time.Hour)
	if err != nil {
		t.Fatalf("newRuntimePermitForManifest: %v", err)
	}
	if permit.Runtime.BinarySHA256 != allowedHash {
		t.Fatalf("binary_sha256=%q, want %q", permit.Runtime.BinarySHA256, allowedHash)
	}
}

func TestRuntimePermitIssueCapsTTLToOfflineLeasePolicy(t *testing.T) {
	manifest := testRuntimePermitManifest(t)
	manifest.Policy.OfflineLeaseSeconds = 30
	now := time.Date(2026, 5, 26, 0, 0, 0, 0, time.UTC)
	permit, err := newRuntimePermitForManifest(manifest, "dev-a", "fake", "", now, time.Hour)
	if err != nil {
		t.Fatalf("newRuntimePermitForManifest: %v", err)
	}
	expiresAt, err := time.Parse(time.RFC3339, permit.Validity.ExpiresAt)
	if err != nil {
		t.Fatalf("expires_at parse: %v", err)
	}
	if expiresAt.Sub(now) != 30*time.Second {
		t.Fatalf("ttl=%s, want 30s", expiresAt.Sub(now))
	}
}

func TestRuntimePermitValidationRejectsLeaseBeyondManifestPolicy(t *testing.T) {
	manifest := testRuntimePermitManifest(t)
	manifest.Policy.OfflineLeaseSeconds = 30
	pub, priv := generateRuntimePermitKey(t)
	now := time.Date(2026, 5, 26, 0, 0, 0, 0, time.UTC)
	permit, err := newRuntimePermitForManifest(manifest, "dev-a", "llama.cpp", "", now, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	permit.Validity.ExpiresAt = now.Add(time.Minute).UTC().Format(time.RFC3339)
	permit, err = signRuntimePermit(permit, "rtp_test", priv)
	if err != nil {
		t.Fatal(err)
	}
	err = validateRuntimePermitForManifest(permit, manifest, "dev-a", "llama.cpp", now.Add(10*time.Second), pub)
	if err == nil || !strings.Contains(err.Error(), "validity exceeds capsule offline lease policy") {
		t.Fatalf("err=%v, want lease duration policy deny", err)
	}
}

func TestRuntimePermitValidationRejectsBroadenedOfflineLeasePolicy(t *testing.T) {
	manifest := testRuntimePermitManifest(t)
	manifest.Policy.OfflineLeaseSeconds = 30
	pub, priv := generateRuntimePermitKey(t)
	now := time.Date(2026, 5, 26, 0, 0, 0, 0, time.UTC)
	permit, err := newRuntimePermitForManifest(manifest, "dev-a", "llama.cpp", "", now, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	permit.Policy.OfflineLeaseSeconds = 60
	permit, err = signRuntimePermit(permit, "rtp_test", priv)
	if err != nil {
		t.Fatal(err)
	}
	err = validateRuntimePermitForManifest(permit, manifest, "dev-a", "llama.cpp", now.Add(10*time.Second), pub)
	if err == nil || !strings.Contains(err.Error(), "offline lease exceeds capsule policy") {
		t.Fatalf("err=%v, want permit policy deny", err)
	}
}

func TestRuntimePermitValidationRejectsAuditOnlyForKernelShieldPolicy(t *testing.T) {
	manifest := testRuntimePermitManifest(t)
	manifest.Policy.RequireKernelShield = true
	pub, priv := generateRuntimePermitKey(t)
	now := time.Date(2026, 5, 26, 0, 0, 0, 0, time.UTC)
	permit, err := newRuntimePermitForManifest(manifest, "dev-a", "llama.cpp", "", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	permit.Policy.ShieldMinTier = runtimePermitShieldTierAuditOnly
	permit, err = signRuntimePermit(permit, "rtp_test", priv)
	if err != nil {
		t.Fatal(err)
	}
	err = validateRuntimePermitForManifest(permit, manifest, "dev-a", "llama.cpp", now.Add(time.Minute), pub)
	if err == nil || !strings.Contains(err.Error(), "kernel shield policy") {
		t.Fatalf("err=%v, want kernel shield policy deny", err)
	}
}

func TestRuntimePermitValidationRejectsAttestationRequiredPolicy(t *testing.T) {
	manifest := testRuntimePermitManifest(t)
	pub, priv := generateRuntimePermitKey(t)
	now := time.Date(2026, 5, 26, 0, 0, 0, 0, time.UTC)
	permit, err := newRuntimePermitForManifest(manifest, "dev-a", "llama.cpp", "", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Policy.RequireAttestation = true
	permit, err = signRuntimePermit(permit, "rtp_test", priv)
	if err != nil {
		t.Fatal(err)
	}
	err = validateRuntimePermitForManifest(permit, manifest, "dev-a", "llama.cpp", now.Add(time.Minute), pub)
	if err == nil || !strings.Contains(err.Error(), "attestation policy") {
		t.Fatalf("err=%v, want attestation policy deny", err)
	}
}

func TestRuntimePermitExpiredDenies(t *testing.T) {
	manifest := testRuntimePermitManifest(t)
	pub, priv := generateRuntimePermitKey(t)
	now := time.Date(2026, 5, 26, 0, 0, 0, 0, time.UTC)
	permit, err := newRuntimePermitForManifest(manifest, "dev-a", "llama.cpp", "", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	permit, err = signRuntimePermit(permit, "rtp_test", priv)
	if err != nil {
		t.Fatal(err)
	}
	err = validateRuntimePermitForManifest(permit, manifest, "dev-a", "llama.cpp", now.Add(2*time.Hour), pub)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("err=%v, want expired", err)
	}
}

func TestRuntimePermitWrongCapsuleDenies(t *testing.T) {
	manifest := testRuntimePermitManifest(t)
	pub, priv := generateRuntimePermitKey(t)
	now := time.Date(2026, 5, 26, 0, 0, 0, 0, time.UTC)
	permit, err := newRuntimePermitForManifest(manifest, "dev-a", "llama.cpp", "", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	permit.CapsuleID = "zmc_wrong"
	permit, err = signRuntimePermit(permit, "rtp_test", priv)
	if err != nil {
		t.Fatal(err)
	}
	err = validateRuntimePermitForManifest(permit, manifest, "dev-a", "llama.cpp", now.Add(time.Minute), pub)
	if err == nil || !strings.Contains(err.Error(), "capsule mismatch") {
		t.Fatalf("err=%v, want capsule mismatch", err)
	}
}

func TestRuntimePermitWrongDeviceDenies(t *testing.T) {
	manifest := testRuntimePermitManifest(t)
	pub, priv := generateRuntimePermitKey(t)
	now := time.Date(2026, 5, 26, 0, 0, 0, 0, time.UTC)
	permit, err := newRuntimePermitForManifest(manifest, "dev-a", "llama.cpp", "", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	permit, err = signRuntimePermit(permit, "rtp_test", priv)
	if err != nil {
		t.Fatal(err)
	}
	err = validateRuntimePermitForManifest(permit, manifest, "dev-b", "llama.cpp", now.Add(time.Minute), pub)
	if err == nil || !strings.Contains(err.Error(), "device mismatch") {
		t.Fatalf("err=%v, want device mismatch", err)
	}
}

func TestRuntimePermitWrongRuntimeDenies(t *testing.T) {
	manifest := testRuntimePermitManifest(t)
	pub, priv := generateRuntimePermitKey(t)
	now := time.Date(2026, 5, 26, 0, 0, 0, 0, time.UTC)
	permit, err := newRuntimePermitForManifest(manifest, "dev-a", "llama.cpp", "", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	permit, err = signRuntimePermit(permit, "rtp_test", priv)
	if err != nil {
		t.Fatal(err)
	}
	err = validateRuntimePermitForManifest(permit, manifest, "dev-a", "ollama", now.Add(time.Minute), pub)
	if err == nil || !strings.Contains(err.Error(), "runtime mismatch") {
		t.Fatalf("err=%v, want runtime mismatch", err)
	}
}

func TestRuntimePermitValidationRejectsDisallowedRuntime(t *testing.T) {
	manifest := testRuntimePermitManifest(t)
	pub, priv := generateRuntimePermitKey(t)
	now := time.Date(2026, 5, 26, 0, 0, 0, 0, time.UTC)
	permit, err := newRuntimePermitForManifest(manifest, "dev-a", "llama.cpp", "", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	permit.Runtime.Name = "ollama"
	permit, err = signRuntimePermit(permit, "rtp_test", priv)
	if err != nil {
		t.Fatal(err)
	}
	err = validateRuntimePermitForManifest(permit, manifest, "dev-a", "ollama", now.Add(time.Minute), pub)
	if err == nil || !strings.Contains(err.Error(), "not allowed by model policy") {
		t.Fatalf("err=%v, want policy deny", err)
	}
}

func TestRuntimePermitValidationRejectsDisallowedBinaryHash(t *testing.T) {
	manifest := testRuntimePermitManifest(t)
	pub, priv := generateRuntimePermitKey(t)
	now := time.Date(2026, 5, 26, 0, 0, 0, 0, time.UTC)
	permit, err := newRuntimePermitForManifest(manifest, "dev-a", "llama.cpp", "", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Policy.RuntimeBinaryHashes = []string{strings.Repeat("a", 64)}
	permit.Runtime.BinarySHA256 = strings.Repeat("b", 64)
	permit, err = signRuntimePermit(permit, "rtp_test", priv)
	if err != nil {
		t.Fatal(err)
	}
	err = validateRuntimePermitForManifest(permit, manifest, "dev-a", "llama.cpp", now.Add(time.Minute), pub)
	if err == nil || !strings.Contains(err.Error(), "binary_sha256 is not allowed") {
		t.Fatalf("err=%v, want binary hash policy deny", err)
	}
}

func TestRuntimePermitSignatureMismatchDenies(t *testing.T) {
	manifest := testRuntimePermitManifest(t)
	pub, priv := generateRuntimePermitKey(t)
	now := time.Date(2026, 5, 26, 0, 0, 0, 0, time.UTC)
	permit, err := newRuntimePermitForManifest(manifest, "dev-a", "llama.cpp", "", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	permit, err = signRuntimePermit(permit, "rtp_test", priv)
	if err != nil {
		t.Fatal(err)
	}
	permit.PermitID = "permit_tampered"
	err = validateRuntimePermitForManifest(permit, manifest, "dev-a", "llama.cpp", now.Add(time.Minute), pub)
	if err == nil || !strings.Contains(err.Error(), "signature mismatch") {
		t.Fatalf("err=%v, want signature mismatch", err)
	}
}

func generateRuntimePermitKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func testRuntimePermitManifest(t *testing.T) modelCapsuleManifestV1 {
	t.Helper()
	dir := t.TempDir()
	modelPath := filepath.Join(dir, "demo.gguf")
	if err := os.WriteFile(modelPath, []byte("GGUFdemo"), 0644); err != nil {
		t.Fatal(err)
	}
	manifest, err := buildModelCapsuleManifest(buildModelManifestInput{
		ModelPath: modelPath,
		Name:      "demo",
		Version:   "1",
		Format:    "gguf",
		ClientID:  "edge-a",
		TenantID:  "tenant-a",
		Profile:   trustProfileConfidential,
		Runtimes:  []string{"fake", "llama.cpp"},
		CreatedAt: time.Date(2026, 5, 26, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}
