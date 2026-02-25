package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"testing"
	"time"
)

func TestPolicyActivationContract_ActivateStagedUpdatesActiveAndLKG(t *testing.T) {
	store := &policyActivationStore{stateDir: t.TempDir()}
	priv, pub := policyActivationKeyPairContract(10)
	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)

	bundle := signPolicyActivationBundleContract(t, signedPolicyBundle{
		ManifestID:  "pmf_extension_internal_20260225_aaaaaaaaaaaaaaaa",
		Profile:     "internal",
		Version:     "2026.02.25-120000z",
		SHA256:      sha256HexBytes([]byte("max_size_mb = 50\n")),
		EffectiveAt: now.Add(-1 * time.Hour).Format(time.RFC3339),
		ExpiresAt:   now.Add(24 * time.Hour).Format(time.RFC3339),
		KeyID:       "policy-key-v1",
		ContentTOML: "max_size_mb = 50\n",
	}, priv)

	if err := store.stage("extension", bundle); err != nil {
		t.Fatalf("stage: %v", err)
	}
	result, err := store.activateStaged("extension", map[string]ed25519.PublicKey{"policy-key-v1": pub}, now)
	if err != nil {
		t.Fatalf("activateStaged: %v", err)
	}
	if !result.Activated {
		t.Fatalf("Activated = false, want true")
	}
	if result.ActiveManifestID != bundle.ManifestID {
		t.Fatalf("ActiveManifestID = %q, want %q", result.ActiveManifestID, bundle.ManifestID)
	}

	active, err := store.readActive("extension")
	if err != nil {
		t.Fatalf("readActive: %v", err)
	}
	if active.ManifestID != bundle.ManifestID {
		t.Fatalf("active manifest_id = %q, want %q", active.ManifestID, bundle.ManifestID)
	}
	lkg, err := store.readLastKnownGood("extension")
	if err != nil {
		t.Fatalf("readLastKnownGood: %v", err)
	}
	if lkg.ManifestID != bundle.ManifestID {
		t.Fatalf("lkg manifest_id = %q, want %q", lkg.ManifestID, bundle.ManifestID)
	}
}

func TestPolicyActivationContract_BrokenStagedKeepsActiveUnchanged(t *testing.T) {
	store := &policyActivationStore{stateDir: t.TempDir()}
	priv, pub := policyActivationKeyPairContract(20)
	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)

	activeBundle := signPolicyActivationBundleContract(t, signedPolicyBundle{
		ManifestID:  "pmf_extension_internal_20260225_bbbbbbbbbbbbbbbb",
		Profile:     "internal",
		Version:     "2026.02.25-120000z",
		SHA256:      sha256HexBytes([]byte("scan_only_extensions=[\".txt\"]\n")),
		EffectiveAt: now.Add(-1 * time.Hour).Format(time.RFC3339),
		ExpiresAt:   now.Add(24 * time.Hour).Format(time.RFC3339),
		KeyID:       "policy-key-v1",
		ContentTOML: "scan_only_extensions=[\".txt\"]\n",
	}, priv)
	if err := store.stage("extension", activeBundle); err != nil {
		t.Fatalf("stage(active): %v", err)
	}
	if _, err := store.activateStaged("extension", map[string]ed25519.PublicKey{"policy-key-v1": pub}, now); err != nil {
		t.Fatalf("activateStaged(active): %v", err)
	}

	broken := signPolicyActivationBundleContract(t, signedPolicyBundle{
		ManifestID:  "pmf_extension_internal_20260225_cccccccccccccccc",
		Profile:     "internal",
		Version:     "2026.02.25-130000z",
		SHA256:      sha256HexBytes([]byte("scan_only_extensions=[\".md\"]\n")),
		EffectiveAt: now.Add(-1 * time.Hour).Format(time.RFC3339),
		ExpiresAt:   now.Add(24 * time.Hour).Format(time.RFC3339),
		KeyID:       "policy-key-v1",
		ContentTOML: "scan_only_extensions=[\".md\"]\n",
	}, priv)
	broken.ContentTOML = "scan_only_extensions=[\".json\"]\n" // tamper after signing
	if err := store.stage("extension", broken); err != nil {
		t.Fatalf("stage(broken): %v", err)
	}

	result, err := store.activateStaged("extension", map[string]ed25519.PublicKey{"policy-key-v1": pub}, now)
	if err == nil {
		t.Fatalf("activateStaged(broken) returned nil error, want fail-closed")
	}
	if result.Activated {
		t.Fatalf("Activated = true, want false")
	}
	var actErr *policyActivationError
	if !errors.As(err, &actErr) {
		t.Fatalf("error type = %T, want *policyActivationError", err)
	}
	if actErr.Code != "policy_activation_verify_failed" {
		t.Fatalf("error code = %q, want policy_activation_verify_failed", actErr.Code)
	}

	activeAfter, err := store.readActive("extension")
	if err != nil {
		t.Fatalf("readActive(after): %v", err)
	}
	if activeAfter.ManifestID != activeBundle.ManifestID {
		t.Fatalf("active changed on broken staged apply: got=%q want=%q", activeAfter.ManifestID, activeBundle.ManifestID)
	}
}

func TestPolicyActivationContract_RestoreFromLKGWhenActiveMissing(t *testing.T) {
	store := &policyActivationStore{stateDir: t.TempDir()}
	priv, pub := policyActivationKeyPairContract(30)
	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)

	good := signPolicyActivationBundleContract(t, signedPolicyBundle{
		ManifestID:  "pmf_scan_internal_20260225_dddddddddddddddd",
		Profile:     "internal",
		Version:     "2026.02.25-120000z",
		SHA256:      sha256HexBytes([]byte("required_scanners=[\"ClamAV\"]\n")),
		EffectiveAt: now.Add(-1 * time.Hour).Format(time.RFC3339),
		ExpiresAt:   now.Add(24 * time.Hour).Format(time.RFC3339),
		KeyID:       "policy-key-v1",
		ContentTOML: "required_scanners=[\"ClamAV\"]\n",
	}, priv)
	if err := writeSignedPolicyBundleAtomic(store.lastKnownGoodPath("scan"), good); err != nil {
		t.Fatalf("write lkg: %v", err)
	}

	broken := signPolicyActivationBundleContract(t, signedPolicyBundle{
		ManifestID:  "pmf_scan_internal_20260225_eeeeeeeeeeeeeeee",
		Profile:     "internal",
		Version:     "2026.02.25-130000z",
		SHA256:      sha256HexBytes([]byte("required_scanners=[\"YARA\"]\n")),
		EffectiveAt: now.Add(-1 * time.Hour).Format(time.RFC3339),
		ExpiresAt:   now.Add(24 * time.Hour).Format(time.RFC3339),
		KeyID:       "policy-key-v1",
		ContentTOML: "required_scanners=[\"YARA\"]\n",
	}, priv)
	broken.Signature = "%%%broken%%%"
	if err := store.stage("scan", broken); err != nil {
		t.Fatalf("stage(broken): %v", err)
	}

	result, err := store.activateStaged("scan", map[string]ed25519.PublicKey{"policy-key-v1": pub}, now)
	if err == nil {
		t.Fatalf("activateStaged returned nil error, want fail-closed")
	}
	if !result.RolledBackToLKG {
		t.Fatalf("RolledBackToLKG = false, want true")
	}
	active, err := store.readActive("scan")
	if err != nil {
		t.Fatalf("readActive: %v", err)
	}
	if active.ManifestID != good.ManifestID {
		t.Fatalf("active manifest_id = %q, want restored %q", active.ManifestID, good.ManifestID)
	}
}

func policyActivationKeyPairContract(seedStart byte) (ed25519.PrivateKey, ed25519.PublicKey) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = seedStart + byte(i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return priv, priv.Public().(ed25519.PublicKey)
}

func signPolicyActivationBundleContract(t *testing.T, bundle signedPolicyBundle, priv ed25519.PrivateKey) signedPolicyBundle {
	t.Helper()
	signingBytes, err := policyBundleSigningBytes(bundle)
	if err != nil {
		t.Fatalf("policyBundleSigningBytes: %v", err)
	}
	bundle.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, signingBytes))
	return bundle
}

func TestPolicyActivationContract_NormalizeKindRejectsInvalid(t *testing.T) {
	if _, err := normalizePolicyStateKind(" "); err == nil {
		t.Fatalf("normalizePolicyStateKind(empty) returned nil error")
	}
	if _, err := normalizePolicyStateKind("../../escape"); err == nil {
		t.Fatalf("normalizePolicyStateKind(invalid) returned nil error")
	}
	if got, err := normalizePolicyStateKind("Extension"); err != nil || got != "extension" {
		t.Fatalf("normalizePolicyStateKind(Extension) = %q, %v; want extension, nil", got, err)
	}
}

func TestPolicyActivationContract_StageWritesStagedBundle(t *testing.T) {
	store := &policyActivationStore{stateDir: t.TempDir()}
	bundle := signedPolicyBundle{ManifestID: "pmf_test"}
	if err := store.stage("extension", bundle); err != nil {
		t.Fatalf("stage: %v", err)
	}
	if _, err := os.Stat(store.stagedPath("extension")); err != nil {
		t.Fatalf("staged file missing: %v", err)
	}
}
