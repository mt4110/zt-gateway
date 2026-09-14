package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestModelCapsuleArchiveRoundTrip(t *testing.T) {
	dir := t.TempDir()
	modelPath := filepath.Join(dir, "demo.gguf")
	if err := os.WriteFile(modelPath, []byte("GGUFdemo"), 0644); err != nil {
		t.Fatal(err)
	}
	payloadPath := filepath.Join(dir, "payload.spkg.tgz")
	if err := os.WriteFile(payloadPath, []byte("signed-payload"), 0600); err != nil {
		t.Fatal(err)
	}

	manifest, err := buildModelCapsuleManifest(buildModelManifestInput{
		ModelPath: modelPath,
		Name:      "demo",
		Version:   "0.1",
		Format:    "gguf",
		ClientID:  "edge-a",
		TenantID:  "tenant-a",
		Profile:   trustProfileConfidential,
		CreatedAt: time.Date(2026, 5, 26, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("build manifest: %v", err)
	}
	payloadSHA, err := fileSHA256Hex(payloadPath)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Provenance.SecurePackSHA256 = payloadSHA

	capsulePath := filepath.Join(dir, "demo.zmc")
	info, err := writeModelCapsuleArchive(capsulePath, manifest, payloadPath)
	if err != nil {
		t.Fatalf("writeModelCapsuleArchive: %v", err)
	}
	if info.CapsuleSHA256 == "" || info.ManifestSHA256 == "" || info.PayloadSHA256 != payloadSHA {
		t.Fatalf("unexpected archive info: %+v", info)
	}

	readDir := filepath.Join(dir, "read")
	if err := os.Mkdir(readDir, 0700); err != nil {
		t.Fatal(err)
	}
	got, err := readModelCapsuleArchive(capsulePath, readDir)
	if err != nil {
		t.Fatalf("readModelCapsuleArchive: %v", err)
	}
	if got.Manifest.CapsuleID != manifest.CapsuleID {
		t.Fatalf("capsule_id=%q, want %q", got.Manifest.CapsuleID, manifest.CapsuleID)
	}
	if got.Info.PayloadSHA256 != payloadSHA {
		t.Fatalf("payload sha=%q, want %q", got.Info.PayloadSHA256, payloadSHA)
	}
	if _, err := os.Stat(got.Payload); err != nil {
		t.Fatalf("payload not extracted: %v", err)
	}
}

func TestModelCapsuleSignedMetadataAllowsOuterPayloadSHA(t *testing.T) {
	manifest := testRuntimePermitManifest(t)
	manifest.Provenance.SecurePackSHA256 = strings.Repeat("1", 64)
	extractedRoot := writeSignedModelCapsuleMetadata(t, manifest, manifest.Policy)

	if err := validateModelCapsuleSignedMetadata(modelCapsuleReadResult{Manifest: manifest, Policy: manifest.Policy}, extractedRoot); err != nil {
		t.Fatalf("validateModelCapsuleSignedMetadata: %v", err)
	}
}

func TestModelCapsuleSignedMetadataRejectsOuterManifestTamper(t *testing.T) {
	signedManifest := testRuntimePermitManifest(t)
	outerManifest := signedManifest
	outerManifest.Provenance.SecurePackSHA256 = strings.Repeat("1", 64)
	outerManifest.Distribution.TenantID = "tenant-b"
	extractedRoot := writeSignedModelCapsuleMetadata(t, signedManifest, signedManifest.Policy)

	err := validateModelCapsuleSignedMetadata(modelCapsuleReadResult{Manifest: outerManifest, Policy: outerManifest.Policy}, extractedRoot)
	if err == nil || !strings.Contains(err.Error(), "signed manifest does not match") {
		t.Fatalf("err=%v, want signed manifest mismatch", err)
	}
}

func TestModelCapsuleSignedMetadataRejectsPolicyTamper(t *testing.T) {
	manifest := testRuntimePermitManifest(t)
	manifest.Provenance.SecurePackSHA256 = strings.Repeat("1", 64)
	signedPolicy := manifest.Policy
	signedPolicy.AllowedRuntimes = []string{"ollama"}
	extractedRoot := writeSignedModelCapsuleMetadata(t, manifest, signedPolicy)

	err := validateModelCapsuleSignedMetadata(modelCapsuleReadResult{Manifest: manifest, Policy: manifest.Policy}, extractedRoot)
	if err == nil || !strings.Contains(err.Error(), "signed policy.json does not match") {
		t.Fatalf("err=%v, want signed policy mismatch", err)
	}
}

func TestModelCapsuleSignedMetadataRejectsArtifactTamper(t *testing.T) {
	manifest := testRuntimePermitManifest(t)
	manifest.Provenance.SecurePackSHA256 = strings.Repeat("1", 64)
	extractedRoot := writeSignedModelCapsuleMetadata(t, manifest, manifest.Policy, []byte("tampered-model"))

	err := validateModelCapsuleSignedMetadata(modelCapsuleReadResult{Manifest: manifest, Policy: manifest.Policy}, extractedRoot)
	if err == nil || !strings.Contains(err.Error(), "signed artifact[0]") || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("err=%v, want signed artifact sha mismatch", err)
	}
}

func TestModelCapsuleSignedMetadataRequiresSignedProvenanceFiles(t *testing.T) {
	manifest := testRuntimePermitManifest(t)
	manifest.Provenance.SecurePackSHA256 = strings.Repeat("1", 64)
	manifest.Policy.Scan = &modelPolicyScanRequirements{RequireSignedProvenance: true}
	slsaBytes := []byte(`{"predicateType":"https://slsa.dev/provenance/v1"}`)
	omsBytes := []byte("signed-by-oms")
	manifest.Provenance.SLSAProvenanceSHA256 = sha256HexBytes(slsaBytes)
	manifest.Provenance.OMSSignatureSHA256 = sha256HexBytes(omsBytes)
	extractedRoot := writeSignedModelCapsuleMetadata(t, manifest, manifest.Policy)

	err := validateModelCapsuleSignedMetadata(modelCapsuleReadResult{Manifest: manifest, Policy: manifest.Policy}, extractedRoot)
	if err == nil || !strings.Contains(err.Error(), "signed slsa provenance is missing") {
		t.Fatalf("err=%v, want missing signed provenance", err)
	}
}

func TestModelCapsuleSignedMetadataRejectsSignedProvenanceTamper(t *testing.T) {
	manifest := testRuntimePermitManifest(t)
	manifest.Provenance.SecurePackSHA256 = strings.Repeat("1", 64)
	manifest.Policy.Scan = &modelPolicyScanRequirements{RequireSignedProvenance: true}
	slsaBytes := []byte(`{"predicateType":"https://slsa.dev/provenance/v1"}`)
	omsBytes := []byte("signed-by-oms")
	manifest.Provenance.SLSAProvenanceSHA256 = sha256HexBytes(slsaBytes)
	manifest.Provenance.OMSSignatureSHA256 = sha256HexBytes(omsBytes)
	extractedRoot := writeSignedModelCapsuleMetadata(t, manifest, manifest.Policy, nil, []byte("tampered-slsa"), omsBytes)

	err := validateModelCapsuleSignedMetadata(modelCapsuleReadResult{Manifest: manifest, Policy: manifest.Policy}, extractedRoot)
	if err == nil || !strings.Contains(err.Error(), "signed slsa provenance sha256 mismatch") {
		t.Fatalf("err=%v, want signed provenance sha mismatch", err)
	}
}

func TestModelCapsuleSignedMetadataAcceptsSignedProvenanceFiles(t *testing.T) {
	manifest := testRuntimePermitManifest(t)
	manifest.Provenance.SecurePackSHA256 = strings.Repeat("1", 64)
	manifest.Policy.Scan = &modelPolicyScanRequirements{RequireSignedProvenance: true}
	slsaBytes := []byte(`{"predicateType":"https://slsa.dev/provenance/v1"}`)
	omsBytes := []byte("signed-by-oms")
	manifest.Provenance.SLSAProvenanceSHA256 = sha256HexBytes(slsaBytes)
	manifest.Provenance.OMSSignatureSHA256 = sha256HexBytes(omsBytes)
	extractedRoot := writeSignedModelCapsuleMetadata(t, manifest, manifest.Policy, nil, slsaBytes, omsBytes)

	if err := validateModelCapsuleSignedMetadata(modelCapsuleReadResult{Manifest: manifest, Policy: manifest.Policy}, extractedRoot); err != nil {
		t.Fatalf("validateModelCapsuleSignedMetadata: %v", err)
	}
}

func writeSignedModelCapsuleMetadata(t *testing.T, manifest modelCapsuleManifestV1, policy modelPolicyV1, artifactBytes ...[]byte) string {
	t.Helper()
	root := t.TempDir()
	docsDir := filepath.Join(root, "docs")
	if err := os.MkdirAll(docsDir, 0700); err != nil {
		t.Fatal(err)
	}
	signedManifest := manifest
	signedManifest.Provenance.SecurePackSHA256 = ""
	manifestJSON, err := marshalModelJSON(signedManifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(docsDir, modelCapsuleManifestName), manifestJSON, 0600); err != nil {
		t.Fatal(err)
	}
	policyJSON, err := marshalModelJSON(policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(docsDir, modelCapsulePolicyName), policyJSON, 0600); err != nil {
		t.Fatal(err)
	}
	modelBytes := []byte("GGUFdemo")
	if len(artifactBytes) > 0 && artifactBytes[0] != nil {
		modelBytes = artifactBytes[0]
	}
	for _, artifact := range manifest.Artifacts {
		if err := os.WriteFile(filepath.Join(docsDir, artifact.Path), modelBytes, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if len(artifactBytes) > 1 && artifactBytes[1] != nil {
		provenanceDir := filepath.Join(docsDir, modelCapsuleProvenanceDir)
		if err := os.MkdirAll(provenanceDir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(provenanceDir, modelCapsuleSLSAProvenanceName), artifactBytes[1], 0600); err != nil {
			t.Fatal(err)
		}
	}
	if len(artifactBytes) > 2 && artifactBytes[2] != nil {
		signaturesDir := filepath.Join(docsDir, modelCapsuleSignaturesDir)
		if err := os.MkdirAll(signaturesDir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(signaturesDir, modelCapsuleOMSSignatureName), artifactBytes[2], 0600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}
