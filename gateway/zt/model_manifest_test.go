package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBuildModelCapsuleManifestV1(t *testing.T) {
	dir := t.TempDir()
	modelPath := filepath.Join(dir, "demo.gguf")
	if err := os.WriteFile(modelPath, []byte("GGUFdemo"), 0644); err != nil {
		t.Fatal(err)
	}

	manifest, err := buildModelCapsuleManifest(buildModelManifestInput{
		ModelPath: modelPath,
		Name:      "internal-llm",
		Version:   "1.0",
		Format:    "gguf",
		ClientID:  "edge-a",
		TenantID:  "tenant-a",
		Profile:   trustProfileConfidential,
		Runtimes:  []string{"llama.cpp", "llama.cpp", "ollama"},
		CreatedAt: time.Date(2026, 5, 26, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("buildModelCapsuleManifest: %v", err)
	}
	if manifest.SchemaVersion != modelCapsuleManifestSchemaV1 {
		t.Fatalf("schema_version=%q", manifest.SchemaVersion)
	}
	if !strings.HasPrefix(manifest.CapsuleID, "zmc_") {
		t.Fatalf("capsule_id=%q, want zmc_ prefix", manifest.CapsuleID)
	}
	if !strings.HasPrefix(manifest.Model.ModelID, "mdl_") {
		t.Fatalf("model_id=%q, want mdl_ prefix", manifest.Model.ModelID)
	}
	if manifest.Model.DeclaredSizeBytes != int64(len("GGUFdemo")) {
		t.Fatalf("declared size=%d", manifest.Model.DeclaredSizeBytes)
	}
	if got := len(manifest.Policy.AllowedRuntimes); got != 2 {
		t.Fatalf("allowed runtimes len=%d, want 2", got)
	}
	if err := validateModelCapsuleManifest(manifest); err != nil {
		t.Fatalf("validateModelCapsuleManifest: %v", err)
	}
}

func TestBuildModelCapsuleManifestDefaultsToPolicyRuntime(t *testing.T) {
	dir := t.TempDir()
	modelPath := filepath.Join(dir, "demo.gguf")
	if err := os.WriteFile(modelPath, []byte("GGUFdemo"), 0644); err != nil {
		t.Fatal(err)
	}
	manifest, err := buildModelCapsuleManifest(buildModelManifestInput{
		ModelPath: modelPath,
		Name:      "demo",
		Version:   "1.0",
		Format:    "gguf",
		ClientID:  "edge-a",
		TenantID:  "tenant-a",
		Profile:   trustProfileConfidential,
		CreatedAt: time.Date(2026, 5, 26, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("buildModelCapsuleManifest: %v", err)
	}
	if !modelPolicyAllowsRuntime(manifest.Policy, defaultModelRuntimeName) {
		t.Fatalf("default allowed runtimes=%v, want %s", manifest.Policy.AllowedRuntimes, defaultModelRuntimeName)
	}
	if len(manifest.Policy.AllowedRuntimes) != 1 {
		t.Fatalf("default allowed runtimes=%v, want only %s", manifest.Policy.AllowedRuntimes, defaultModelRuntimeName)
	}
}

func TestBuildModelCapsuleManifestLoadsProfileModelPolicy(t *testing.T) {
	repoRoot := t.TempDir()
	writeTestModelPolicy(t, repoRoot, trustProfileRegulated, `
profile = "regulated"
allowed_runtimes = ["llama.cpp"]
offline_lease_seconds = 43200
require_kernel_shield = true
require_attestation = true

[scan]
require_signed_provenance = true
`)
	modelPath := filepath.Join(repoRoot, "demo.gguf")
	if err := os.WriteFile(modelPath, []byte("GGUFdemo"), 0644); err != nil {
		t.Fatal(err)
	}
	slsaPath := filepath.Join(repoRoot, "slsa.provenance.json")
	if err := os.WriteFile(slsaPath, []byte(`{"predicateType":"https://slsa.dev/provenance/v1"}`), 0644); err != nil {
		t.Fatal(err)
	}
	omsPath := filepath.Join(repoRoot, "oms.sig")
	if err := os.WriteFile(omsPath, []byte("signed-by-oms"), 0644); err != nil {
		t.Fatal(err)
	}
	manifest, err := buildModelCapsuleManifest(buildModelManifestInput{
		ModelPath:          modelPath,
		Name:               "demo",
		Version:            "1.0",
		Format:             "gguf",
		ClientID:           "edge-a",
		TenantID:           "tenant-a",
		Profile:            trustProfileRegulated,
		RepoRoot:           repoRoot,
		CreatedAt:          time.Date(2026, 5, 26, 0, 0, 0, 0, time.UTC),
		SLSAProvenancePath: slsaPath,
		OMSSignaturePath:   omsPath,
	})
	if err != nil {
		t.Fatalf("buildModelCapsuleManifest: %v", err)
	}
	if manifest.Policy.OfflineLeaseSeconds != 43200 {
		t.Fatalf("offline_lease_seconds=%d, want 43200", manifest.Policy.OfflineLeaseSeconds)
	}
	if !manifest.Policy.RequireKernelShield || !manifest.Policy.RequireAttestation {
		t.Fatalf("profile policy flags not loaded: %+v", manifest.Policy)
	}
	if len(manifest.Policy.AllowedRuntimes) != 1 || manifest.Policy.AllowedRuntimes[0] != "llama.cpp" {
		t.Fatalf("allowed_runtimes=%v, want [llama.cpp]", manifest.Policy.AllowedRuntimes)
	}
	if manifest.Policy.Scan == nil || !manifest.Policy.Scan.RequireSignedProvenance {
		t.Fatalf("scan policy not loaded: %+v", manifest.Policy.Scan)
	}
	wantSLSA, err := fileSHA256Hex(slsaPath)
	if err != nil {
		t.Fatal(err)
	}
	wantOMS, err := fileSHA256Hex(omsPath)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Provenance.SLSAProvenanceSHA256 != wantSLSA || manifest.Provenance.OMSSignatureSHA256 != wantOMS {
		t.Fatalf("signed provenance hashes=%+v, want slsa=%s oms=%s", manifest.Provenance, wantSLSA, wantOMS)
	}
}

func TestBuildModelCapsuleManifestRejectsMissingRequiredSignedProvenance(t *testing.T) {
	repoRoot := t.TempDir()
	writeTestModelPolicy(t, repoRoot, trustProfileRegulated, `
profile = "regulated"
allowed_runtimes = ["llama.cpp"]
offline_lease_seconds = 43200
require_kernel_shield = false
require_attestation = false

[scan]
require_signed_provenance = true
`)
	modelPath := filepath.Join(repoRoot, "demo.gguf")
	if err := os.WriteFile(modelPath, []byte("GGUFdemo"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := buildModelCapsuleManifest(buildModelManifestInput{
		ModelPath: modelPath,
		Name:      "demo",
		Version:   "1.0",
		Format:    "gguf",
		ClientID:  "edge-a",
		TenantID:  "tenant-a",
		Profile:   trustProfileRegulated,
		RepoRoot:  repoRoot,
		CreatedAt: time.Date(2026, 5, 26, 0, 0, 0, 0, time.UTC),
	})
	if err == nil || !strings.Contains(err.Error(), "require_signed_provenance") {
		t.Fatalf("err=%v, want signed provenance requirement", err)
	}
}

func TestBuildModelCapsuleManifestLoadsPublicModelPolicy(t *testing.T) {
	repoRoot := t.TempDir()
	writeTestModelPolicy(t, repoRoot, trustProfilePublic, `
profile = "public"
allowed_runtimes = ["llama.cpp"]
offline_lease_seconds = 86400
require_kernel_shield = false
require_attestation = false
`)
	modelPath := filepath.Join(repoRoot, "demo.gguf")
	if err := os.WriteFile(modelPath, []byte("GGUFdemo"), 0644); err != nil {
		t.Fatal(err)
	}
	manifest, err := buildModelCapsuleManifest(buildModelManifestInput{
		ModelPath: modelPath,
		Name:      "demo",
		Version:   "1.0",
		Format:    "gguf",
		ClientID:  "edge-a",
		TenantID:  "tenant-a",
		Profile:   trustProfilePublic,
		RepoRoot:  repoRoot,
		CreatedAt: time.Date(2026, 5, 26, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("buildModelCapsuleManifest: %v", err)
	}
	if manifest.Policy.Profile != trustProfilePublic {
		t.Fatalf("profile=%q, want public", manifest.Policy.Profile)
	}
	if len(manifest.Policy.AllowedRuntimes) != 1 || manifest.Policy.AllowedRuntimes[0] != defaultModelRuntimeName {
		t.Fatalf("allowed_runtimes=%v, want [%s]", manifest.Policy.AllowedRuntimes, defaultModelRuntimeName)
	}
}

func TestBuildModelCapsuleManifestLoadsModelPolicyFormatRules(t *testing.T) {
	repoRoot := t.TempDir()
	writeTestModelPolicy(t, repoRoot, trustProfileInternal, `
profile = "internal"
allowed_runtimes = ["llama.cpp"]
offline_lease_seconds = 86400
require_kernel_shield = false
require_attestation = false

[formats]
allow = ["gguf", "safetensors"]
warn = ["onnx"]
deny = ["pt", "pth", "bin"]
`)
	modelPath := filepath.Join(repoRoot, "demo.gguf")
	if err := os.WriteFile(modelPath, []byte("GGUFdemo"), 0644); err != nil {
		t.Fatal(err)
	}
	manifest, err := buildModelCapsuleManifest(buildModelManifestInput{
		ModelPath: modelPath,
		Name:      "demo",
		Version:   "1.0",
		Format:    "gguf",
		ClientID:  "edge-a",
		TenantID:  "tenant-a",
		Profile:   trustProfileInternal,
		RepoRoot:  repoRoot,
		CreatedAt: time.Date(2026, 5, 26, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("buildModelCapsuleManifest: %v", err)
	}
	if manifest.Policy.Formats == nil {
		t.Fatalf("formats policy not loaded")
	}
	if !stringListContainsNormalizedFormat(manifest.Policy.Formats.Deny, "pt") {
		t.Fatalf("deny formats=%v, want pt", manifest.Policy.Formats.Deny)
	}
	if !stringListContainsNormalizedFormat(manifest.Policy.Formats.Warn, "onnx") {
		t.Fatalf("warn formats=%v, want onnx", manifest.Policy.Formats.Warn)
	}
}

func TestBuildModelCapsuleManifestRejectsRuntimeOutsideProfilePolicy(t *testing.T) {
	repoRoot := t.TempDir()
	writeTestModelPolicy(t, repoRoot, trustProfileRegulated, `
profile = "regulated"
allowed_runtimes = ["llama.cpp"]
offline_lease_seconds = 43200
require_kernel_shield = false
require_attestation = false
`)
	modelPath := filepath.Join(repoRoot, "demo.gguf")
	if err := os.WriteFile(modelPath, []byte("GGUFdemo"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := buildModelCapsuleManifest(buildModelManifestInput{
		ModelPath: modelPath,
		Name:      "demo",
		Version:   "1.0",
		Format:    "gguf",
		ClientID:  "edge-a",
		TenantID:  "tenant-a",
		Profile:   trustProfileRegulated,
		Runtimes:  []string{"fake"},
		RepoRoot:  repoRoot,
		CreatedAt: time.Date(2026, 5, 26, 0, 0, 0, 0, time.UTC),
	})
	if err == nil || !strings.Contains(err.Error(), "not allowed by model policy") {
		t.Fatalf("err=%v, want runtime policy deny", err)
	}
}

func TestBuildModelCapsuleManifestFailsClosedOnMissingProfileModelPolicy(t *testing.T) {
	repoRoot := t.TempDir()
	modelPath := filepath.Join(repoRoot, "demo.gguf")
	if err := os.WriteFile(modelPath, []byte("GGUFdemo"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := buildModelCapsuleManifest(buildModelManifestInput{
		ModelPath: modelPath,
		Name:      "demo",
		Version:   "1.0",
		Format:    "gguf",
		ClientID:  "edge-a",
		TenantID:  "tenant-a",
		Profile:   trustProfileRegulated,
		RepoRoot:  repoRoot,
		CreatedAt: time.Date(2026, 5, 26, 0, 0, 0, 0, time.UTC),
	})
	if err == nil || !strings.Contains(err.Error(), "model policy file is missing") {
		t.Fatalf("err=%v, want missing model policy error", err)
	}
}

func TestBuildModelCapsuleManifestRejectsReservedArtifactName(t *testing.T) {
	dir := t.TempDir()
	modelPath := filepath.Join(dir, modelCapsuleManifestName)
	if err := os.WriteFile(modelPath, []byte("GGUFdemo"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := buildModelCapsuleManifest(buildModelManifestInput{
		ModelPath: modelPath,
		Name:      "demo",
		Version:   "1.0",
		Format:    "gguf",
		ClientID:  "edge-a",
		TenantID:  "tenant-a",
		Profile:   trustProfileConfidential,
		CreatedAt: time.Date(2026, 5, 26, 0, 0, 0, 0, time.UTC),
	})
	if err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("err=%v, want reserved artifact filename", err)
	}
}

func TestValidateModelCapsuleManifestFailClosed(t *testing.T) {
	m := modelCapsuleManifestV1{
		SchemaVersion: modelCapsuleManifestSchemaV1,
		CapsuleID:     "zmc_demo",
		Model: modelManifestModel{
			ModelID:           "mdl_demo",
			Name:              "demo",
			Version:           "1",
			Format:            "gguf",
			DeclaredSizeBytes: 4,
		},
		Artifacts: []modelManifestArtifact{{
			Path:      "../model.gguf",
			Kind:      modelArtifactKindWeight,
			SHA256:    strings.Repeat("a", 64),
			SizeBytes: 4,
		}},
		Policy: modelPolicyV1{
			SchemaVersion:       modelPolicySchemaV1,
			Profile:             trustProfileConfidential,
			AllowedRuntimes:     []string{"llama.cpp"},
			OfflineLeaseSeconds: 1,
		},
		Distribution: modelManifestDistribution{
			TenantID:  "tenant-a",
			ClientID:  "edge-a",
			CreatedAt: "2026-05-26T00:00:00Z",
		},
	}
	if err := validateModelCapsuleManifest(m); err == nil {
		t.Fatalf("validateModelCapsuleManifest accepted path traversal artifact")
	}
}

func TestValidateModelCapsuleManifestRejectsNonFileArtifactNames(t *testing.T) {
	for _, path := range []string{".", "./model.gguf", modelCapsuleManifestName, modelCapsulePolicyName, "scan_result.json", modelCapsuleProvenanceDir, modelCapsuleSignaturesDir} {
		m := validTestModelCapsuleManifest()
		m.Artifacts[0].Path = path
		if err := validateModelCapsuleManifest(m); err == nil {
			t.Fatalf("validateModelCapsuleManifest accepted artifact path %q", path)
		}
	}
}

func TestValidateSHA256StringMessageMatchesNormalization(t *testing.T) {
	if err := validateSHA256String(strings.ToUpper(strings.Repeat("a", 64))); err != nil {
		t.Fatalf("uppercase sha should be normalized: %v", err)
	}
	err := validateSHA256String(strings.Repeat("g", 64))
	if err == nil || !strings.Contains(err.Error(), "must be hex") {
		t.Fatalf("err=%v, want hex message", err)
	}
}

func validTestModelCapsuleManifest() modelCapsuleManifestV1 {
	return modelCapsuleManifestV1{
		SchemaVersion: modelCapsuleManifestSchemaV1,
		CapsuleID:     "zmc_demo",
		Model: modelManifestModel{
			ModelID:           "mdl_demo",
			Name:              "demo",
			Version:           "1",
			Format:            "gguf",
			DeclaredSizeBytes: 4,
		},
		Artifacts: []modelManifestArtifact{{
			Path:      "model.gguf",
			Kind:      modelArtifactKindWeight,
			SHA256:    strings.Repeat("a", 64),
			SizeBytes: 4,
		}},
		Policy: modelPolicyV1{
			SchemaVersion:       modelPolicySchemaV1,
			Profile:             trustProfileConfidential,
			AllowedRuntimes:     []string{"llama.cpp"},
			OfflineLeaseSeconds: 1,
		},
		Distribution: modelManifestDistribution{
			TenantID:  "tenant-a",
			ClientID:  "edge-a",
			CreatedAt: "2026-05-26T00:00:00Z",
		},
	}
}

func writeTestModelPolicy(t *testing.T, repoRoot, profile, content string) {
	t.Helper()
	var dir string
	if profile == trustProfileInternal {
		dir = filepath.Join(repoRoot, "policy")
	} else {
		dir = filepath.Join(repoRoot, "policy", "profiles", profile)
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "model_policy.toml"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}
