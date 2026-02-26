package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInferReceiptClient(t *testing.T) {
	if got := inferReceiptClient("bundle_clientA_20260225T000000Z.spkg.tgz"); got != "clientA" {
		t.Fatalf("inferReceiptClient() = %q, want clientA", got)
	}
	if got := inferReceiptClient("random.spkg.tgz"); got != "unknown" {
		t.Fatalf("inferReceiptClient(non-match) = %q, want unknown", got)
	}
}

func TestExtractVerifiedSignerFingerprint(t *testing.T) {
	in := "SIGNER_FINGERPRINT=0123456789ABCDEF0123456789ABCDEF01234567\nOK: Signature and checksum verified.\n"
	got, err := extractVerifiedSignerFingerprint(in)
	if err != nil {
		t.Fatalf("extractVerifiedSignerFingerprint() error = %v", err)
	}
	want := "0123456789ABCDEF0123456789ABCDEF01234567"
	if got != want {
		t.Fatalf("extractVerifiedSignerFingerprint() = %q, want %q", got, want)
	}
}

func TestExtractVerifiedSignerFingerprint_MissingFails(t *testing.T) {
	_, err := extractVerifiedSignerFingerprint("OK: Signature and checksum verified.\n")
	if err == nil {
		t.Fatalf("expected error when SIGNER_FINGERPRINT is missing")
	}
}

func TestBuildAndWriteVerificationReceipt(t *testing.T) {
	tmp := t.TempDir()
	artifact := filepath.Join(tmp, "bundle_clientA_20260225T000000Z.spkg.tgz")
	if err := os.WriteFile(artifact, []byte("packet"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ZT_SECURE_PACK_VERSION", "v0.3.0-test")
	receipt, err := buildVerificationReceipt(artifact, decisionForVerify(true, "policy_verify_pass"), "0123456789ABCDEF0123456789ABCDEF01234567")
	if err != nil {
		t.Fatalf("buildVerificationReceipt returned error: %v", err)
	}

	if receipt.ReceiptVersion != "v1" {
		t.Fatalf("ReceiptVersion = %q, want v1", receipt.ReceiptVersion)
	}
	if receipt.Provenance.Client != "clientA" {
		t.Fatalf("Provenance.Client = %q, want clientA", receipt.Provenance.Client)
	}
	if receipt.Tooling.SecurePackVersion != "v0.3.0-test" {
		t.Fatalf("SecurePackVersion = %q", receipt.Tooling.SecurePackVersion)
	}
	if receipt.Provenance.KeyFingerprint != "0123456789ABCDEF0123456789ABCDEF01234567" {
		t.Fatalf("Provenance.KeyFingerprint = %q", receipt.Provenance.KeyFingerprint)
	}
	if len(receipt.ReceiptID) != 32 {
		t.Fatalf("ReceiptID len = %d, want 32", len(receipt.ReceiptID))
	}

	outPath := filepath.Join(tmp, "receipts", "verify.json")
	if err := writeVerificationReceipt(outPath, receipt); err != nil {
		t.Fatalf("writeVerificationReceipt returned error: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	if !strings.Contains(string(data), "\n") {
		t.Fatalf("receipt JSON should be indented: %q", string(data))
	}
	var got verificationReceipt
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}
	if got.Artifact.Path != artifact {
		t.Fatalf("Artifact.Path = %q, want %q", got.Artifact.Path, artifact)
	}
	if got.Verification.PolicyResult != "pass" {
		t.Fatalf("Verification.PolicyResult = %q", got.Verification.PolicyResult)
	}
	if got.Verification.PolicyDecision.Decision != policyDecisionAllow {
		t.Fatalf("Verification.PolicyDecision.Decision = %q", got.Verification.PolicyDecision.Decision)
	}
}

func TestVerificationReceipt_JSONContractV1(t *testing.T) {
	tmp := t.TempDir()
	artifact := filepath.Join(tmp, "bundle_clientA_20260225T000000Z.spkg.tgz")
	if err := os.WriteFile(artifact, []byte("packet"), 0o644); err != nil {
		t.Fatal(err)
	}
	receipt, err := buildVerificationReceipt(artifact, decisionForVerify(true, "policy_verify_pass"), "0123456789ABCDEF0123456789ABCDEF01234567")
	if err != nil {
		t.Fatalf("buildVerificationReceipt returned error: %v", err)
	}
	data, err := json.Marshal(receipt)
	if err != nil {
		t.Fatalf("json.Marshal returned error: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}
	if got["receipt_version"] != "v1" {
		t.Fatalf("receipt_version = %v", got["receipt_version"])
	}
	requiredTopLevel := []string{"receipt_id", "verified_at", "artifact", "verification", "provenance", "tooling"}
	for _, k := range requiredTopLevel {
		if _, ok := got[k]; !ok {
			t.Fatalf("missing top-level key: %s", k)
		}
	}
	artifactMap, ok := got["artifact"].(map[string]any)
	if !ok {
		t.Fatalf("artifact is invalid: %#v", got["artifact"])
	}
	if artifactMap["path"] != artifact {
		t.Fatalf("artifact.path = %v, want %s", artifactMap["path"], artifact)
	}
	verificationMap, ok := got["verification"].(map[string]any)
	if !ok {
		t.Fatalf("verification is invalid: %#v", got["verification"])
	}
	if verificationMap["policy_result"] != "pass" {
		t.Fatalf("verification.policy_result = %v", verificationMap["policy_result"])
	}
	if _, ok := verificationMap["policy_decision"]; !ok {
		t.Fatalf("verification.policy_decision is missing")
	}
}

func TestBuildVerificationReceipt_BoundaryMetadata(t *testing.T) {
	tmp := t.TempDir()
	artifact := filepath.Join(tmp, "bundle_clientA_20260225T000000Z.spkg.tgz")
	if err := os.WriteFile(artifact, []byte("packet"), 0o644); err != nil {
		t.Fatal(err)
	}
	setActiveTeamBoundaryContext(&teamBoundaryRuntimeContext{
		TenantID:              "corp-example",
		TeamID:                "secops",
		BoundaryPolicyVersion: "2026-02-26",
		BreakGlass:            true,
		BreakGlassReason:      "incident-9204",
	})
	defer setActiveTeamBoundaryContext(nil)

	receipt, err := buildVerificationReceipt(artifact, decisionForVerify(true, "policy_verify_pass"), "0123456789ABCDEF0123456789ABCDEF01234567")
	if err != nil {
		t.Fatalf("buildVerificationReceipt returned error: %v", err)
	}
	if receipt.Provenance.TenantID != "corp-example" {
		t.Fatalf("tenant_id = %q", receipt.Provenance.TenantID)
	}
	if receipt.Provenance.TeamID != "secops" {
		t.Fatalf("team_id = %q", receipt.Provenance.TeamID)
	}
	if receipt.Provenance.BoundaryPolicyVersion != "2026-02-26" {
		t.Fatalf("boundary_policy_version = %q", receipt.Provenance.BoundaryPolicyVersion)
	}
	if !receipt.Provenance.BreakGlass {
		t.Fatalf("break_glass = false, want true")
	}
}
