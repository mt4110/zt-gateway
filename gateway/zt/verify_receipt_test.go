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

func TestResolveReceiptKeyFingerprint(t *testing.T) {
	t.Setenv("ZT_RECEIPT_KEY_FINGERPRINT", "")
	t.Setenv("ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS", "0123 4567 89ab cdef 0123 4567 89ab cdef 0123 4567")
	got := resolveReceiptKeyFingerprint()
	want := "0123456789ABCDEF0123456789ABCDEF01234567"
	if got != want {
		t.Fatalf("resolveReceiptKeyFingerprint() = %q, want %q", got, want)
	}
}

func TestBuildAndWriteVerificationReceipt(t *testing.T) {
	tmp := t.TempDir()
	artifact := filepath.Join(tmp, "bundle_clientA_20260225T000000Z.spkg.tgz")
	if err := os.WriteFile(artifact, []byte("packet"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ZT_SECURE_PACK_VERSION", "v0.3.0-test")
	receipt := buildVerificationReceipt(artifact)

	if receipt.ReceiptVersion != "v1" {
		t.Fatalf("ReceiptVersion = %q, want v1", receipt.ReceiptVersion)
	}
	if receipt.Provenance.Client != "clientA" {
		t.Fatalf("Provenance.Client = %q, want clientA", receipt.Provenance.Client)
	}
	if receipt.Tooling.SecurePackVersion != "v0.3.0-test" {
		t.Fatalf("SecurePackVersion = %q", receipt.Tooling.SecurePackVersion)
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
}
