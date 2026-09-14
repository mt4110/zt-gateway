package main

import (
	"strings"
	"testing"
)

func TestParseModelPackArgsAllowsPathBeforeFlags(t *testing.T) {
	opts, err := parseModelPackArgs([]string{
		"demo.gguf",
		"--name", "demo",
		"--version", "1.0",
		"--format", "gguf",
		"--client", "edge-a",
		"--slsa-provenance", "slsa.provenance.json",
		"--oms-signature", "oms.sig",
		"--runtime", "llama.cpp",
	})
	if err != nil {
		t.Fatalf("parseModelPackArgs: %v", err)
	}
	if opts.ModelPath != "demo.gguf" || opts.Name != "demo" || opts.Client != "edge-a" {
		t.Fatalf("unexpected opts: %+v", opts)
	}
	if opts.SLSAProvenance != "slsa.provenance.json" || opts.OMSSignature != "oms.sig" {
		t.Fatalf("unexpected provenance opts: %+v", opts)
	}
}

func TestParseModelVerifyArgsAllowsPathBeforeFlags(t *testing.T) {
	opts, err := parseModelVerifyArgs([]string{"demo.zmc", "--receipt-out", "receipt.json"})
	if err != nil {
		t.Fatalf("parseModelVerifyArgs: %v", err)
	}
	if opts.CapsulePath != "demo.zmc" || opts.ReceiptOut != "receipt.json" {
		t.Fatalf("unexpected opts: %+v", opts)
	}
}

func TestEnforceModelScanPolicyRejectsDeniedFormat(t *testing.T) {
	err := enforceModelScanPolicy(ScanResult{
		Result:      "warn",
		Reason:      "model.pickle_rce_warn",
		ModelFormat: "pt",
	}, modelPolicyV1{
		Formats: &modelPolicyFormatRules{Deny: []string{"pt"}},
	}, "pt")
	if err == nil || !strings.Contains(err.Error(), "policy.formats.deny") {
		t.Fatalf("err=%v, want policy format deny", err)
	}
}

func TestEnforceModelScanPolicyRejectsSecretFindingWhenRequired(t *testing.T) {
	err := enforceModelScanPolicy(ScanResult{
		Result:      "warn",
		Reason:      "model.secret_detected",
		ModelFormat: "gguf",
		Findings:    []ScanFinding{{Category: "secret"}},
	}, modelPolicyV1{
		Scan: &modelPolicyScanRequirements{DenySecretPatterns: true},
	}, "gguf")
	if err == nil || !strings.Contains(err.Error(), "deny_secret_patterns") {
		t.Fatalf("err=%v, want secret policy deny", err)
	}
}

func TestEnforceModelScanPolicyRejectsPickleFindingWhenRequired(t *testing.T) {
	err := enforceModelScanPolicy(ScanResult{
		Result:      "warn",
		Reason:      "model.pickle_rce_warn",
		ModelFormat: "pt",
		Findings:    []ScanFinding{{Category: "unsafe_serialization"}},
	}, modelPolicyV1{
		Scan: &modelPolicyScanRequirements{DenyPickleSerialization: true},
	}, "pt")
	if err == nil || !strings.Contains(err.Error(), "deny_pickle_serialization") {
		t.Fatalf("err=%v, want pickle policy deny", err)
	}
}
