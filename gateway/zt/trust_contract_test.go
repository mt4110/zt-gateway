package main

import (
	"encoding/json"
	"testing"
)

func TestNewTrustStatusSuccess_DefaultReceipt(t *testing.T) {
	got := newTrustStatusSuccess("")
	if !got.Verified {
		t.Fatalf("Verified = false, want true")
	}
	if got.Receipt != "none" {
		t.Fatalf("Receipt = %q, want none", got.Receipt)
	}
	want := "TRUST: verified=true tamper=false policy=pass receipt=none"
	if got.Line != want {
		t.Fatalf("Line = %q, want %q", got.Line, want)
	}
}

func TestNewTrustStatusFailure_Reason(t *testing.T) {
	got := newTrustStatusFailure(ztErrorCodeSendPackFail)
	if got.Verified {
		t.Fatalf("Verified = true, want false")
	}
	if got.Reason != ztErrorCodeSendPackFail {
		t.Fatalf("Reason = %q", got.Reason)
	}
	want := "TRUST: verified=false tamper=unknown policy=fail reason=" + ztErrorCodeSendPackFail
	if got.Line != want {
		t.Fatalf("Line = %q, want %q", got.Line, want)
	}
}

func TestBuildQuickFixBundle_UsesRetryWhenNoFixes(t *testing.T) {
	got := buildQuickFixBundle("setup checks failed", nil, "zt setup --json")
	if got == nil {
		t.Fatalf("bundle = nil")
	}
	if len(got.Commands) != 1 || got.Commands[0] != "zt setup --json" {
		t.Fatalf("Commands = %#v", got.Commands)
	}
	if got.Runbook != "docs/OPERATIONS.md" {
		t.Fatalf("Runbook = %q", got.Runbook)
	}
}

func TestFailureEnvelope_Contract(t *testing.T) {
	bundle := buildQuickFixBundle("setup checks failed", []string{"zt setup --json", "zt setup --json", "zt sync --force"}, "zt setup --json")
	payload := struct {
		ErrorCode      string          `json:"error_code"`
		Summary        string          `json:"summary"`
		QuickFixBundle *quickFixBundle `json:"quick_fix_bundle,omitempty"`
	}{
		ErrorCode:      ztErrorCodeSetupChecksFailed,
		Summary:        "setup checks failed",
		QuickFixBundle: bundle,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal returned error: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}
	if got["error_code"] != ztErrorCodeSetupChecksFailed {
		t.Fatalf("error_code = %v", got["error_code"])
	}
	if got["summary"] != "setup checks failed" {
		t.Fatalf("summary = %v", got["summary"])
	}
	qfb, ok := got["quick_fix_bundle"].(map[string]any)
	if !ok {
		t.Fatalf("quick_fix_bundle missing or invalid: %#v", got["quick_fix_bundle"])
	}
	if qfb["why"] != "setup checks failed" {
		t.Fatalf("why = %v", qfb["why"])
	}
	if qfb["runbook"] != "docs/OPERATIONS.md" {
		t.Fatalf("runbook = %v", qfb["runbook"])
	}
	if qfb["retry"] != "zt setup --json" {
		t.Fatalf("retry = %v", qfb["retry"])
	}
	commands, ok := qfb["commands"].([]any)
	if !ok || len(commands) != 2 {
		t.Fatalf("commands = %#v, want deduped length 2", qfb["commands"])
	}
}
