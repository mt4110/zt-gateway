package main

import "testing"

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
