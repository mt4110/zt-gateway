package main

import "testing"

func TestClassifyVerifyPacketFailure_SignerPinMissing(t *testing.T) {
	code, reason, hints, meta := classifyVerifyPacketFailure("SECURE_PACK_ERROR_CODE=SP_SIGNER_PIN_MISSING\n", nil)
	if code != ztErrorCodeVerifySignerPinMissing {
		t.Fatalf("code = %q", code)
	}
	if reason != "policy_verify_signer_pin_missing" {
		t.Fatalf("reason = %q", reason)
	}
	if len(hints) == 0 {
		t.Fatalf("hints should not be empty")
	}
	if meta["secure_pack_error_code"] != "SP_SIGNER_PIN_MISSING" {
		t.Fatalf("meta.secure_pack_error_code = %v", meta["secure_pack_error_code"])
	}
}

func TestClassifyVerifyPacketFailure_SignerPinMismatchDetails(t *testing.T) {
	out := "SECURE_PACK_ERROR_CODE=SP_SIGNER_PIN_MISMATCH\npacket signer fingerprint mismatch: got ABC, allowed=DEF,GHI\n"
	code, reason, _, meta := classifyVerifyPacketFailure(out, nil)
	if code != ztErrorCodeVerifySignerPinMismatch {
		t.Fatalf("code = %q", code)
	}
	if reason != "policy_verify_signer_pin_mismatch" {
		t.Fatalf("reason = %q", reason)
	}
	if meta["actual_signer_fingerprint"] != "ABC" {
		t.Fatalf("actual_signer_fingerprint = %v", meta["actual_signer_fingerprint"])
	}
}

func TestClassifyVerifyPacketFailure_Default(t *testing.T) {
	code, reason, hints, _ := classifyVerifyPacketFailure("verify failed", nil)
	if code != ztErrorCodeVerifyPacketFailed {
		t.Fatalf("code = %q", code)
	}
	if reason != "policy_verify_failed" {
		t.Fatalf("reason = %q", reason)
	}
	if len(hints) != 0 {
		t.Fatalf("hints = %v, want empty", hints)
	}
}
