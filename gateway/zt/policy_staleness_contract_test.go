package main

import (
	"errors"
	"testing"
	"time"
)

func TestPolicyStalenessContract_RegulatedFailClosedOnExpiry(t *testing.T) {
	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	degraded, err := evaluatePolicyStaleness(trustProfileRegulated, now.Add(-1*time.Hour), now)
	if err == nil {
		t.Fatalf("evaluatePolicyStaleness returned nil error, want fail-closed")
	}
	if degraded {
		t.Fatalf("degraded = true, want false")
	}
	var verr *policyBundleVerifyError
	if !errors.As(err, &verr) {
		t.Fatalf("error type = %T, want *policyBundleVerifyError", err)
	}
	if verr.ErrorCode != policyErrorCodeStale {
		t.Fatalf("error_code = %q, want %q", verr.ErrorCode, policyErrorCodeStale)
	}
}

func TestPolicyStalenessContract_InternalGraceThenFailClosed(t *testing.T) {
	t.Setenv("ZT_POLICY_STALE_GRACE_HOURS", "24")
	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	degraded, err := evaluatePolicyStaleness(trustProfileInternal, now.Add(-1*time.Hour), now)
	if err != nil {
		t.Fatalf("evaluatePolicyStaleness(grace) error: %v", err)
	}
	if !degraded {
		t.Fatalf("degraded = false, want true")
	}
	degraded, err = evaluatePolicyStaleness(trustProfileInternal, now.Add(-30*time.Hour), now)
	if err == nil {
		t.Fatalf("evaluatePolicyStaleness(after grace) returned nil error")
	}
	if degraded {
		t.Fatalf("degraded = true after grace, want false")
	}
}
