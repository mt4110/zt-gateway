package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuildAuditTrailSetupCheck_OK(t *testing.T) {
	repoRoot := t.TempDir()
	check, fixes := buildAuditTrailSetupCheck(repoRoot)
	if check.Status != "ok" {
		t.Fatalf("status = %q, want ok (check=%+v)", check.Status, check)
	}
	if check.Code != "" {
		t.Fatalf("code = %q, want empty", check.Code)
	}
	if len(fixes) != 0 {
		t.Fatalf("fixes = %v, want empty", fixes)
	}
}

func TestBuildAuditTrailSetupCheck_MalformedAuditLogFails(t *testing.T) {
	repoRoot := t.TempDir()
	spoolDir := filepath.Join(repoRoot, ".zt-spool")
	if err := os.MkdirAll(spoolDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(spoolDir, "events.jsonl"), []byte("{\"event_id\":\"ok\"}\nnot-json\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	check, fixes := buildAuditTrailSetupCheck(repoRoot)
	if check.Status != "fail" {
		t.Fatalf("status = %q, want fail", check.Status)
	}
	if check.Code != auditTrailAppendUnavailableCode {
		t.Fatalf("code = %q, want %q", check.Code, auditTrailAppendUnavailableCode)
	}
	if len(fixes) == 0 {
		t.Fatalf("fixes should not be empty")
	}
}

func TestAuditAppendFailureState_ConsumeContract(t *testing.T) {
	resetAuditAppendFailureState()
	if got := consumeAuditAppendFailureState(); got != nil {
		t.Fatalf("consume before record = %+v, want nil", got)
	}
	rememberAuditAppendFailure("/v1/events/verify", os.ErrPermission)
	got := consumeAuditAppendFailureState()
	if got == nil {
		t.Fatalf("consume after record = nil, want non-nil")
	}
	if got.Endpoint != "/v1/events/verify" {
		t.Fatalf("endpoint = %q", got.Endpoint)
	}
	if got.Message == "" {
		t.Fatalf("message is empty")
	}
	if got2 := consumeAuditAppendFailureState(); got2 != nil {
		t.Fatalf("consume should clear state, got %+v", got2)
	}
}
