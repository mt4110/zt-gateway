package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAppendAuditEvent_ExternalLedgerDisabled(t *testing.T) {
	repoRoot := t.TempDir()
	t.Setenv(auditExternalLedgerEnabledEnv, "")
	spool := newEventSpool(repoRoot)
	spool.SetAutoSync(false)

	if err := spool.appendAuditEvent("/v1/events/verify", map[string]any{
		"event_id": "evt-ledger-off",
		"result":   "verified",
	}); err != nil {
		t.Fatalf("appendAuditEvent: %v", err)
	}
	if _, err := os.Stat(spool.auditPath()); err != nil {
		t.Fatalf("audit path missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(spool.cfg.SpoolDir, "audit-external-ledger.jsonl")); err == nil {
		t.Fatalf("external ledger file exists unexpectedly when disabled")
	}
}

func TestAppendAuditEvent_ExternalLedgerEnabled(t *testing.T) {
	repoRoot := t.TempDir()
	t.Setenv(auditExternalLedgerEnabledEnv, "1")
	ledgerPath := filepath.Join(repoRoot, ".zt-spool", "ledger.jsonl")
	t.Setenv(auditExternalLedgerPathEnv, ledgerPath)
	spool := newEventSpool(repoRoot)
	spool.SetAutoSync(false)

	if err := spool.appendAuditEvent("/v1/events/verify", map[string]any{
		"event_id": "evt-ledger-on",
		"result":   "verified",
	}); err != nil {
		t.Fatalf("appendAuditEvent: %v", err)
	}
	raw, err := os.ReadFile(ledgerPath)
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 1 {
		t.Fatalf("ledger lines=%d, want 1", len(lines))
	}
	var rec auditExternalLedgerRecord
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("unmarshal ledger: %v", err)
	}
	if rec.EventID != "evt-ledger-on" {
		t.Fatalf("event_id=%q, want evt-ledger-on", rec.EventID)
	}
	if strings.TrimSpace(rec.RecordSHA256) == "" {
		t.Fatalf("record_sha256 is empty")
	}
}
