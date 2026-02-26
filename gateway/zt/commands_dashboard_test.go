package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCollectDashboardSnapshot_Basic(t *testing.T) {
	repoRoot := t.TempDir()
	spoolDir := filepath.Join(repoRoot, ".zt-spool")
	if err := os.MkdirAll(spoolDir, 0o755); err != nil {
		t.Fatal(err)
	}

	auditPath := filepath.Join(spoolDir, "events.jsonl")
	rec := auditEventRecord{
		EventID:       "evt_1",
		EventType:     "verify",
		Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
		Result:        "verified",
		Endpoint:      "/v1/events/verify",
		PayloadSHA256: "abc",
		ChainVersion:  "v1",
		RecordSHA256:  "abc",
	}
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(auditPath, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}

	packetPath := filepath.Join(repoRoot, "bundle_clientA_20260225T000000Z.spkg.tgz")
	if err := os.WriteFile(packetPath, []byte("packet"), 0o644); err != nil {
		t.Fatal(err)
	}
	receipt := buildVerificationReceipt(packetPath, decisionForVerify(true, "policy_verify_pass"))
	receiptPath := filepath.Join(repoRoot, "receipt_bundle_clientA_20260225T000000Z.json")
	if err := writeVerificationReceipt(receiptPath, receipt); err != nil {
		t.Fatal(err)
	}

	snapshot := collectDashboardSnapshot(repoRoot, time.Now().UTC())
	if snapshot.SchemaVersion != 1 {
		t.Fatalf("SchemaVersion = %d, want 1", snapshot.SchemaVersion)
	}
	if snapshot.Audit.TotalCount != 1 {
		t.Fatalf("Audit.TotalCount = %d, want 1", snapshot.Audit.TotalCount)
	}
	if len(snapshot.Receipts) == 0 {
		t.Fatalf("Receipts is empty")
	}
	if snapshot.Receipts[0].ReceiptID == "" {
		t.Fatalf("receipt id is empty")
	}
}

func TestCollectDashboardSnapshot_IncludesLockAndDanger(t *testing.T) {
	repoRoot := t.TempDir()
	if _, err := writeLocalOperationLock(repoRoot, true, "incident", "test", time.Now().UTC()); err != nil {
		t.Fatalf("writeLocalOperationLock: %v", err)
	}

	snapshot := collectDashboardSnapshot(repoRoot, time.Now().UTC())
	if !snapshot.Lock.Locked {
		t.Fatalf("snapshot.Lock.Locked = false, want true")
	}
	if snapshot.Danger.Level != "high" {
		t.Fatalf("snapshot.Danger.Level = %q, want high", snapshot.Danger.Level)
	}
	found := false
	for _, s := range snapshot.Danger.Signals {
		if strings.TrimSpace(s.Code) == "local_lock_active" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("danger signals missing local_lock_active: %#v", snapshot.Danger.Signals)
	}
}
