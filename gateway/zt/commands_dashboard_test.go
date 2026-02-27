package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	receipt, err := buildVerificationReceipt(packetPath, decisionForVerify(true, "policy_verify_pass"), "0123456789ABCDEF0123456789ABCDEF01234567")
	if err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(repoRoot, "receipt_bundle_clientA_20260225T000000Z.json")
	if err := writeVerificationReceipt(receiptPath, receipt); err != nil {
		t.Fatal(err)
	}

	snapshot := collectDashboardSnapshot(repoRoot, time.Now().UTC())
	if snapshot.SchemaVersion != 7 {
		t.Fatalf("SchemaVersion = %d, want 7", snapshot.SchemaVersion)
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
	if snapshot.KPI.VerifyReceiptsTotal == 0 {
		t.Fatalf("KPI.VerifyReceiptsTotal = 0, want >0")
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

func TestCollectDashboardSnapshot_AlertDispatchUnsafeConfigSignal(t *testing.T) {
	t.Setenv("ZT_DASHBOARD_ALERT_DISPATCH_ENABLED", "1")
	t.Setenv("ZT_DASHBOARD_ALERT_WEBHOOK_ALLOW_HOSTS", "")
	repoRoot := t.TempDir()

	snapshot := collectDashboardSnapshot(repoRoot, time.Now().UTC())
	if snapshot.Danger.Level != "high" {
		t.Fatalf("snapshot.Danger.Level = %q, want high", snapshot.Danger.Level)
	}
	found := false
	for _, s := range snapshot.Danger.Signals {
		if strings.TrimSpace(s.Code) == "dashboard_alert_dispatch_unsafe_config" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("danger signals missing dashboard_alert_dispatch_unsafe_config: %#v", snapshot.Danger.Signals)
	}
}

func TestCollectDashboardSnapshot_AlertDispatchAllowHostsConfigured_NoUnsafeSignal(t *testing.T) {
	t.Setenv("ZT_DASHBOARD_ALERT_DISPATCH_ENABLED", "1")
	t.Setenv("ZT_DASHBOARD_ALERT_WEBHOOK_ALLOW_HOSTS", "hooks.slack.com")
	repoRoot := t.TempDir()

	snapshot := collectDashboardSnapshot(repoRoot, time.Now().UTC())
	for _, s := range snapshot.Danger.Signals {
		if strings.TrimSpace(s.Code) == "dashboard_alert_dispatch_unsafe_config" {
			t.Fatalf("unexpected dashboard_alert_dispatch_unsafe_config signal: %#v", snapshot.Danger.Signals)
		}
	}
}

func TestV098CollectDashboardSnapshot_RemoteBindMutationLockedSignal(t *testing.T) {
	repoRoot := t.TempDir()
	snapshot := collectDashboardSnapshotWithListenAddr(repoRoot, time.Now().UTC(), "0.0.0.0:8787")
	found := false
	for _, s := range snapshot.Danger.Signals {
		if strings.TrimSpace(s.Code) == "dashboard_remote_bind_mutation_locked" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("danger signals missing dashboard_remote_bind_mutation_locked: %#v", snapshot.Danger.Signals)
	}
	if snapshot.Danger.Level != "high" {
		t.Fatalf("snapshot.Danger.Level = %q, want high", snapshot.Danger.Level)
	}
}

func TestV098CollectDashboardSnapshot_RemoteBindMutationLockedSignal_NoTokenRequiredWhenConfigured(t *testing.T) {
	t.Setenv("ZT_DASHBOARD_MUTATION_TOKEN", "token-1")
	repoRoot := t.TempDir()
	snapshot := collectDashboardSnapshotWithListenAddr(repoRoot, time.Now().UTC(), "0.0.0.0:8787")
	for _, s := range snapshot.Danger.Signals {
		if strings.TrimSpace(s.Code) == "dashboard_remote_bind_mutation_locked" {
			t.Fatalf("unexpected dashboard_remote_bind_mutation_locked signal: %#v", snapshot.Danger.Signals)
		}
	}
}

func TestV098HandleDashboardLockAPI_RemoteBindRejectsWithoutToken(t *testing.T) {
	repoRoot := t.TempDir()
	req := httptest.NewRequest(http.MethodPost, "/api/lock", bytes.NewBufferString(`{"action":"lock","reason":"incident"}`))
	rr := httptest.NewRecorder()
	handleDashboardLockAPI(repoRoot, "0.0.0.0:8787", rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d, want %d body=%s", rr.Code, http.StatusForbidden, rr.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("json.Unmarshal: %v body=%s", err, rr.Body.String())
	}
	if got, _ := out["error"].(string); got != "dashboard_mutation_token_required" {
		t.Fatalf("error=%q, want dashboard_mutation_token_required", got)
	}
}

func TestV098HandleDashboardLockAPI_RemoteBindRejectsOnTokenMismatch(t *testing.T) {
	t.Setenv("ZT_DASHBOARD_MUTATION_TOKEN", "token-1")
	repoRoot := t.TempDir()
	req := httptest.NewRequest(http.MethodPost, "/api/lock", bytes.NewBufferString(`{"action":"lock","reason":"incident"}`))
	req.Header.Set(dashboardMutationTokenHdr, "token-2")
	rr := httptest.NewRecorder()
	handleDashboardLockAPI(repoRoot, "0.0.0.0:8787", rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d, want %d body=%s", rr.Code, http.StatusForbidden, rr.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("json.Unmarshal: %v body=%s", err, rr.Body.String())
	}
	if got, _ := out["error"].(string); got != "dashboard_mutation_auth_failed" {
		t.Fatalf("error=%q, want dashboard_mutation_auth_failed", got)
	}
}

func TestV098HandleDashboardLockAPI_RemoteBindAllowsWithToken(t *testing.T) {
	t.Setenv("ZT_DASHBOARD_MUTATION_TOKEN", "token-1")
	repoRoot := t.TempDir()
	req := httptest.NewRequest(http.MethodPost, "/api/lock", bytes.NewBufferString(`{"action":"lock","reason":"incident"}`))
	req.Header.Set(dashboardMutationTokenHdr, "token-1")
	rr := httptest.NewRecorder()
	handleDashboardLockAPI(repoRoot, "0.0.0.0:8787", rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want %d body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	var out dashboardLockStatus
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("json.Unmarshal: %v body=%s", err, rr.Body.String())
	}
	if !out.Locked {
		t.Fatalf("locked=%v, want true", out.Locked)
	}
}
