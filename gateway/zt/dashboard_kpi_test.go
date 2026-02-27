package main

import (
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCollectDashboardSnapshot_KPIUsesLocalSORExchangeMetrics(t *testing.T) {
	repoRoot := t.TempDir()
	store := setupDashboardClientTestLocalSOR(t, repoRoot)
	t.Setenv("ZT_DASHBOARD_TENANT_ID", "tenant-a")
	t.Setenv("ZT_DASHBOARD_SLO_VERIFY_PASS_TARGET", "0.70")

	mustExecLocalSOR(t, store, `
insert into local_sor_exchanges (exchange_id, tenant_id, client_id, asset_id, direction, result, verify_result, signer_fingerprint, created_at)
values
  ('ex-1', 'tenant-a', 'client-a', 'asset-1', 'verify', 'verified', 'pass', 'FP1', '2026-02-27T00:00:00Z'),
  ('ex-2', 'tenant-a', 'client-a', 'asset-2', 'verify', 'verified', 'pass', 'FP1', '2026-02-27T00:01:00Z'),
  ('ex-3', 'tenant-a', 'client-a', 'asset-3', 'verify', 'failed', 'fail', 'FP1', '2026-02-27T00:02:00Z'),
  ('ex-4', 'tenant-a', 'client-a', 'asset-4', 'send', 'ok', 'n/a', 'FP1', '2026-02-27T00:03:00Z'),
  ('ex-5', 'tenant-a', 'client-a', 'asset-5', 'receive', 'ok', 'n/a', 'FP1', '2026-02-27T00:04:00Z')
`)
	mustExecLocalSOR(t, store, `
insert into local_sor_key_repair_jobs (job_id, tenant_id, key_id, trigger, state, runbook_id, started_at, updated_at)
values
  ('kr-auto-done', 'tenant-a', 'key-a', 'auto_detected', 'completed', 'docs/OPERATIONS.md#key-repair', '2026-02-27T00:10:00Z', '2026-02-27T00:20:00Z'),
  ('kr-auto-open', 'tenant-a', 'key-b', 'compromised_key_detected', 'contained', 'docs/OPERATIONS.md#key-repair', '2026-02-27T00:11:00Z', '2026-02-27T00:21:00Z'),
  ('kr-manual', 'tenant-a', 'key-c', 'manual_investigation', 'completed', 'docs/OPERATIONS.md#key-repair', '2026-02-27T00:12:00Z', '2026-02-27T00:22:00Z')
`)
	snapshot := collectDashboardSnapshot(repoRoot, time.Now().UTC())
	kpi := snapshot.KPI

	if kpi.TenantID != "tenant-a" {
		t.Fatalf("tenant_id=%q, want tenant-a", kpi.TenantID)
	}
	if kpi.ExchangeTotal != 5 {
		t.Fatalf("exchange_total=%d, want 5", kpi.ExchangeTotal)
	}
	if kpi.SendCount != 1 {
		t.Fatalf("send_count=%d, want 1", kpi.SendCount)
	}
	if kpi.ReceiveCount != 1 {
		t.Fatalf("receive_count=%d, want 1", kpi.ReceiveCount)
	}
	if kpi.VerifyReceiptsTotal != 3 {
		t.Fatalf("verify_receipts_total=%d, want 3", kpi.VerifyReceiptsTotal)
	}
	if kpi.VerifyPassCount != 2 {
		t.Fatalf("verify_pass_count=%d, want 2", kpi.VerifyPassCount)
	}
	if kpi.VerifyFailCount != 1 {
		t.Fatalf("verify_fail_count=%d, want 1", kpi.VerifyFailCount)
	}
	if math.Abs(kpi.VerifyPassRatio-(2.0/3.0)) > 0.0001 {
		t.Fatalf("verify_pass_ratio=%f, want %f", kpi.VerifyPassRatio, 2.0/3.0)
	}
	if math.Abs(kpi.VerifyPassSLOTarget-0.70) > 0.0001 {
		t.Fatalf("verify_pass_slo_target=%f, want 0.70", kpi.VerifyPassSLOTarget)
	}
	if kpi.VerifyPassSLOMet {
		t.Fatalf("verify_pass_slo_met=true, want false")
	}
	if kpi.KeyRepairAutoTriggeredJobs != 2 {
		t.Fatalf("key_repair_auto_triggered_jobs=%d, want 2", kpi.KeyRepairAutoTriggeredJobs)
	}
	if kpi.KeyRepairAutoCompletedJobs != 1 {
		t.Fatalf("key_repair_auto_completed_jobs=%d, want 1", kpi.KeyRepairAutoCompletedJobs)
	}
	if math.Abs(kpi.KeyRepairAutoRecoveryRate-0.5) > 0.0001 {
		t.Fatalf("key_repair_auto_recovery_rate=%f, want 0.5", kpi.KeyRepairAutoRecoveryRate)
	}
}

func TestHandleDashboardKPIAPI_MatchesSnapshotKPI(t *testing.T) {
	repoRoot := t.TempDir()
	store := setupDashboardClientTestLocalSOR(t, repoRoot)
	t.Setenv("ZT_DASHBOARD_TENANT_ID", "tenant-a")
	t.Setenv("ZT_DASHBOARD_SLO_VERIFY_PASS_TARGET", "0.50")

	mustExecLocalSOR(t, store, `
insert into local_sor_exchanges (exchange_id, tenant_id, client_id, asset_id, direction, result, verify_result, signer_fingerprint, created_at)
values
  ('kpi-1', 'tenant-a', 'client-a', 'asset-a', 'verify', 'verified', 'pass', 'FP1', '2026-02-27T01:00:00Z'),
  ('kpi-2', 'tenant-a', 'client-a', 'asset-b', 'verify', 'failed', 'fail', 'FP1', '2026-02-27T01:01:00Z')
`)

	expected := collectDashboardSnapshot(repoRoot, time.Now().UTC()).KPI
	req := httptest.NewRequest(http.MethodGet, "/api/kpi", nil)
	rr := httptest.NewRecorder()
	handleDashboardKPIAPI(repoRoot, rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var resp dashboardKPIResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Source != "dashboard_snapshot" {
		t.Fatalf("source=%q, want dashboard_snapshot", resp.Source)
	}
	if resp.KPI.VerifyReceiptsTotal != expected.VerifyReceiptsTotal {
		t.Fatalf("verify_receipts_total=%d, want %d", resp.KPI.VerifyReceiptsTotal, expected.VerifyReceiptsTotal)
	}
	if resp.KPI.VerifyPassCount != expected.VerifyPassCount {
		t.Fatalf("verify_pass_count=%d, want %d", resp.KPI.VerifyPassCount, expected.VerifyPassCount)
	}
	if resp.KPI.VerifyFailCount != expected.VerifyFailCount {
		t.Fatalf("verify_fail_count=%d, want %d", resp.KPI.VerifyFailCount, expected.VerifyFailCount)
	}
	if resp.KPI.ExchangeTotal != expected.ExchangeTotal {
		t.Fatalf("exchange_total=%d, want %d", resp.KPI.ExchangeTotal, expected.ExchangeTotal)
	}
	if math.Abs(resp.KPI.VerifyPassRatio-expected.VerifyPassRatio) > 0.0001 {
		t.Fatalf("verify_pass_ratio=%f, want %f", resp.KPI.VerifyPassRatio, expected.VerifyPassRatio)
	}
}

func TestCollectDashboardKPIStatus_ComputesSignatureAnomalyFalsePositiveRatio(t *testing.T) {
	kpi := collectDashboardKPIStatus(
		t.TempDir(),
		dashboardDangerStatus{},
		dashboardEventSyncStatus{},
		dashboardAuditStatus{},
		[]dashboardVerificationRecord{
			{PolicyResult: "pass", SignatureValid: false, TamperDetected: false},
			{PolicyResult: "deny", SignatureValid: false, TamperDetected: true},
			{PolicyResult: "pass", SignatureValid: true, TamperDetected: false},
		},
		dashboardControlPlaneStatus{},
		time.Now().UTC(),
	)
	if kpi.SignatureAnomalyCount != 2 {
		t.Fatalf("signature_anomaly_count=%d, want 2", kpi.SignatureAnomalyCount)
	}
	if kpi.SignatureAnomalyFalsePositiveCount != 1 {
		t.Fatalf("signature_anomaly_false_positive_count=%d, want 1", kpi.SignatureAnomalyFalsePositiveCount)
	}
	if math.Abs(kpi.SignatureAnomalyFalsePositiveRatio-0.5) > 0.0001 {
		t.Fatalf("signature_anomaly_false_positive_ratio=%f, want 0.5", kpi.SignatureAnomalyFalsePositiveRatio)
	}
}

func TestCollectDashboardSnapshot_KPIIncludesSignatureHolderRealtimeMetrics(t *testing.T) {
	repoRoot := t.TempDir()
	store := setupDashboardClientTestLocalSOR(t, repoRoot)
	t.Setenv("ZT_DASHBOARD_TENANT_ID", "tenant-a")
	t.Setenv("ZT_DASHBOARD_SIGNATURE_HOLDER_SLO_SECONDS", "60")

	mustExecLocalSOR(t, store, `
insert into local_sor_signature_holders (tenant_id, signature_id, holder_count_estimated, holder_count_confirmed, updated_at)
values
  ('tenant-a', 'FP-1', 3, 3, '2026-02-27T00:00:10Z'),
  ('tenant-a', 'FP-2', 4, 2, '2026-02-27T00:02:30Z')
`)
	snapshot := collectDashboardSnapshot(
		repoRoot,
		time.Date(2026, time.February, 27, 0, 3, 0, 0, time.UTC),
	)
	kpi := snapshot.KPI
	if kpi.SignatureHoldersRealtimeSLOSeconds != 60 {
		t.Fatalf("signature_holders_realtime_slo_seconds=%d, want 60", kpi.SignatureHoldersRealtimeSLOSeconds)
	}
	if kpi.SignatureHoldersRealtimeDelayed != 1 {
		t.Fatalf("signature_holders_realtime_delayed_signatures=%d, want 1", kpi.SignatureHoldersRealtimeDelayed)
	}
	if kpi.SignatureHoldersRealtimeSLOMet {
		t.Fatalf("signature_holders_realtime_slo_met=true, want false")
	}
}
