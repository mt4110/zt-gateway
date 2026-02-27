package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCollectDashboardIncidentStatus_TracksBreakGlassActive(t *testing.T) {
	repoRoot := t.TempDir()
	now := time.Now().UTC()
	if err := appendDashboardIncidentRecord(repoRoot, dashboardIncidentRecord{
		Action:     "break_glass_start",
		Reason:     "incident=INC-1;approved_by=secops;expires_at=" + now.Add(30*time.Minute).Format(time.RFC3339),
		IncidentID: "INC-1",
		ApprovedBy: "secops",
		ExpiresAt:  now.Add(30 * time.Minute).Format(time.RFC3339),
		Actor:      "test",
		Timestamp:  now.Format(time.RFC3339),
	}); err != nil {
		t.Fatalf("appendDashboardIncidentRecord(start): %v", err)
	}

	status := collectDashboardIncidentStatus(repoRoot, now.Add(1*time.Minute), 10)
	if !status.ActiveBreakGlass {
		t.Fatalf("ActiveBreakGlass = false, want true")
	}
	if status.BreakGlassUntil == "" {
		t.Fatalf("BreakGlassUntil is empty")
	}
	if status.TotalCount != 1 {
		t.Fatalf("TotalCount = %d, want 1", status.TotalCount)
	}
}

func TestDispatchDashboardAlerts_GuardsExternalByDefault(t *testing.T) {
	repoRoot := setupDashboardAlertDispatchTestEnv(t)
	t.Setenv("ZT_DASHBOARD_ALERT_DISPATCH_ENABLED", "")
	alert := dashboardAlertStatus{
		Level: "high",
		Items: []dashboardAlertItem{{Severity: "high", Code: "x", Source: "test", Message: "m"}},
		Count: 1,
	}
	_, err := dispatchDashboardAlerts(repoRoot, alert, dashboardAlertDispatchRequest{
		Channel:    "webhook",
		WebhookURL: "https://hooks.example.com/a",
		DryRun:     true,
	})
	if err == nil {
		t.Fatalf("dispatchDashboardAlerts error = nil, want guard error")
	}
	if got := err.Error(); got != "external_dispatch_disabled" {
		t.Fatalf("error = %q, want external_dispatch_disabled", got)
	}
	rec := lastDashboardAlertDispatchAuditRecord(t, repoRoot)
	if rec.Result != "rejected" {
		t.Fatalf("audit result = %q, want rejected", rec.Result)
	}
	if rec.EventType != dashboardAlertDispatchCommand {
		t.Fatalf("audit event_type = %q, want %q", rec.EventType, dashboardAlertDispatchCommand)
	}
	if rec.Endpoint != dashboardAlertDispatchAuditEndpoint {
		t.Fatalf("audit endpoint = %q, want %q", rec.Endpoint, dashboardAlertDispatchAuditEndpoint)
	}
}

func TestDispatchDashboardAlerts_DryRunAudited(t *testing.T) {
	repoRoot := setupDashboardAlertDispatchTestEnv(t)
	t.Setenv("ZT_DASHBOARD_ALERT_DISPATCH_ENABLED", "1")
	t.Setenv("ZT_DASHBOARD_ALERT_WEBHOOK_ALLOW_HOSTS", "hooks.example.com")
	alert := dashboardAlertStatus{
		Level: "medium",
		Items: []dashboardAlertItem{
			{Severity: "high", Code: "key_repair_in_progress", Source: "danger", Message: "open key repair jobs=1"},
		},
		Count: 1,
	}
	out, err := dispatchDashboardAlerts(repoRoot, alert, dashboardAlertDispatchRequest{
		Channel:    "webhook",
		WebhookURL: "https://hooks.example.com/dispatch",
		DryRun:     true,
	})
	if err != nil {
		t.Fatalf("dispatchDashboardAlerts(dry_run) error: %v", err)
	}
	if ok, _ := out["ok"].(bool); !ok {
		t.Fatalf("dispatch output ok=false: %#v", out)
	}
	rec := lastDashboardAlertDispatchAuditRecord(t, repoRoot)
	if rec.Result != "dry_run" {
		t.Fatalf("audit result = %q, want dry_run", rec.Result)
	}
}

func TestDispatchDashboardAlerts_FailedPostAudited(t *testing.T) {
	repoRoot := setupDashboardAlertDispatchTestEnv(t)
	t.Setenv("ZT_DASHBOARD_ALERT_DISPATCH_ENABLED", "1")
	t.Setenv("ZT_DASHBOARD_ALERT_WEBHOOK_ALLOW_HOSTS", "127.0.0.1")
	alert := dashboardAlertStatus{
		Level: "high",
		Items: []dashboardAlertItem{
			{Severity: "high", Code: "event_sync_fail_closed_backlog", Source: "event_sync", Message: "fail-closed backlog=1"},
		},
		Count: 1,
	}
	_, err := dispatchDashboardAlerts(repoRoot, alert, dashboardAlertDispatchRequest{
		Channel:    "webhook",
		WebhookURL: "https://127.0.0.1:1/dispatch",
		DryRun:     false,
	})
	if err == nil {
		t.Fatalf("dispatchDashboardAlerts error=nil, want webhook failure")
	}
	rec := lastDashboardAlertDispatchAuditRecord(t, repoRoot)
	if rec.Result != "failed" {
		t.Fatalf("audit result = %q, want failed", rec.Result)
	}
}

func TestBuildDashboardAlertMessage_MinimalPayload(t *testing.T) {
	msg := buildDashboardAlertMessage(dashboardAlertStatus{
		Level: "high",
		Count: 1,
		Items: []dashboardAlertItem{
			{
				Severity: "high",
				Code:     "receipt_tamper_detected",
				Source:   "danger",
				Message:  "tamper detected at /sensitive/path/receipt.json",
			},
		},
	})
	if strings.Contains(msg, "/sensitive/path/receipt.json") {
		t.Fatalf("message contains sensitive detail: %q", msg)
	}
	if !strings.Contains(msg, "receipt_tamper_detected") {
		t.Fatalf("message missing alert code: %q", msg)
	}
}

func TestCollectDashboardControlPlaneStatus_NoConfig(t *testing.T) {
	repoRoot := t.TempDir()
	status := collectDashboardControlPlaneStatus(repoRoot, time.Now().UTC())
	if status.Configured {
		t.Fatalf("Configured = true, want false")
	}
}

func TestResolveDashboardControlPlaneClient_IncludesBearerToken(t *testing.T) {
	repoRoot := t.TempDir()
	cfgPath := filepath.Join(repoRoot, "policy", "zt_client.toml")
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	cfg := "control_plane_url='https://cp.example'\napi_key='api-secret'\nbearer_token='jwt-token'\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	baseURL, apiKey, bearer := resolveDashboardControlPlaneClient(repoRoot)
	if baseURL != "https://cp.example" {
		t.Fatalf("baseURL = %q, want https://cp.example", baseURL)
	}
	if apiKey != "api-secret" {
		t.Fatalf("apiKey = %q, want api-secret", apiKey)
	}
	if bearer != "jwt-token" {
		t.Fatalf("bearer = %q, want jwt-token", bearer)
	}
}

func TestCollectDashboardAlertStatus_IncludesAnomalyFalsePositiveSignal(t *testing.T) {
	t.Setenv("ZT_DASHBOARD_ANOMALY_FALSE_POSITIVE_THRESHOLD", "0.20")
	alerts := collectDashboardAlertStatus(
		dashboardDangerStatus{Level: "low", Signals: []dashboardDangerItem{{Level: "low", Code: "healthy", Message: "ok"}}},
		dashboardEventSyncStatus{},
		dashboardIncidentStatus{},
		dashboardKPIStatus{
			SignatureAnomalyCount:              4,
			SignatureAnomalyFalsePositiveCount: 1,
			SignatureAnomalyFalsePositiveRatio: 0.25,
		},
		dashboardControlPlaneStatus{},
	)
	found := false
	for _, item := range alerts.Items {
		if item.Code == "signature_anomaly_false_positive_high" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("alerts missing signature_anomaly_false_positive_high: %#v", alerts.Items)
	}
}

func setupDashboardAlertDispatchTestEnv(t *testing.T) string {
	t.Helper()
	repoRoot := t.TempDir()
	t.Setenv("ZT_EVENT_SPOOL_DIR", filepath.Join(repoRoot, ".zt-spool"))
	prev := cpEvents
	cpEvents = nil
	t.Cleanup(func() {
		cpEvents = prev
	})
	return repoRoot
}

func lastDashboardAlertDispatchAuditRecord(t *testing.T, repoRoot string) auditEventRecordContract {
	t.Helper()
	path := filepath.Join(repoRoot, ".zt-spool", "events.jsonl")
	records := readAuditEventRecordsContract(t, path)
	if len(records) == 0 {
		t.Fatalf("audit records are empty")
	}
	return records[len(records)-1]
}
