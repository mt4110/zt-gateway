package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHandleDashboardModelsAPI_RequiresTenantScope(t *testing.T) {
	repoRoot := t.TempDir()
	setupDashboardClientTestLocalSOR(t, repoRoot)

	req := httptest.NewRequest(http.MethodGet, "/api/models", nil)
	rr := httptest.NewRecorder()
	handleDashboardModelsAPI(repoRoot, rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json decode failed: %v", err)
	}
	if got, _ := resp["error"].(string); got != "tenant_scope_required" {
		t.Fatalf("error=%q, want tenant_scope_required", got)
	}
}

func TestHandleDashboardModelsAPI_TenantIsolation(t *testing.T) {
	repoRoot := t.TempDir()
	store := setupDashboardClientTestLocalSOR(t, repoRoot)
	mustExecLocalSOR(t, store, `
insert into model_assets (model_id, tenant_id, name, version, format, capsule_id, artifact_sha256, manifest_sha256, declared_size_bytes, created_at, updated_at, last_seen_at, status)
values
  ('mdl-a', 'tenant-a', 'Alpha', '1.0', 'gguf', 'zmc-a', 'sha-a', 'msha-a', 10, '2026-02-27T00:00:00Z', '2026-02-27T01:00:00Z', '2026-02-27T01:00:00Z', 'active'),
  ('mdl-b', 'tenant-b', 'Beta', '1.0', 'gguf', 'zmc-b', 'sha-b', 'msha-b', 10, '2026-02-27T00:00:00Z', '2026-02-27T02:00:00Z', '2026-02-27T02:00:00Z', 'active')
`)

	req := httptest.NewRequest(http.MethodGet, "/api/models?tenant_id=tenant-a", nil)
	rr := httptest.NewRecorder()
	handleDashboardModelsAPI(repoRoot, rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var resp dashboardModelsListResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json decode failed: %v", err)
	}
	if resp.TenantID != "tenant-a" || resp.Total != 1 || len(resp.Items) != 1 {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if resp.Items[0].TenantID != "tenant-a" || resp.Items[0].ModelID != "mdl-a" {
		t.Fatalf("tenant leak detected: %+v", resp.Items)
	}
}

func TestCollectDashboardModelSnapshotRequiresTenantScope(t *testing.T) {
	repoRoot := t.TempDir()
	setupDashboardClientTestLocalSOR(t, repoRoot)

	snapshot := collectDashboardModelSnapshot(repoRoot, time.Now().UTC())
	if snapshot.Error != "tenant_scope_required" {
		t.Fatalf("error=%q, want tenant_scope_required", snapshot.Error)
	}
}
