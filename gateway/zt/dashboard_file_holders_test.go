package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHandleDashboardFileHoldersAPI_List(t *testing.T) {
	repoRoot := t.TempDir()
	store := setupDashboardClientTestLocalSOR(t, repoRoot)

	mustExecLocalSOR(t, store, `
insert into local_sor_assets (asset_id, tenant_id, client_id, filename, content_sha256, location_type, location_ref, created_at, last_seen_at, access_count)
values
  ('asset-a1', 'tenant-a', 'client-a', 'report.pdf', 'sha-report', 'local_path', '/tmp/report.pdf', '2026-02-27T00:00:00Z', '2026-02-27T02:00:00Z', 1),
  ('asset-b1', 'tenant-a', 'client-b', 'report-copy.pdf', 'sha-report', 'local_path', '/tmp/report-copy.pdf', '2026-02-27T00:30:00Z', '2026-02-27T03:00:00Z', 1),
  ('asset-c1', 'tenant-a', 'client-c', 'other.pdf', 'sha-other', 'local_path', '/tmp/other.pdf', '2026-02-27T01:00:00Z', '2026-02-27T03:30:00Z', 1)
`)
	mustExecLocalSOR(t, store, `
insert into local_sor_exchanges (exchange_id, tenant_id, client_id, asset_id, direction, result, verify_result, signer_fingerprint, created_at)
values
  ('ex-1', 'tenant-a', 'client-a', 'asset-a1', 'verify', 'verified', 'pass', 'FP-A', '2026-02-27T03:10:00Z'),
  ('ex-2', 'tenant-a', 'client-b', 'asset-b1', 'verify', 'verified', 'pass', 'FP-B', '2026-02-27T03:11:00Z')
`)

	req := httptest.NewRequest(http.MethodGet, "/api/files/holders?tenant_id=tenant-a&sort=holder_desc", nil)
	rr := httptest.NewRecorder()
	handleDashboardFileHoldersAPI(repoRoot, rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var resp dashboardFileHoldersListResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json decode failed: %v", err)
	}
	if resp.Total != 2 {
		t.Fatalf("total=%d, want 2", resp.Total)
	}
	if len(resp.Items) == 0 {
		t.Fatalf("items is empty")
	}
	if resp.Items[0].ContentSHA256 != "sha-report" {
		t.Fatalf("first content_sha256=%q, want sha-report", resp.Items[0].ContentSHA256)
	}
	if resp.Items[0].HolderClientCount != 2 {
		t.Fatalf("holder_client_count=%d, want 2", resp.Items[0].HolderClientCount)
	}
}

func TestHandleDashboardFileHoldersTimelineAPI(t *testing.T) {
	repoRoot := t.TempDir()
	store := setupDashboardClientTestLocalSOR(t, repoRoot)
	now := time.Now().UTC()
	day3 := now.AddDate(0, 0, -3).Format(time.RFC3339)
	day1 := now.AddDate(0, 0, -1).Format(time.RFC3339)
	day0 := now.Format(time.RFC3339)

	mustExecLocalSOR(t, store, fmt.Sprintf(`
insert into local_sor_assets (asset_id, tenant_id, client_id, filename, content_sha256, location_type, location_ref, created_at, last_seen_at, access_count)
values
  ('asset-a1', 'tenant-a', 'client-a', 'report.pdf', 'sha-report', 'local_path', '/tmp/report.pdf', '%s', '%s', 1),
  ('asset-b1', 'tenant-a', 'client-b', 'report-copy.pdf', 'sha-report', 'local_path', '/tmp/report-copy.pdf', '%s', '%s', 1)
`, day3, day0, day1, day0))
	mustExecLocalSOR(t, store, fmt.Sprintf(`
insert into local_sor_exchanges (exchange_id, tenant_id, client_id, asset_id, direction, result, verify_result, signer_fingerprint, created_at)
values
  ('ex-1', 'tenant-a', 'client-a', 'asset-a1', 'verify', 'verified', 'pass', 'FP-A', '%s'),
  ('ex-2', 'tenant-a', 'client-b', 'asset-b1', 'verify', 'verified', 'pass', 'FP-B', '%s')
`, day0, day0))

	req := httptest.NewRequest(http.MethodGet, "/api/files/holders/timeseries?tenant_id=tenant-a&content_sha256=sha-report&window_days=7", nil)
	rr := httptest.NewRecorder()
	handleDashboardFileHoldersTimelineAPI(repoRoot, rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var resp dashboardFileHolderTimelineResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json decode failed: %v", err)
	}
	if resp.ContentSHA256 != "sha-report" {
		t.Fatalf("content_sha256=%q, want sha-report", resp.ContentSHA256)
	}
	if len(resp.Points) != 7 {
		t.Fatalf("len(points)=%d, want 7", len(resp.Points))
	}
	last := resp.Points[len(resp.Points)-1]
	if last.HolderCount < 1 {
		t.Fatalf("last holder_count=%d, want >=1", last.HolderCount)
	}
}
