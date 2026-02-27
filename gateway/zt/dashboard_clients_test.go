package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHandleDashboardClientsAPI_ListAndTenantIsolation(t *testing.T) {
	repoRoot := t.TempDir()
	store := setupDashboardClientTestLocalSOR(t, repoRoot)

	mustExecLocalSOR(t, store, `
insert into local_sor_clients (client_id, tenant_id, display_name, status, created_at, updated_at)
values
  ('client-a', 'tenant-a', 'Client A', 'active', '2026-02-27T00:00:00Z', '2026-02-27T00:00:00Z'),
  ('client-b', 'tenant-a', 'Client B', 'active', '2026-02-27T01:00:00Z', '2026-02-27T01:00:00Z')
`)
	mustExecLocalSOR(t, store, `
insert into local_sor_assets (asset_id, tenant_id, client_id, filename, content_sha256, location_type, location_ref, created_at, last_seen_at, access_count)
values
  ('asset-1', 'tenant-a', 'client-a', 'a.pdf', 'sha-a', 'local_path', '/tmp/a.pdf', '2026-02-27T00:00:00Z', '2026-02-27T02:00:00Z', 1),
  ('asset-2', 'tenant-a', 'client-b', 'b.pdf', 'sha-b', 'local_path', '/tmp/b.pdf', '2026-02-27T01:00:00Z', '2026-02-27T02:30:00Z', 1)
`)

	t.Run("list_with_paging_and_q", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/clients?tenant_id=tenant-a&q=client&page=1&page_size=1&sort=last_seen_desc", nil)
		rr := httptest.NewRecorder()
		handleDashboardClientsAPI(repoRoot, rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
		var resp dashboardClientsListResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("json decode failed: %v", err)
		}
		if resp.Total != 2 {
			t.Fatalf("total=%d, want 2", resp.Total)
		}
		if len(resp.Items) != 1 {
			t.Fatalf("len(items)=%d, want 1", len(resp.Items))
		}
		if resp.Items[0].ClientID != "client-b" {
			t.Fatalf("items[0].client_id=%q, want client-b (last_seen desc)", resp.Items[0].ClientID)
		}
		if resp.NextPage != 2 {
			t.Fatalf("next_page=%d, want 2", resp.NextPage)
		}
	})

	t.Run("tenant_scope_violation_when_enforced", func(t *testing.T) {
		t.Setenv("ZT_DASHBOARD_TENANT_ID", "tenant-a")
		req := httptest.NewRequest(http.MethodGet, "/api/clients?tenant_id=tenant-b", nil)
		rr := httptest.NewRecorder()
		handleDashboardClientsAPI(repoRoot, rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
		var resp map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &resp)
		if got, _ := resp["error"].(string); got != "tenant_scope_violation" {
			t.Fatalf("error=%q, want tenant_scope_violation", got)
		}
	})
}

func TestHandleDashboardClientDetailAPI_ExportCSV(t *testing.T) {
	repoRoot := t.TempDir()
	store := setupDashboardClientTestLocalSOR(t, repoRoot)

	mustExecLocalSOR(t, store, `
insert into local_sor_clients (client_id, tenant_id, display_name, status, created_at, updated_at)
values ('client-a', 'tenant-a', 'Client A', 'active', '2026-02-27T00:00:00Z', '2026-02-27T00:00:00Z')
`)
	mustExecLocalSOR(t, store, `
insert into local_sor_assets (asset_id, tenant_id, client_id, filename, content_sha256, location_type, location_ref, created_at, last_seen_at, access_count)
values ('asset-1', 'tenant-a', 'client-a', 'a.pdf', 'sha-a', 'local_path', '/tmp/a.pdf', '2026-02-27T00:00:00Z', '2026-02-27T02:00:00Z', 2)
`)

	req := httptest.NewRequest(http.MethodGet, "/api/clients/client-a?tenant_id=tenant-a&export=csv", nil)
	rr := httptest.NewRecorder()
	handleDashboardClientDetailAPI(repoRoot, "client-a", rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Fatalf("content-type=%q, want text/csv", ct)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "asset_id") || !strings.Contains(body, "asset-1") {
		t.Fatalf("unexpected csv body: %s", body)
	}
}

func setupDashboardClientTestLocalSOR(t *testing.T, repoRoot string) *localSORStore {
	t.Helper()
	t.Setenv(localSORMasterKeyEnv, "")
	t.Setenv(localSORAllowPlaintextEnv, "1")
	t.Setenv(localSORDBPathEnv, filepath.Join(repoRoot, ".zt-spool", "dashboard-clients-test.db"))
	store, err := initializeLocalSOR(repoRoot)
	if err != nil {
		t.Fatalf("initializeLocalSOR: %v", err)
	}
	old := localSOR
	localSOR = store
	t.Cleanup(func() {
		localSOR = old
		_ = store.db.Close()
	})
	return store
}

func mustExecLocalSOR(t *testing.T, store *localSORStore, stmt string) {
	t.Helper()
	if _, err := store.db.Exec(strings.TrimSpace(stmt)); err != nil {
		t.Fatalf("exec failed: %v", err)
	}
}

func TestIngestDashboardReceiptsToLocalSOR(t *testing.T) {
	repoRoot := t.TempDir()
	store := setupDashboardClientTestLocalSOR(t, repoRoot)

	receiptPath := filepath.Join(repoRoot, "receipt_clientA.json")
	receipt := verificationReceipt{
		ReceiptVersion: "v1",
		ReceiptID:      "r-1",
		VerifiedAt:     time.Now().UTC().Format(time.RFC3339),
		Artifact: receiptArtifact{
			Path:   filepath.Join(repoRoot, "bundle_clientA_20260227T010101Z.spkg.tgz"),
			SHA256: "ab12",
		},
		Verification: receiptVerification{
			SignatureValid: true,
			TamperDetected: false,
			PolicyResult:   "pass",
		},
		Provenance: receiptProvenance{
			Client:   "client-a",
			TenantID: "tenant-a",
		},
	}
	data, _ := json.Marshal(receipt)
	if err := os.WriteFile(receiptPath, data, 0o644); err != nil {
		t.Fatalf("write receipt: %v", err)
	}

	ingestDashboardReceiptsToLocalSOR(repoRoot, []dashboardVerificationRecord{{Path: receiptPath}}, time.Now().UTC())

	var count int
	if err := store.db.QueryRow(`select count(*) from local_sor_clients where tenant_id='tenant-a' and client_id='client-a'`).Scan(&count); err != nil {
		t.Fatalf("count clients: %v", err)
	}
	if count != 1 {
		t.Fatalf("clients count=%d, want 1", count)
	}
	if err := store.db.QueryRow(`select count(*) from local_sor_assets where tenant_id='tenant-a' and client_id='client-a'`).Scan(&count); err != nil {
		t.Fatalf("count assets: %v", err)
	}
	if count != 1 {
		t.Fatalf("assets count=%d, want 1", count)
	}
}
