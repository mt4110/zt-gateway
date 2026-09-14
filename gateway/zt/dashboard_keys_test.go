package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHandleDashboardKeysAPI_ListAndTenantIsolation(t *testing.T) {
	repoRoot := t.TempDir()
	store := setupDashboardClientTestLocalSOR(t, repoRoot)

	mustExecLocalSOR(t, store, `
insert into local_sor_keys (key_id, tenant_id, client_id, key_purpose, status, fingerprint, created_at, rotated_at, revoked_at, compromise_flag)
values
  ('key-a', 'tenant-a', 'client-a', 'artifact_signing', 'active', 'FPA', '2026-02-27T00:00:00Z', null, null, 0),
  ('key-b', 'tenant-a', 'client-b', 'artifact_signing', 'compromised', 'FPB', '2026-02-27T01:00:00Z', null, null, 1),
  ('key-c', 'tenant-b', 'client-c', 'artifact_signing', 'active', 'FPC', '2026-02-27T02:00:00Z', null, null, 0)
`)

	t.Run("list_status_filtered", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/keys?tenant_id=tenant-a&status=compromised&page=1&page_size=10", nil)
		rr := httptest.NewRecorder()
		handleDashboardKeysAPI(repoRoot, rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
		var resp dashboardKeysListResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("json decode failed: %v", err)
		}
		if resp.Total != 1 {
			t.Fatalf("total=%d, want 1", resp.Total)
		}
		if len(resp.Items) != 1 || resp.Items[0].KeyID != "key-b" {
			t.Fatalf("items=%#v, want only key-b", resp.Items)
		}
		if !resp.Items[0].CompromiseFlag {
			t.Fatalf("compromise_flag=false, want true")
		}
	})

	t.Run("tenant_scope_violation_when_enforced", func(t *testing.T) {
		t.Setenv("ZT_DASHBOARD_TENANT_ID", "tenant-a")
		req := httptest.NewRequest(http.MethodGet, "/api/keys?tenant_id=tenant-b", nil)
		rr := httptest.NewRecorder()
		handleDashboardKeysAPI(repoRoot, rr, req)
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

func TestHandleDashboardKeyStatusAPI_TransitionAuditedAndDangerHigh(t *testing.T) {
	repoRoot := t.TempDir()
	store := setupDashboardClientTestLocalSOR(t, repoRoot)

	mustExecLocalSOR(t, store, `
insert into local_sor_keys (key_id, tenant_id, client_id, key_purpose, status, fingerprint, created_at, rotated_at, revoked_at, compromise_flag)
values ('key-a', 'tenant-a', 'client-a', 'artifact_signing', 'active', 'FPA', '2026-02-27T00:00:00Z', null, null, 0)
`)

	body := dashboardKeyStatusUpdateRequest{
		Status: "compromised",
		Reason: "signature mismatch",
		Actor:  "ops-user",
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/keys/key-a/status?tenant_id=tenant-a", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleDashboardKeyStatusAPI(repoRoot, "127.0.0.1:8787", "key-a", rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var resp dashboardKeyStatusUpdateResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json decode failed: %v", err)
	}
	if !resp.Changed {
		t.Fatalf("changed=false, want true")
	}
	if resp.ToStatus != localSORKeyStatusCompromised {
		t.Fatalf("to_status=%q, want %q", resp.ToStatus, localSORKeyStatusCompromised)
	}
	if !resp.Key.CompromiseFlag {
		t.Fatalf("key.compromise_flag=false, want true")
	}

	var incidentCount int
	if err := store.db.QueryRow(`
select count(*) from local_sor_incidents
where tenant_id = 'tenant-a' and action = 'key_status_transition' and reason like '%key_id=key-a%'
`).Scan(&incidentCount); err != nil {
		t.Fatalf("count incidents: %v", err)
	}
	if incidentCount == 0 {
		t.Fatalf("incident count=0, want >0")
	}

	t.Setenv("ZT_DASHBOARD_TENANT_ID", "tenant-a")
	snapshot := collectDashboardSnapshot(repoRoot, time.Now().UTC())
	found := false
	for _, sig := range snapshot.Danger.Signals {
		if strings.TrimSpace(sig.Code) == "local_sor_keys_compromised" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("danger signals missing local_sor_keys_compromised: %#v", snapshot.Danger.Signals)
	}
}

func TestV099HandleDashboardKeyStatusAPI_RemoteBindRejectsWithoutToken(t *testing.T) {
	repoRoot := t.TempDir()
	store := setupDashboardClientTestLocalSOR(t, repoRoot)
	t.Setenv("ZT_DASHBOARD_MUTATION_TOKEN", "")

	mustExecLocalSOR(t, store, `
insert into local_sor_keys (key_id, tenant_id, client_id, key_purpose, status, fingerprint, created_at, rotated_at, revoked_at, compromise_flag)
values ('key-auth', 'tenant-a', 'client-a', 'artifact_signing', 'active', 'FPAUTH', '2026-02-27T00:00:00Z', null, null, 0)
`)

	body := dashboardKeyStatusUpdateRequest{
		Status: "compromised",
		Reason: "signature mismatch",
		Actor:  "ops-user",
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/keys/key-auth/status?tenant_id=tenant-a", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleDashboardKeyStatusAPI(repoRoot, "0.0.0.0:8787", "key-auth", rr, req)
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

func TestV099HandleDashboardKeyStatusAPI_RemoteBindRejectsTokenMismatch(t *testing.T) {
	repoRoot := t.TempDir()
	store := setupDashboardClientTestLocalSOR(t, repoRoot)
	t.Setenv("ZT_DASHBOARD_MUTATION_TOKEN", "token-1")

	mustExecLocalSOR(t, store, `
insert into local_sor_keys (key_id, tenant_id, client_id, key_purpose, status, fingerprint, created_at, rotated_at, revoked_at, compromise_flag)
values ('key-auth', 'tenant-a', 'client-a', 'artifact_signing', 'active', 'FPAUTH', '2026-02-27T00:00:00Z', null, null, 0)
`)

	body := dashboardKeyStatusUpdateRequest{
		Status: "compromised",
		Reason: "signature mismatch",
		Actor:  "ops-user",
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/keys/key-auth/status?tenant_id=tenant-a", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(dashboardMutationTokenHdr, "token-2")
	rr := httptest.NewRecorder()
	handleDashboardKeyStatusAPI(repoRoot, "0.0.0.0:8787", "key-auth", rr, req)
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

func TestV099HandleDashboardKeyStatusAPI_RemoteBindAllowsTokenMatch(t *testing.T) {
	repoRoot := t.TempDir()
	store := setupDashboardClientTestLocalSOR(t, repoRoot)
	t.Setenv("ZT_DASHBOARD_MUTATION_TOKEN", "token-1")

	mustExecLocalSOR(t, store, `
insert into local_sor_keys (key_id, tenant_id, client_id, key_purpose, status, fingerprint, created_at, rotated_at, revoked_at, compromise_flag)
values ('key-auth', 'tenant-a', 'client-a', 'artifact_signing', 'active', 'FPAUTH', '2026-02-27T00:00:00Z', null, null, 0)
`)

	body := dashboardKeyStatusUpdateRequest{
		Status: "compromised",
		Reason: "signature mismatch",
		Actor:  "ops-user",
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/keys/key-auth/status?tenant_id=tenant-a", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(dashboardMutationTokenHdr, "token-1")
	rr := httptest.NewRecorder()
	handleDashboardKeyStatusAPI(repoRoot, "0.0.0.0:8787", "key-auth", rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want %d body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
}
