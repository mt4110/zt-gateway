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

func TestUpdateKeyStatus_AutoCreatesKeyRepairJob(t *testing.T) {
	repoRoot := t.TempDir()
	store := setupDashboardClientTestLocalSOR(t, repoRoot)

	mustExecLocalSOR(t, store, `
insert into local_sor_keys (key_id, tenant_id, client_id, key_purpose, status, fingerprint, created_at, rotated_at, revoked_at, compromise_flag)
values ('key-auto', 'tenant-a', 'client-a', 'artifact_signing', 'active', 'FPAUTO', '2026-02-27T00:00:00Z', null, null, 0)
`)

	_, _, changed, err := store.updateKeyStatus("tenant-a", "key-auto", localSORKeyStatusCompromised, "detected mismatch", "ops-user", "evidence-1", time.Now().UTC())
	if err != nil {
		t.Fatalf("updateKeyStatus: %v", err)
	}
	if !changed {
		t.Fatalf("changed=false, want true")
	}

	var state, runbook string
	if err := store.db.QueryRow(`
select state, runbook_id
from local_sor_key_repair_jobs
where tenant_id = 'tenant-a' and key_id = 'key-auto'
order by started_at desc
limit 1
`).Scan(&state, &runbook); err != nil {
		t.Fatalf("query key repair job: %v", err)
	}
	if state != localSORKeyRepairStateDetected {
		t.Fatalf("state=%q, want %q", state, localSORKeyRepairStateDetected)
	}
	if strings.TrimSpace(runbook) == "" {
		t.Fatalf("runbook_id is empty")
	}

	var incidentCount int
	if err := store.db.QueryRow(`
select count(*) from local_sor_incidents
where tenant_id='tenant-a' and action='key_repair_detected' and reason like '%runbook_id=%'
`).Scan(&incidentCount); err != nil {
		t.Fatalf("count incidents: %v", err)
	}
	if incidentCount == 0 {
		t.Fatalf("incident count=0, want >0")
	}
}

func TestHandleDashboardKeyRepairJobsAPI_TransitionAndDangerLifecycle(t *testing.T) {
	repoRoot := t.TempDir()
	store := setupDashboardClientTestLocalSOR(t, repoRoot)
	t.Setenv("ZT_DASHBOARD_TENANT_ID", "tenant-a")

	mustExecLocalSOR(t, store, `
insert into local_sor_keys (key_id, tenant_id, client_id, key_purpose, status, fingerprint, created_at, rotated_at, revoked_at, compromise_flag)
values ('key-repair', 'tenant-a', 'client-a', 'artifact_signing', 'active', 'FPREPAIR', '2026-02-27T00:00:00Z', null, null, 0)
`)

	createReq := dashboardKeyRepairCreateRequest{
		KeyID:     "key-repair",
		Trigger:   "manual_investigation",
		Operator:  "ops-user",
		Summary:   "start repair workflow",
		RunbookID: "docs/OPERATIONS.md#kr-001",
	}
	rawCreate, _ := json.Marshal(createReq)
	req := httptest.NewRequest(http.MethodPost, "/api/key-repair/jobs?tenant_id=tenant-a", bytes.NewReader(rawCreate))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleDashboardKeyRepairJobsAPI(repoRoot, rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}

	var created dashboardKeyRepairDetailResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if created.Job.State != localSORKeyRepairStateDetected {
		t.Fatalf("state=%q, want %q", created.Job.State, localSORKeyRepairStateDetected)
	}
	if created.Job.JobID == "" {
		t.Fatalf("job_id is empty")
	}

	snapshotBefore := collectDashboardSnapshot(repoRoot, time.Now().UTC())
	foundInProgress := false
	for _, sig := range snapshotBefore.Danger.Signals {
		if strings.TrimSpace(sig.Code) == "key_repair_in_progress" {
			foundInProgress = true
			break
		}
	}
	if !foundInProgress {
		t.Fatalf("danger signals missing key_repair_in_progress: %#v", snapshotBefore.Danger.Signals)
	}

	advance := func(state string) {
		t.Helper()
		transitionReq := dashboardKeyRepairTransitionRequest{
			State:       state,
			Operator:    "ops-user",
			Summary:     "move to " + state,
			RunbookID:   "docs/OPERATIONS.md#kr-001",
			EvidenceRef: "incident-42",
		}
		raw, _ := json.Marshal(transitionReq)
		req := httptest.NewRequest(http.MethodPost, "/api/key-repair/jobs/"+created.Job.JobID+"/transition?tenant_id=tenant-a", bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		handleDashboardKeyRepairJobTransitionAPI(repoRoot, created.Job.JobID, rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("transition %s: status=%d body=%s", state, rr.Code, rr.Body.String())
		}
	}

	advance(localSORKeyRepairStateContained)
	advance(localSORKeyRepairStateRekeyed)
	advance(localSORKeyRepairStateRewrapped)
	advance(localSORKeyRepairStateCompleted)

	snapshotAfter := collectDashboardSnapshot(repoRoot, time.Now().UTC())
	for _, sig := range snapshotAfter.Danger.Signals {
		if strings.TrimSpace(sig.Code) == "key_repair_in_progress" {
			t.Fatalf("key_repair_in_progress should be cleared after completion: %#v", snapshotAfter.Danger.Signals)
		}
	}

	var keyStatus string
	if err := store.db.QueryRow(`select status from local_sor_keys where tenant_id='tenant-a' and key_id='key-repair'`).Scan(&keyStatus); err != nil {
		t.Fatalf("query key status: %v", err)
	}
	if keyStatus != localSORKeyStatusActive {
		t.Fatalf("key status=%q, want %q after completed", keyStatus, localSORKeyStatusActive)
	}

	var transitionCount int
	if err := store.db.QueryRow(`
select count(*) from local_sor_incidents
where tenant_id='tenant-a' and action='key_repair_transition' and reason like '%runbook_id=docs/OPERATIONS.md#kr-001%'
`).Scan(&transitionCount); err != nil {
		t.Fatalf("count transition incidents: %v", err)
	}
	if transitionCount == 0 {
		t.Fatalf("transition incidents count=0, want >0")
	}
}
