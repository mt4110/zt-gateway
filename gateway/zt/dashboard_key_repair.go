package main

import (
	"encoding/csv"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

type dashboardKeyRepairSnapshot struct {
	TenantID      string                 `json:"tenant_id,omitempty"`
	TotalJobs     int                    `json:"total_jobs"`
	OpenJobs      int                    `json:"open_jobs"`
	CompletedJobs int                    `json:"completed_jobs"`
	FailedJobs    int                    `json:"failed_jobs"`
	Recent        []localSORKeyRepairJob `json:"recent,omitempty"`
	Error         string                 `json:"error,omitempty"`
}

type dashboardKeyRepairListResponse struct {
	TenantID    string                 `json:"tenant_id"`
	KeyID       string                 `json:"key_id,omitempty"`
	Q           string                 `json:"q,omitempty"`
	State       string                 `json:"state,omitempty"`
	Page        int                    `json:"page"`
	PageSize    int                    `json:"page_size"`
	Total       int                    `json:"total"`
	TotalPages  int                    `json:"total_pages"`
	NextPage    int                    `json:"next_page"`
	Sort        string                 `json:"sort"`
	Items       []localSORKeyRepairJob `json:"items"`
	Source      string                 `json:"source"`
	GeneratedAt string                 `json:"generated_at"`
}

type dashboardKeyRepairDetailResponse struct {
	TenantID    string               `json:"tenant_id"`
	Job         localSORKeyRepairJob `json:"job"`
	Source      string               `json:"source"`
	GeneratedAt string               `json:"generated_at"`
}

type dashboardKeyRepairCreateRequest struct {
	TenantID    string `json:"tenant_id,omitempty"`
	KeyID       string `json:"key_id"`
	Trigger     string `json:"trigger,omitempty"`
	Operator    string `json:"operator,omitempty"`
	Summary     string `json:"summary,omitempty"`
	EvidenceRef string `json:"evidence_ref,omitempty"`
	RunbookID   string `json:"runbook_id,omitempty"`
}

type dashboardKeyRepairTransitionRequest struct {
	TenantID    string `json:"tenant_id,omitempty"`
	State       string `json:"state"`
	Operator    string `json:"operator,omitempty"`
	Summary     string `json:"summary,omitempty"`
	EvidenceRef string `json:"evidence_ref,omitempty"`
	RunbookID   string `json:"runbook_id,omitempty"`
}

type dashboardKeyRepairTransitionResponse struct {
	TenantID    string               `json:"tenant_id"`
	Job         localSORKeyRepairJob `json:"job"`
	FromState   string               `json:"from_state"`
	ToState     string               `json:"to_state"`
	Changed     bool                 `json:"changed"`
	Source      string               `json:"source"`
	GeneratedAt string               `json:"generated_at"`
}

func collectDashboardKeyRepairSnapshot(repoRoot string, now time.Time) dashboardKeyRepairSnapshot {
	_ = now
	if localSOR == nil || localSOR.db == nil {
		return dashboardKeyRepairSnapshot{Error: "local_sor_unavailable"}
	}
	tenantID, code := resolveDashboardClientTenantScope(repoRoot, "")
	if code != "" {
		return dashboardKeyRepairSnapshot{Error: code}
	}
	items, total, err := localSOR.listKeyRepairJobs(tenantID, "", "", "", "started_at_desc", 5, 0, false)
	if err != nil {
		return dashboardKeyRepairSnapshot{TenantID: tenantID, Error: err.Error()}
	}
	out := dashboardKeyRepairSnapshot{
		TenantID:  tenantID,
		TotalJobs: total,
		Recent:    items,
	}
	if err := localSOR.db.QueryRow(`
select
  count(*),
  coalesce(sum(case when state in ('detected','contained','rekeyed','rewrapped') then 1 else 0 end), 0),
  coalesce(sum(case when state = 'completed' then 1 else 0 end), 0),
  coalesce(sum(case when state = 'failed' then 1 else 0 end), 0)
from local_sor_key_repair_jobs
where tenant_id = ?1
`, tenantID).Scan(&out.TotalJobs, &out.OpenJobs, &out.CompletedJobs, &out.FailedJobs); err != nil {
		out.Error = appendDashboardError(out.Error, err)
	}
	return out
}

func handleDashboardKeyRepairJobsAPI(repoRoot string, w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		handleDashboardKeyRepairJobsList(repoRoot, w, r)
	case http.MethodPost:
		handleDashboardKeyRepairJobsCreate(repoRoot, w, r)
	default:
		writeDashboardClientJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
	}
}

func handleDashboardKeyRepairJobsList(repoRoot string, w http.ResponseWriter, r *http.Request) {
	if localSOR == nil || localSOR.db == nil {
		writeDashboardClientJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "local_sor_unavailable"})
		return
	}
	tenantID, code := resolveDashboardClientTenantScope(repoRoot, r.URL.Query().Get("tenant_id"))
	if code != "" {
		writeDashboardClientJSON(w, httpStatusForDashboardClientError(code), map[string]any{"error": code})
		return
	}
	keyID := strings.TrimSpace(r.URL.Query().Get("key_id"))
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	rawState := strings.TrimSpace(r.URL.Query().Get("state"))
	state := normalizeDashboardKeyRepairStateFilter(rawState)
	if rawState != "" && state == "" {
		writeDashboardClientJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_job_state"})
		return
	}
	sortBy := normalizeDashboardKeyRepairSort(r.URL.Query().Get("sort"))
	page := parseDashboardPositiveInt(r.URL.Query().Get("page"), 1, 100000)
	pageSize := parseDashboardPositiveInt(r.URL.Query().Get("page_size"), 20, 200)
	offset := (page - 1) * pageSize
	exportCSV := strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("export")), "csv")

	items, total, err := localSOR.listKeyRepairJobs(tenantID, keyID, q, state, sortBy, pageSize, offset, exportCSV)
	if err != nil {
		writeDashboardClientJSON(w, http.StatusInternalServerError, map[string]any{"error": "key_repair_jobs_query_failed"})
		return
	}
	if exportCSV {
		writeDashboardKeyRepairJobsCSV(w, "dashboard-key-repair-jobs.csv", items)
		return
	}
	totalPages := 0
	if total > 0 {
		totalPages = (total + pageSize - 1) / pageSize
	}
	nextPage := 0
	if page < totalPages {
		nextPage = page + 1
	}
	writeDashboardClientJSON(w, http.StatusOK, dashboardKeyRepairListResponse{
		TenantID:    tenantID,
		KeyID:       keyID,
		Q:           q,
		State:       state,
		Page:        page,
		PageSize:    pageSize,
		Total:       total,
		TotalPages:  totalPages,
		NextPage:    nextPage,
		Sort:        sortBy,
		Items:       items,
		Source:      "local_sor_key_repair_jobs",
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	})
}

func handleDashboardKeyRepairJobsCreate(repoRoot string, w http.ResponseWriter, r *http.Request) {
	if localSOR == nil || localSOR.db == nil {
		writeDashboardClientJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "local_sor_unavailable"})
		return
	}
	defer r.Body.Close()
	var req dashboardKeyRepairCreateRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil && err != io.EOF {
		writeDashboardClientJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_json"})
		return
	}
	requestedTenant := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	if requestedTenant == "" {
		requestedTenant = strings.TrimSpace(req.TenantID)
	}
	tenantID, code := resolveDashboardClientTenantScope(repoRoot, requestedTenant)
	if code != "" {
		writeDashboardClientJSON(w, httpStatusForDashboardClientError(code), map[string]any{"error": code})
		return
	}
	job, created, err := localSOR.createKeyRepairJob(
		tenantID,
		req.KeyID,
		req.Trigger,
		req.Operator,
		req.Summary,
		req.EvidenceRef,
		req.RunbookID,
		time.Now().UTC(),
	)
	if err != nil {
		writeDashboardClientJSON(w, httpStatusForDashboardKeyRepairError(err), map[string]any{"error": strings.TrimSpace(err.Error())})
		return
	}
	statusCode := http.StatusCreated
	if !created {
		statusCode = http.StatusOK
	}
	writeDashboardClientJSON(w, statusCode, dashboardKeyRepairDetailResponse{
		TenantID:    tenantID,
		Job:         job,
		Source:      "local_sor_key_repair_jobs",
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	})
}

func handleDashboardKeyRepairJobDetailAPI(repoRoot, jobID string, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeDashboardClientJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}
	if localSOR == nil || localSOR.db == nil {
		writeDashboardClientJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "local_sor_unavailable"})
		return
	}
	jobID = strings.TrimSpace(jobID)
	if jobID == "" {
		writeDashboardClientJSON(w, http.StatusBadRequest, map[string]any{"error": "job_id_required"})
		return
	}
	tenantID, code := resolveDashboardClientTenantScope(repoRoot, r.URL.Query().Get("tenant_id"))
	if code != "" {
		writeDashboardClientJSON(w, httpStatusForDashboardClientError(code), map[string]any{"error": code})
		return
	}
	job, ok, err := localSOR.getKeyRepairJob(tenantID, jobID)
	if err != nil {
		writeDashboardClientJSON(w, http.StatusInternalServerError, map[string]any{"error": "key_repair_job_query_failed"})
		return
	}
	if !ok {
		writeDashboardClientJSON(w, http.StatusNotFound, map[string]any{"error": "job_not_found"})
		return
	}
	writeDashboardClientJSON(w, http.StatusOK, dashboardKeyRepairDetailResponse{
		TenantID:    tenantID,
		Job:         job,
		Source:      "local_sor_key_repair_jobs",
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	})
}

func handleDashboardKeyRepairJobTransitionAPI(repoRoot, listenAddr, jobID string, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeDashboardClientJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}
	if ok, _ := requireDashboardMutationAuth(w, r, listenAddr); !ok {
		return
	}
	if localSOR == nil || localSOR.db == nil {
		writeDashboardClientJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "local_sor_unavailable"})
		return
	}
	jobID = strings.TrimSpace(jobID)
	if jobID == "" {
		writeDashboardClientJSON(w, http.StatusBadRequest, map[string]any{"error": "job_id_required"})
		return
	}
	defer r.Body.Close()
	var req dashboardKeyRepairTransitionRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil && err != io.EOF {
		writeDashboardClientJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_json"})
		return
	}
	requestedTenant := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	if requestedTenant == "" {
		requestedTenant = strings.TrimSpace(req.TenantID)
	}
	tenantID, code := resolveDashboardClientTenantScope(repoRoot, requestedTenant)
	if code != "" {
		writeDashboardClientJSON(w, httpStatusForDashboardClientError(code), map[string]any{"error": code})
		return
	}
	updated, fromState, changed, err := localSOR.transitionKeyRepairJob(
		tenantID,
		jobID,
		req.State,
		req.Operator,
		req.Summary,
		req.EvidenceRef,
		req.RunbookID,
		time.Now().UTC(),
	)
	if err != nil {
		writeDashboardClientJSON(w, httpStatusForDashboardKeyRepairError(err), map[string]any{"error": strings.TrimSpace(err.Error())})
		return
	}
	writeDashboardClientJSON(w, http.StatusOK, dashboardKeyRepairTransitionResponse{
		TenantID:    tenantID,
		Job:         updated,
		FromState:   fromState,
		ToState:     updated.State,
		Changed:     changed,
		Source:      "local_sor_key_repair_jobs",
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	})
}

func httpStatusForDashboardKeyRepairError(err error) int {
	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	switch {
	case strings.Contains(msg, "key_not_found"), strings.Contains(msg, "job_not_found"):
		return http.StatusNotFound
	case strings.Contains(msg, "invalid_job_state"), strings.Contains(msg, "job_id is required"), strings.Contains(msg, "key_id is required"):
		return http.StatusBadRequest
	case strings.Contains(msg, "job_state_transition_disallowed"):
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}

func normalizeDashboardKeyRepairStateFilter(raw string) string {
	state, ok := normalizeLocalSORKeyRepairState(raw)
	if !ok {
		return ""
	}
	return state
}

func normalizeDashboardKeyRepairSort(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "started_at_asc":
		return "started_at_asc"
	case "started_at_desc":
		return "started_at_desc"
	case "state_asc":
		return "state_asc"
	case "state_desc":
		return "state_desc"
	default:
		return "started_at_desc"
	}
}

func writeDashboardKeyRepairJobsCSV(w http.ResponseWriter, filename string, items []localSORKeyRepairJob) {
	if strings.TrimSpace(filename) == "" {
		filename = "dashboard-key-repair-jobs.csv"
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{
		"tenant_id",
		"job_id",
		"key_id",
		"trigger",
		"state",
		"runbook_id",
		"started_at",
		"updated_at",
		"finished_at",
		"operator",
		"summary",
		"evidence_ref",
	})
	for _, item := range items {
		_ = cw.Write([]string{
			item.TenantID,
			item.JobID,
			item.KeyID,
			item.Trigger,
			item.State,
			item.RunbookID,
			item.StartedAt,
			item.UpdatedAt,
			item.FinishedAt,
			item.Operator,
			item.Summary,
			item.EvidenceRef,
		})
	}
	cw.Flush()
}
