package main

import (
	"encoding/csv"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type dashboardKeySnapshot struct {
	TenantID         string              `json:"tenant_id,omitempty"`
	TotalKeys        int                 `json:"total_keys"`
	ActiveCount      int                 `json:"active_count"`
	RotatingCount    int                 `json:"rotating_count"`
	RevokedCount     int                 `json:"revoked_count"`
	CompromisedCount int                 `json:"compromised_count"`
	Recent           []localSORKeyRecord `json:"recent,omitempty"`
	Error            string              `json:"error,omitempty"`
}

type dashboardKeysListResponse struct {
	TenantID    string              `json:"tenant_id"`
	Q           string              `json:"q,omitempty"`
	Status      string              `json:"status,omitempty"`
	Page        int                 `json:"page"`
	PageSize    int                 `json:"page_size"`
	Total       int                 `json:"total"`
	TotalPages  int                 `json:"total_pages"`
	NextPage    int                 `json:"next_page"`
	Sort        string              `json:"sort"`
	Items       []localSORKeyRecord `json:"items"`
	Source      string              `json:"source"`
	GeneratedAt string              `json:"generated_at"`
}

type dashboardKeyDetailResponse struct {
	TenantID    string            `json:"tenant_id"`
	Key         localSORKeyRecord `json:"key"`
	Source      string            `json:"source"`
	GeneratedAt string            `json:"generated_at"`
}

type dashboardKeyStatusUpdateRequest struct {
	TenantID    string `json:"tenant_id,omitempty"`
	Status      string `json:"status"`
	Reason      string `json:"reason,omitempty"`
	Actor       string `json:"actor,omitempty"`
	EvidenceRef string `json:"evidence_ref,omitempty"`
}

type dashboardKeyStatusUpdateResponse struct {
	TenantID    string            `json:"tenant_id"`
	Key         localSORKeyRecord `json:"key"`
	FromStatus  string            `json:"from_status"`
	ToStatus    string            `json:"to_status"`
	Changed     bool              `json:"changed"`
	Source      string            `json:"source"`
	GeneratedAt string            `json:"generated_at"`
}

func collectDashboardKeySnapshot(repoRoot string, now time.Time) dashboardKeySnapshot {
	_ = now
	if localSOR == nil || localSOR.db == nil {
		return dashboardKeySnapshot{Error: "local_sor_unavailable"}
	}
	tenantID, code := resolveDashboardClientTenantScope(repoRoot, "")
	if code != "" {
		return dashboardKeySnapshot{Error: code}
	}
	items, total, err := localSOR.listKeys(tenantID, "", "", "created_at_desc", 5, 0, false)
	if err != nil {
		return dashboardKeySnapshot{TenantID: tenantID, Error: err.Error()}
	}
	out := dashboardKeySnapshot{
		TenantID:  tenantID,
		TotalKeys: total,
		Recent:    items,
	}
	if err := localSOR.db.QueryRow(`
select
  count(*),
  coalesce(sum(case when status = 'active' then 1 else 0 end), 0),
  coalesce(sum(case when status = 'rotating' then 1 else 0 end), 0),
  coalesce(sum(case when status = 'revoked' then 1 else 0 end), 0),
  coalesce(sum(case when status = 'compromised' then 1 else 0 end), 0)
from local_sor_keys
where tenant_id = ?1
`, tenantID).Scan(&out.TotalKeys, &out.ActiveCount, &out.RotatingCount, &out.RevokedCount, &out.CompromisedCount); err != nil {
		out.Error = appendDashboardError(out.Error, err)
	}
	return out
}

func handleDashboardKeysAPI(repoRoot string, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeDashboardClientJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}
	if localSOR == nil || localSOR.db == nil {
		writeDashboardClientJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "local_sor_unavailable"})
		return
	}
	tenantID, code := resolveDashboardClientTenantScope(repoRoot, r.URL.Query().Get("tenant_id"))
	if code != "" {
		writeDashboardClientJSON(w, httpStatusForDashboardClientError(code), map[string]any{"error": code})
		return
	}

	q := strings.TrimSpace(r.URL.Query().Get("q"))
	rawStatusFilter := strings.TrimSpace(r.URL.Query().Get("status"))
	statusFilter := normalizeDashboardKeyStatusFilter(rawStatusFilter)
	if rawStatusFilter != "" && statusFilter == "" {
		writeDashboardClientJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_key_status"})
		return
	}
	sortBy := normalizeDashboardKeySort(r.URL.Query().Get("sort"))
	page := parseDashboardPositiveInt(r.URL.Query().Get("page"), 1, 100000)
	pageSize := parseDashboardPositiveInt(r.URL.Query().Get("page_size"), 20, 200)
	offset := (page - 1) * pageSize
	exportCSV := strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("export")), "csv")

	items, total, err := localSOR.listKeys(tenantID, q, statusFilter, sortBy, pageSize, offset, exportCSV)
	if err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(strings.ToLower(err.Error()), "invalid key status") {
			status = http.StatusBadRequest
		}
		writeDashboardClientJSON(w, status, map[string]any{"error": "keys_query_failed"})
		return
	}
	if exportCSV {
		writeDashboardKeysCSV(w, "dashboard-keys.csv", items)
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
	writeDashboardClientJSON(w, http.StatusOK, dashboardKeysListResponse{
		TenantID:    tenantID,
		Q:           q,
		Status:      statusFilter,
		Page:        page,
		PageSize:    pageSize,
		Total:       total,
		TotalPages:  totalPages,
		NextPage:    nextPage,
		Sort:        sortBy,
		Items:       items,
		Source:      "local_sor_keys",
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	})
}

func handleDashboardKeyDetailAPI(repoRoot, keyID string, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeDashboardClientJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}
	if localSOR == nil || localSOR.db == nil {
		writeDashboardClientJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "local_sor_unavailable"})
		return
	}
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		writeDashboardClientJSON(w, http.StatusBadRequest, map[string]any{"error": "key_id_required"})
		return
	}
	tenantID, code := resolveDashboardClientTenantScope(repoRoot, r.URL.Query().Get("tenant_id"))
	if code != "" {
		writeDashboardClientJSON(w, httpStatusForDashboardClientError(code), map[string]any{"error": code})
		return
	}
	item, ok, err := localSOR.getKey(tenantID, keyID)
	if err != nil {
		writeDashboardClientJSON(w, http.StatusInternalServerError, map[string]any{"error": "key_query_failed"})
		return
	}
	if !ok {
		writeDashboardClientJSON(w, http.StatusNotFound, map[string]any{"error": "key_not_found"})
		return
	}
	writeDashboardClientJSON(w, http.StatusOK, dashboardKeyDetailResponse{
		TenantID:    tenantID,
		Key:         item,
		Source:      "local_sor_keys",
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	})
}

func handleDashboardKeyStatusAPI(repoRoot, keyID string, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeDashboardClientJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}
	if localSOR == nil || localSOR.db == nil {
		writeDashboardClientJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "local_sor_unavailable"})
		return
	}
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		writeDashboardClientJSON(w, http.StatusBadRequest, map[string]any{"error": "key_id_required"})
		return
	}
	defer r.Body.Close()
	var req dashboardKeyStatusUpdateRequest
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

	updated, fromStatus, changed, err := localSOR.updateKeyStatus(
		tenantID,
		keyID,
		req.Status,
		req.Reason,
		req.Actor,
		req.EvidenceRef,
		time.Now().UTC(),
	)
	if err != nil {
		writeDashboardClientJSON(w, httpStatusForDashboardKeyStatusError(err), map[string]any{"error": strings.TrimSpace(err.Error())})
		return
	}
	writeDashboardClientJSON(w, http.StatusOK, dashboardKeyStatusUpdateResponse{
		TenantID:    tenantID,
		Key:         updated,
		FromStatus:  fromStatus,
		ToStatus:    updated.Status,
		Changed:     changed,
		Source:      "local_sor_keys",
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	})
}

func httpStatusForDashboardKeyStatusError(err error) int {
	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	switch {
	case strings.Contains(msg, "key_not_found"):
		return http.StatusNotFound
	case strings.Contains(msg, "invalid key status"):
		return http.StatusBadRequest
	case strings.Contains(msg, "key_status_transition_disallowed"):
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}

func normalizeDashboardKeyStatusFilter(raw string) string {
	status, ok := normalizeLocalSORKeyStatus(raw)
	if !ok {
		return ""
	}
	return status
}

func normalizeDashboardKeySort(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "created_at_asc":
		return "created_at_asc"
	case "status_asc":
		return "status_asc"
	case "status_desc":
		return "status_desc"
	default:
		return "created_at_desc"
	}
}

func writeDashboardKeysCSV(w http.ResponseWriter, filename string, items []localSORKeyRecord) {
	if strings.TrimSpace(filename) == "" {
		filename = "dashboard-keys.csv"
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{
		"tenant_id",
		"key_id",
		"client_id",
		"key_purpose",
		"status",
		"fingerprint",
		"created_at",
		"rotated_at",
		"revoked_at",
		"compromise_flag",
	})
	for _, item := range items {
		_ = cw.Write([]string{
			item.TenantID,
			item.KeyID,
			item.ClientID,
			item.KeyPurpose,
			item.Status,
			item.Fingerprint,
			item.CreatedAt,
			item.RotatedAt,
			item.RevokedAt,
			strconv.FormatBool(item.CompromiseFlag),
		})
	}
	cw.Flush()
}
