package main

import (
	"encoding/csv"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type dashboardSignatureHolderSnapshot struct {
	TenantID                 string                          `json:"tenant_id,omitempty"`
	TotalSignatures          int                             `json:"total_signatures"`
	TotalEstimatedHolders    int                             `json:"total_estimated_holders"`
	TotalConfirmedHolders    int                             `json:"total_confirmed_holders"`
	ConfirmedCoverageRatio   float64                         `json:"confirmed_coverage_ratio"`
	EstimatedVsConfirmedMode string                          `json:"estimated_vs_confirmed_mode"`
	RealtimeSLOSeconds       int64                           `json:"realtime_slo_seconds"`
	RealtimeMaxLagSeconds    int64                           `json:"realtime_max_lag_seconds"`
	RealtimeDelayedCount     int                             `json:"realtime_delayed_signatures"`
	RealtimeSLOMet           bool                            `json:"realtime_slo_met"`
	Recent                   []localSORSignatureHolderRecord `json:"recent,omitempty"`
	Error                    string                          `json:"error,omitempty"`
}

type dashboardSignatureHoldersListResponse struct {
	TenantID    string                          `json:"tenant_id"`
	ClientID    string                          `json:"client_id,omitempty"`
	Q           string                          `json:"q,omitempty"`
	Page        int                             `json:"page"`
	PageSize    int                             `json:"page_size"`
	Total       int                             `json:"total"`
	TotalPages  int                             `json:"total_pages"`
	NextPage    int                             `json:"next_page"`
	Sort        string                          `json:"sort"`
	Items       []localSORSignatureHolderRecord `json:"items"`
	Source      string                          `json:"source"`
	GeneratedAt string                          `json:"generated_at"`
}

func collectDashboardSignatureHolderSnapshot(repoRoot string, now time.Time) dashboardSignatureHolderSnapshot {
	if localSOR == nil || localSOR.db == nil {
		return dashboardSignatureHolderSnapshot{Error: "local_sor_unavailable"}
	}
	tenantID, code := resolveDashboardClientTenantScope(repoRoot, "")
	if code != "" {
		return dashboardSignatureHolderSnapshot{Error: code}
	}
	items, total, err := localSOR.listSignatureHolders(tenantID, "", "holder_desc", 5, 0, false)
	if err != nil {
		return dashboardSignatureHolderSnapshot{TenantID: tenantID, Error: err.Error()}
	}
	out := dashboardSignatureHolderSnapshot{
		TenantID:        tenantID,
		TotalSignatures: total,
		Recent:          items,
		RealtimeSLOMet:  true,
	}
	for _, item := range items {
		out.TotalEstimatedHolders += item.HolderCountEstimated
		out.TotalConfirmedHolders += item.HolderCountConfirmed
	}
	out.ConfirmedCoverageRatio = localSORConfirmedCoverageRatio(out.TotalConfirmedHolders, out.TotalEstimatedHolders)
	out.EstimatedVsConfirmedMode = "estimated_vs_confirmed"
	if metrics, err := localSOR.collectSignatureHolderRealtimeMetrics(tenantID, now); err == nil {
		out.RealtimeSLOSeconds = metrics.SLOSeconds
		out.RealtimeMaxLagSeconds = metrics.MaxLagSeconds
		out.RealtimeDelayedCount = metrics.DelayedCount
		out.RealtimeSLOMet = metrics.SLOMet
	}
	return out
}

func handleDashboardSignatureHoldersAPI(repoRoot string, w http.ResponseWriter, r *http.Request) {
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
	sortBy := normalizeDashboardSignatureHolderSort(r.URL.Query().Get("sort"))
	page := parseDashboardPositiveInt(r.URL.Query().Get("page"), 1, 100000)
	pageSize := parseDashboardPositiveInt(r.URL.Query().Get("page_size"), 20, 200)
	offset := (page - 1) * pageSize
	exportCSV := strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("export")), "csv")

	items, total, err := localSOR.listSignatureHolders(tenantID, q, sortBy, pageSize, offset, exportCSV)
	if err != nil {
		writeDashboardClientJSON(w, http.StatusInternalServerError, map[string]any{"error": "signature_holders_query_failed"})
		return
	}
	if exportCSV {
		writeDashboardSignatureHoldersCSV(w, "dashboard-signature-holders.csv", items)
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
	writeDashboardClientJSON(w, http.StatusOK, dashboardSignatureHoldersListResponse{
		TenantID:    tenantID,
		Q:           q,
		Page:        page,
		PageSize:    pageSize,
		Total:       total,
		TotalPages:  totalPages,
		NextPage:    nextPage,
		Sort:        sortBy,
		Items:       items,
		Source:      "local_sor_signature_holders",
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	})
}

func handleDashboardClientSignatureHoldersAPI(repoRoot, clientID string, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeDashboardClientJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}
	if localSOR == nil || localSOR.db == nil {
		writeDashboardClientJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "local_sor_unavailable"})
		return
	}
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		writeDashboardClientJSON(w, http.StatusBadRequest, map[string]any{"error": "client_id_required"})
		return
	}
	tenantID, code := resolveDashboardClientTenantScope(repoRoot, r.URL.Query().Get("tenant_id"))
	if code != "" {
		writeDashboardClientJSON(w, httpStatusForDashboardClientError(code), map[string]any{"error": code})
		return
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	sortBy := normalizeDashboardSignatureHolderSort(r.URL.Query().Get("sort"))
	page := parseDashboardPositiveInt(r.URL.Query().Get("page"), 1, 100000)
	pageSize := parseDashboardPositiveInt(r.URL.Query().Get("page_size"), 20, 200)
	offset := (page - 1) * pageSize
	exportCSV := strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("export")), "csv")

	items, total, err := localSOR.listClientSignatureHolders(tenantID, clientID, q, sortBy, pageSize, offset, exportCSV)
	if err != nil {
		writeDashboardClientJSON(w, http.StatusInternalServerError, map[string]any{"error": "client_signature_holders_query_failed"})
		return
	}
	if exportCSV {
		writeDashboardSignatureHoldersCSV(w, "dashboard-client-signature-holders-"+clientID+".csv", items)
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
	writeDashboardClientJSON(w, http.StatusOK, dashboardSignatureHoldersListResponse{
		TenantID:    tenantID,
		ClientID:    clientID,
		Q:           q,
		Page:        page,
		PageSize:    pageSize,
		Total:       total,
		TotalPages:  totalPages,
		NextPage:    nextPage,
		Sort:        sortBy,
		Items:       items,
		Source:      "local_sor_signature_holders",
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	})
}

func normalizeDashboardSignatureHolderSort(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "updated_at_asc":
		return "updated_at_asc"
	case "holder_desc":
		return "holder_desc"
	case "holder_asc":
		return "holder_asc"
	case "event_desc":
		return "event_desc"
	case "event_asc":
		return "event_asc"
	default:
		return "updated_at_desc"
	}
}

func writeDashboardSignatureHoldersCSV(w http.ResponseWriter, filename string, items []localSORSignatureHolderRecord) {
	if strings.TrimSpace(filename) == "" {
		filename = "dashboard-signature-holders.csv"
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{
		"tenant_id",
		"signature_id",
		"holder_count_estimated",
		"holder_count_confirmed",
		"confirmed_coverage_ratio",
		"confirmation_status",
		"event_count",
		"client_event_count",
		"last_seen_at",
	})
	for _, item := range items {
		_ = cw.Write([]string{
			item.TenantID,
			item.SignatureID,
			strconv.Itoa(item.HolderCountEstimated),
			strconv.Itoa(item.HolderCountConfirmed),
			strconv.FormatFloat(item.ConfirmedCoverageRatio, 'f', 6, 64),
			item.ConfirmationStatus,
			strconv.Itoa(item.EventCount),
			strconv.Itoa(item.ClientEventCount),
			item.LastSeenAt,
		})
	}
	cw.Flush()
}
