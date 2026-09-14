package main

import (
	"net/http"
	"strings"
	"time"
)

type dashboardModelSnapshot struct {
	TenantID      string                     `json:"tenant_id,omitempty"`
	TotalModels   int                        `json:"total_models"`
	TotalCapsules int                        `json:"total_capsules"`
	Recent        []localSORModelAssetRecord `json:"recent,omitempty"`
	Error         string                     `json:"error,omitempty"`
}

type dashboardModelsListResponse struct {
	TenantID    string                     `json:"tenant_id"`
	Q           string                     `json:"q,omitempty"`
	Page        int                        `json:"page"`
	PageSize    int                        `json:"page_size"`
	Total       int                        `json:"total"`
	TotalPages  int                        `json:"total_pages"`
	NextPage    int                        `json:"next_page"`
	Items       []localSORModelAssetRecord `json:"items"`
	Source      string                     `json:"source"`
	GeneratedAt string                     `json:"generated_at"`
}

func collectDashboardModelSnapshot(repoRoot string, now time.Time) dashboardModelSnapshot {
	if localSOR == nil || localSOR.db == nil {
		return dashboardModelSnapshot{Error: "local_sor_unavailable"}
	}
	tenantID, code := resolveDashboardClientTenantScope(repoRoot, "")
	if code != "" {
		return dashboardModelSnapshot{Error: code}
	}
	items, total, err := localSOR.listModelAssets(tenantID, "", 5, 0, false)
	if err != nil {
		return dashboardModelSnapshot{TenantID: tenantID, Error: err.Error()}
	}
	metrics, err := localSOR.collectModelInventoryMetrics(tenantID, now)
	if err != nil {
		return dashboardModelSnapshot{TenantID: tenantID, TotalModels: total, Recent: items, Error: err.Error()}
	}
	return dashboardModelSnapshot{
		TenantID:      tenantID,
		TotalModels:   metrics.TotalModels,
		TotalCapsules: metrics.TotalCapsules,
		Recent:        items,
	}
}

func handleDashboardModelsAPI(repoRoot string, w http.ResponseWriter, r *http.Request) {
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
	page := parseDashboardPositiveInt(r.URL.Query().Get("page"), 1, 100000)
	pageSize := parseDashboardPositiveInt(r.URL.Query().Get("page_size"), 20, 200)
	offset := (page - 1) * pageSize
	items, total, err := localSOR.listModelAssets(tenantID, q, pageSize, offset, false)
	if err != nil {
		writeDashboardClientJSON(w, http.StatusInternalServerError, map[string]any{"error": "models_query_failed"})
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
	writeDashboardClientJSON(w, http.StatusOK, dashboardModelsListResponse{
		TenantID:    tenantID,
		Q:           q,
		Page:        page,
		PageSize:    pageSize,
		Total:       total,
		TotalPages:  totalPages,
		NextPage:    nextPage,
		Items:       items,
		Source:      "local_sor_models",
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	})
}
