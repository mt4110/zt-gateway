package main

import (
	"encoding/csv"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type dashboardFileHoldersListResponse struct {
	TenantID    string                     `json:"tenant_id"`
	Q           string                     `json:"q,omitempty"`
	Page        int                        `json:"page"`
	PageSize    int                        `json:"page_size"`
	Total       int                        `json:"total"`
	TotalPages  int                        `json:"total_pages"`
	NextPage    int                        `json:"next_page"`
	Sort        string                     `json:"sort"`
	Items       []localSORFileHolderRecord `json:"items"`
	Source      string                     `json:"source"`
	GeneratedAt string                     `json:"generated_at"`
}

func handleDashboardFileHoldersAPI(repoRoot string, w http.ResponseWriter, r *http.Request) {
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
	sortBy := normalizeDashboardFileHolderSort(r.URL.Query().Get("sort"))
	page := parseDashboardPositiveInt(r.URL.Query().Get("page"), 1, 100000)
	pageSize := parseDashboardPositiveInt(r.URL.Query().Get("page_size"), 20, 200)
	offset := (page - 1) * pageSize
	exportCSV := strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("export")), "csv")

	items, total, err := localSOR.listFileHolders(tenantID, q, sortBy, pageSize, offset, exportCSV)
	if err != nil {
		writeDashboardClientJSON(w, http.StatusInternalServerError, map[string]any{"error": "file_holders_query_failed"})
		return
	}
	if exportCSV {
		writeDashboardFileHoldersCSV(w, "dashboard-file-holders.csv", items)
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
	writeDashboardClientJSON(w, http.StatusOK, dashboardFileHoldersListResponse{
		TenantID:    tenantID,
		Q:           q,
		Page:        page,
		PageSize:    pageSize,
		Total:       total,
		TotalPages:  totalPages,
		NextPage:    nextPage,
		Sort:        sortBy,
		Items:       items,
		Source:      "local_sor_assets+exchanges",
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	})
}

func normalizeDashboardFileHolderSort(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "last_seen_asc":
		return "last_seen_asc"
	case "holder_desc":
		return "holder_desc"
	case "holder_asc":
		return "holder_asc"
	case "exchange_desc":
		return "exchange_desc"
	case "exchange_asc":
		return "exchange_asc"
	default:
		return "last_seen_desc"
	}
}

func writeDashboardFileHoldersCSV(w http.ResponseWriter, filename string, items []localSORFileHolderRecord) {
	if strings.TrimSpace(filename) == "" {
		filename = "dashboard-file-holders.csv"
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{
		"tenant_id",
		"content_sha256",
		"filename_sample",
		"asset_count",
		"holder_client_count",
		"holder_clients",
		"signature_count",
		"exchange_count",
		"last_seen_at",
	})
	for _, item := range items {
		_ = cw.Write([]string{
			item.TenantID,
			item.ContentSHA256,
			item.FilenameSample,
			strconv.Itoa(item.AssetCount),
			strconv.Itoa(item.HolderClientCount),
			strings.Join(item.HolderClients, "|"),
			strconv.Itoa(item.SignatureCount),
			strconv.Itoa(item.ExchangeCount),
			item.LastSeenAt,
		})
	}
	cw.Flush()
}
