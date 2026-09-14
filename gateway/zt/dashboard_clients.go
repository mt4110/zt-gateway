package main

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type dashboardClientSnapshot struct {
	TenantID     string                  `json:"tenant_id,omitempty"`
	TotalClients int                     `json:"total_clients"`
	TotalAssets  int                     `json:"total_assets"`
	Recent       []localSORClientSummary `json:"recent,omitempty"`
	Error        string                  `json:"error,omitempty"`
}

type dashboardClientsListResponse struct {
	TenantID    string                  `json:"tenant_id"`
	Q           string                  `json:"q,omitempty"`
	Page        int                     `json:"page"`
	PageSize    int                     `json:"page_size"`
	Total       int                     `json:"total"`
	TotalPages  int                     `json:"total_pages"`
	NextPage    int                     `json:"next_page"`
	Sort        string                  `json:"sort"`
	Items       []localSORClientSummary `json:"items"`
	Source      string                  `json:"source"`
	GeneratedAt string                  `json:"generated_at"`
}

type dashboardClientDetailResponse struct {
	TenantID    string                `json:"tenant_id"`
	Client      localSORClientSummary `json:"client"`
	Q           string                `json:"q,omitempty"`
	Page        int                   `json:"page"`
	PageSize    int                   `json:"page_size"`
	TotalAssets int                   `json:"total_assets"`
	TotalPages  int                   `json:"total_pages"`
	NextPage    int                   `json:"next_page"`
	Sort        string                `json:"sort"`
	Assets      []localSORAssetRecord `json:"assets"`
	Source      string                `json:"source"`
	GeneratedAt string                `json:"generated_at"`
}

func collectDashboardClientSnapshot(repoRoot string, now time.Time) dashboardClientSnapshot {
	if localSOR == nil || localSOR.db == nil {
		return dashboardClientSnapshot{Error: "local_sor_unavailable"}
	}
	tenantID, code := resolveDashboardClientTenantScope(repoRoot, "")
	if code != "" {
		return dashboardClientSnapshot{Error: code}
	}
	items, total, err := localSOR.listClients(tenantID, "", "last_seen_desc", 5, 0, false)
	if err != nil {
		return dashboardClientSnapshot{TenantID: tenantID, Error: err.Error()}
	}
	var totalAssets int
	if err := localSOR.db.QueryRow(`select count(*) from local_sor_assets where tenant_id = ?1`, tenantID).Scan(&totalAssets); err != nil {
		for _, item := range items {
			totalAssets += item.AssetCount
		}
	}
	return dashboardClientSnapshot{
		TenantID:     tenantID,
		TotalClients: total,
		TotalAssets:  totalAssets,
		Recent:       items,
	}
}

func ingestDashboardReceiptsToLocalSOR(repoRoot string, receipts []dashboardVerificationRecord, now time.Time) {
	if localSOR == nil || localSOR.db == nil || len(receipts) == 0 {
		return
	}
	defaultTenant := strings.TrimSpace(resolveDashboardTenantScope(repoRoot))
	if defaultTenant == "" {
		defaultTenant = "local-default"
	}
	for _, rec := range receipts {
		path := strings.TrimSpace(rec.Path)
		if path == "" {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil || len(data) == 0 {
			continue
		}
		var receipt verificationReceipt
		if err := json.Unmarshal(data, &receipt); err != nil {
			continue
		}
		if strings.TrimSpace(receipt.ReceiptID) == "" || strings.TrimSpace(receipt.ReceiptVersion) == "" {
			continue
		}
		tenantID := strings.TrimSpace(receipt.Provenance.TenantID)
		if tenantID == "" {
			tenantID = defaultTenant
		}
		_ = localSOR.ingestVerificationReceipt(tenantID, receipt, now)
	}
}

func handleDashboardClientsAPI(repoRoot string, w http.ResponseWriter, r *http.Request) {
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
	sortBy := normalizeDashboardClientSort(r.URL.Query().Get("sort"))
	page := parseDashboardPositiveInt(r.URL.Query().Get("page"), 1, 100000)
	pageSize := parseDashboardPositiveInt(r.URL.Query().Get("page_size"), 20, 200)
	offset := (page - 1) * pageSize
	exportCSV := strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("export")), "csv")

	items, total, err := localSOR.listClients(tenantID, q, sortBy, pageSize, offset, exportCSV)
	if err != nil {
		writeDashboardClientJSON(w, http.StatusInternalServerError, map[string]any{"error": "clients_query_failed"})
		return
	}

	if exportCSV {
		writeDashboardClientsCSV(w, "dashboard-clients.csv", items)
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
	writeDashboardClientJSON(w, http.StatusOK, dashboardClientsListResponse{
		TenantID:    tenantID,
		Q:           q,
		Page:        page,
		PageSize:    pageSize,
		Total:       total,
		TotalPages:  totalPages,
		NextPage:    nextPage,
		Sort:        sortBy,
		Items:       items,
		Source:      "local_sor_clients",
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	})
}

func handleDashboardClientDetailAPI(repoRoot, clientID string, w http.ResponseWriter, r *http.Request) {
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

	client, ok, err := localSOR.getClient(tenantID, clientID)
	if err != nil {
		writeDashboardClientJSON(w, http.StatusInternalServerError, map[string]any{"error": "client_query_failed"})
		return
	}
	if !ok {
		writeDashboardClientJSON(w, http.StatusNotFound, map[string]any{"error": "client_not_found"})
		return
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	sortBy := normalizeDashboardAssetSort(r.URL.Query().Get("sort"))
	page := parseDashboardPositiveInt(r.URL.Query().Get("page"), 1, 100000)
	pageSize := parseDashboardPositiveInt(r.URL.Query().Get("page_size"), 20, 200)
	offset := (page - 1) * pageSize
	exportCSV := strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("export")), "csv")

	assets, totalAssets, err := localSOR.listClientAssets(tenantID, clientID, q, sortBy, pageSize, offset, exportCSV)
	if err != nil {
		writeDashboardClientJSON(w, http.StatusInternalServerError, map[string]any{"error": "client_assets_query_failed"})
		return
	}
	if exportCSV {
		writeDashboardClientAssetsCSV(w, "dashboard-client-assets-"+clientID+".csv", assets)
		return
	}
	totalPages := 0
	if totalAssets > 0 {
		totalPages = (totalAssets + pageSize - 1) / pageSize
	}
	nextPage := 0
	if page < totalPages {
		nextPage = page + 1
	}
	writeDashboardClientJSON(w, http.StatusOK, dashboardClientDetailResponse{
		TenantID:    tenantID,
		Client:      client,
		Q:           q,
		Page:        page,
		PageSize:    pageSize,
		TotalAssets: totalAssets,
		TotalPages:  totalPages,
		NextPage:    nextPage,
		Sort:        sortBy,
		Assets:      assets,
		Source:      "local_sor_assets",
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	})
}

func resolveDashboardClientTenantScope(repoRoot, requested string) (string, string) {
	requested = strings.TrimSpace(requested)
	enforced := strings.TrimSpace(resolveDashboardTenantScope(repoRoot))
	if enforced != "" {
		if requested != "" && requested != enforced {
			return "", "tenant_scope_violation"
		}
		return enforced, ""
	}
	if requested == "" {
		return "", "tenant_scope_required"
	}
	return requested, ""
}

func normalizeDashboardClientSort(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "created_at_asc":
		return "created_at_asc"
	case "last_seen_desc":
		return "last_seen_desc"
	case "last_seen_asc":
		return "last_seen_asc"
	default:
		return "created_at_desc"
	}
}

func normalizeDashboardAssetSort(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "created_at_desc":
		return "created_at_desc"
	case "created_at_asc":
		return "created_at_asc"
	case "last_seen_asc":
		return "last_seen_asc"
	default:
		return "last_seen_desc"
	}
}

func parseDashboardPositiveInt(raw string, def, max int) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		return def
	}
	if max > 0 && v > max {
		return max
	}
	return v
}

func httpStatusForDashboardClientError(code string) int {
	switch strings.TrimSpace(code) {
	case "tenant_scope_required", "tenant_scope_violation":
		return http.StatusForbidden
	default:
		return http.StatusBadRequest
	}
}

func writeDashboardClientsCSV(w http.ResponseWriter, filename string, items []localSORClientSummary) {
	if strings.TrimSpace(filename) == "" {
		filename = "dashboard-clients.csv"
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{
		"tenant_id",
		"client_id",
		"display_name",
		"status",
		"created_at",
		"updated_at",
		"asset_count",
		"last_seen_at",
		"file_exchange_count",
	})
	for _, item := range items {
		_ = cw.Write([]string{
			item.TenantID,
			item.ClientID,
			item.DisplayName,
			item.Status,
			item.CreatedAt,
			item.UpdatedAt,
			strconv.Itoa(item.AssetCount),
			item.LastSeenAt,
			strconv.Itoa(item.FileExchangeCount),
		})
	}
	cw.Flush()
}

func writeDashboardClientAssetsCSV(w http.ResponseWriter, filename string, assets []localSORAssetRecord) {
	if strings.TrimSpace(filename) == "" {
		filename = "dashboard-client-assets.csv"
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{
		"tenant_id",
		"client_id",
		"asset_id",
		"filename",
		"content_sha256",
		"location_type",
		"location_ref",
		"created_at",
		"last_seen_at",
		"access_count",
	})
	for _, item := range assets {
		_ = cw.Write([]string{
			item.TenantID,
			item.ClientID,
			item.AssetID,
			item.Filename,
			item.ContentSHA256,
			item.LocationType,
			item.LocationRef,
			item.CreatedAt,
			item.LastSeenAt,
			strconv.Itoa(item.AccessCount),
		})
	}
	cw.Flush()
}

func writeDashboardClientJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(payload)
}
