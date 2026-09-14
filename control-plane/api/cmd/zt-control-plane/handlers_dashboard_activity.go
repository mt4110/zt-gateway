package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	dashboardActivityDefaultPageSize = 20
	dashboardActivityMaxPageSize     = 200
)

func (s *server) handleDashboardActivity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}
	if s.db == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "postgres_not_configured",
			"note":  "dashboard activity endpoint requires ZT_CP_POSTGRES_DSN",
		})
		return
	}

	scope, tenantID, err := s.resolveDashboardAccess(r, r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeDashboardAuthzError(w, err)
		return
	}

	kindFilters, err := parseDashboardKindsQuery(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_kind"})
		return
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	fromTime, fromSet, err := parseDashboardTimeParam(r.URL.Query().Get("from"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_from"})
		return
	}
	toTime, toSet, err := parseDashboardTimeParam(r.URL.Query().Get("to"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_to"})
		return
	}
	if fromSet && toSet && toTime.Before(fromTime) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_time_range"})
		return
	}

	pageSize := dashboardActivityDefaultPageSize
	if v, ok, err := parsePositiveIntQuery(r, "page_size", dashboardActivityMaxPageSize); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_page_size"})
		return
	} else if ok {
		pageSize = v
	}
	if v, ok, err := parsePositiveIntQuery(r, "limit", dashboardActivityMaxPageSize); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_limit"})
		return
	} else if ok {
		pageSize = v
	}
	pageSize = normalizeDashboardActivityPageSize(pageSize)
	page := 1
	if v, ok, err := parsePositiveIntQuery(r, "page", 50000); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_page"})
		return
	} else if ok {
		page = v
	}
	offset := (page - 1) * pageSize

	sortBy := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("sort")))
	switch sortBy {
	case "", "received_at_desc":
		sortBy = "received_at_desc"
	case "received_at_asc":
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_sort"})
		return
	}

	exportMode := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("export")))
	exportCSV := exportMode == "csv"
	if exportMode != "" && !exportCSV {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_export"})
		return
	}

	whereClauses := make([]string, 0, 8)
	args := make([]any, 0, 10)
	if len(kindFilters) > 0 {
		holders := make([]string, 0, len(kindFilters))
		for _, k := range kindFilters {
			args = append(args, k)
			holders = append(holders, fmt.Sprintf("$%d", len(args)))
		}
		whereClauses = append(whereClauses, "kind in ("+strings.Join(holders, ",")+")")
	}
	if tenantID != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("envelope_tenant_id = $%d", len(args)+1))
		args = append(args, tenantID)
	}
	if fromSet {
		whereClauses = append(whereClauses, fmt.Sprintf("received_at >= $%d", len(args)+1))
		args = append(args, fromTime)
	}
	if toSet {
		whereClauses = append(whereClauses, fmt.Sprintf("received_at <= $%d", len(args)+1))
		args = append(args, toTime)
	}
	if q != "" {
		args = append(args, "%"+q+"%")
		needleArg := fmt.Sprintf("$%d", len(args))
		whereClauses = append(whereClauses,
			"(coalesce(event_id,'') ilike "+needleArg+" or coalesce(envelope_tenant_id,'') ilike "+needleArg+" or coalesce(envelope_key_id,'') ilike "+needleArg+")")
	}

	baseFrom := "from event_ingest\n"
	if len(whereClauses) > 0 {
		baseFrom += "where " + strings.Join(whereClauses, " and ") + "\n"
	}

	var total int64
	if err := s.db.QueryRowContext(r.Context(), "select count(*)::bigint\n"+baseFrom, args...).Scan(&total); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "dashboard_count_failed"})
		return
	}

	type recentRow struct {
		IngestID         string    `json:"ingest_id"`
		Kind             string    `json:"kind"`
		EventID          string    `json:"event_id,omitempty"`
		EnvelopeTenantID string    `json:"envelope_tenant_id,omitempty"`
		EnvelopeKeyID    string    `json:"envelope_key_id,omitempty"`
		EnvelopePresent  bool      `json:"envelope_present"`
		EnvelopeVerified bool      `json:"envelope_verified"`
		SignatureAnomaly bool      `json:"signature_anomaly"`
		ReceivedAt       time.Time `json:"received_at"`
	}

	recentSQL := `
select ingest_id, kind, coalesce(event_id,''), coalesce(envelope_tenant_id,''), coalesce(envelope_key_id,''), envelope_present, envelope_verified, received_at
` + baseFrom
	if sortBy == "received_at_asc" {
		recentSQL += "order by received_at asc, ingest_id asc\n"
	} else {
		recentSQL += "order by received_at desc, ingest_id desc\n"
	}
	recentArgs := append([]any{}, args...)
	if !exportCSV {
		recentSQL += fmt.Sprintf("limit $%d offset $%d\n", len(recentArgs)+1, len(recentArgs)+2)
		recentArgs = append(recentArgs, pageSize, offset)
	}

	rows, err := s.db.QueryContext(r.Context(), recentSQL, recentArgs...)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "dashboard_query_failed"})
		return
	}
	defer rows.Close()

	recent := make([]recentRow, 0)
	tenantLeakDropped := 0
	for rows.Next() {
		var rr recentRow
		if err := rows.Scan(&rr.IngestID, &rr.Kind, &rr.EventID, &rr.EnvelopeTenantID, &rr.EnvelopeKeyID, &rr.EnvelopePresent, &rr.EnvelopeVerified, &rr.ReceivedAt); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "dashboard_scan_failed"})
			return
		}
		if tenantID != "" && strings.TrimSpace(rr.EnvelopeTenantID) != "" && strings.TrimSpace(rr.EnvelopeTenantID) != tenantID {
			tenantLeakDropped++
			continue
		}
		rr.SignatureAnomaly = rr.EnvelopePresent && !rr.EnvelopeVerified
		recent = append(recent, rr)
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "dashboard_scan_failed"})
		return
	}

	kindCounts := map[string]int64{}
	countWhere := make([]string, 0, len(whereClauses)+1)
	countWhere = append(countWhere, whereClauses...)
	countArgs := append([]any{}, args...)
	if !fromSet {
		countWhere = append(countWhere, "received_at >= now() - interval '24 hours'")
	}
	countSQL := "select kind, count(*)::bigint\nfrom event_ingest\n"
	if len(countWhere) > 0 {
		countSQL += "where " + strings.Join(countWhere, " and ") + "\n"
	}
	countSQL += "group by kind\n"
	countRows, err := s.db.QueryContext(r.Context(), countSQL, countArgs...)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "dashboard_count_failed"})
		return
	}
	defer countRows.Close()
	for countRows.Next() {
		var kind string
		var n int64
		if err := countRows.Scan(&kind, &n); err == nil {
			kindCounts[kind] = n
		}
	}

	if exportCSV {
		csvRows := make([][]string, 0, len(recent))
		for _, rr := range recent {
			csvRows = append(csvRows, []string{
				rr.IngestID,
				rr.Kind,
				rr.EventID,
				rr.EnvelopeTenantID,
				rr.EnvelopeKeyID,
				fmt.Sprintf("%t", rr.EnvelopePresent),
				fmt.Sprintf("%t", rr.EnvelopeVerified),
				fmt.Sprintf("%t", rr.SignatureAnomaly),
				rr.ReceivedAt.UTC().Format(time.RFC3339),
			})
		}
		writeDashboardCSV(w, "dashboard-activity.csv", []string{
			"ingest_id", "kind", "event_id", "tenant_id", "key_id", "envelope_present", "envelope_verified", "signature_anomaly", "received_at",
		}, csvRows)
		return
	}

	totalPages := 0
	if total > 0 {
		totalPages = int((total + int64(pageSize) - 1) / int64(pageSize))
	}
	nextPage := 0
	if totalPages > page {
		nextPage = page + 1
	}

	window := map[string]any{"mode": "last_24h"}
	if fromSet || toSet {
		window["mode"] = "custom"
	}
	if fromSet {
		window["from"] = fromTime.UTC().Format(time.RFC3339)
	}
	if toSet {
		window["to"] = toTime.UTC().Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"total_events":      total,
		"last_24h_counts":   kindCounts,
		"recent":            recent,
		"limit":             pageSize,
		"page":              page,
		"page_size":         pageSize,
		"offset":            offset,
		"total_pages":       totalPages,
		"next_page":         nextPage,
		"sort":              sortBy,
		"q":                 q,
		"kind":              firstOrEmpty(kindFilters),
		"kinds":             kindFilters,
		"kind_filter_state": kindFilterState(kindFilters),
		"tenant_id":         tenantID,
		"window":            window,
		"source":            "event_ingest",
		"generated_at":      time.Now().UTC().Format(time.RFC3339),
		"authz":             scope,
		"tenant_isolation": map[string]any{
			"enforced":             scope.Enforced,
			"cross_tenant_allowed": scope.Role == dashboardRoleAdmin,
			"effective_tenant_id":  tenantID,
			"dropped_leak_rows":    tenantLeakDropped,
		},
	})
}

func normalizeDashboardActivityPageSize(pageSize int) int {
	if pageSize <= 0 {
		return dashboardActivityDefaultPageSize
	}
	if pageSize > dashboardActivityMaxPageSize {
		return dashboardActivityMaxPageSize
	}
	return pageSize
}
