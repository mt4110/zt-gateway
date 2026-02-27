package main

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

func (s *server) handleDashboardActivityGroups(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}
	if s.db == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "postgres_not_configured",
			"note":  "dashboard activity groups endpoint requires ZT_CP_POSTGRES_DSN",
		})
		return
	}

	scope, tenantID, err := s.resolveDashboardAccess(r, r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeDashboardAuthzError(w, err)
		return
	}

	groupBy := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("group_by")))
	if groupBy != "tenant" && groupBy != "kind" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_group_by"})
		return
	}
	sortBy := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("sort")))
	if sortBy == "" {
		sortBy = "count_desc"
	}
	switch sortBy {
	case "count_desc", "count_asc", "key_asc", "key_desc":
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_sort"})
		return
	}
	topN, topNSet, err := parsePositiveIntQuery(r, "top_n", 1000)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_top_n"})
		return
	}
	if !topNSet {
		if v, ok, err := parsePositiveIntQuery(r, "limit", 1000); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_limit"})
			return
		} else if ok {
			topN = v
			topNSet = true
		}
	}
	includeZero, _, err := parseBoolQuery(r, "include_zero")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_include_zero"})
		return
	}
	kindFilters, err := parseDashboardKindsQuery(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_kind"})
		return
	}
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

	whereClauses := make([]string, 0, 6)
	args := make([]any, 0, 8)
	if tenantID != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("envelope_tenant_id = $%d", len(args)+1))
		args = append(args, tenantID)
	}
	if len(kindFilters) > 0 {
		holders := make([]string, 0, len(kindFilters))
		for _, k := range kindFilters {
			args = append(args, k)
			holders = append(holders, fmt.Sprintf("$%d", len(args)))
		}
		whereClauses = append(whereClauses, "kind in ("+strings.Join(holders, ",")+")")
	}
	if fromSet {
		whereClauses = append(whereClauses, fmt.Sprintf("received_at >= $%d", len(args)+1))
		args = append(args, fromTime)
	} else {
		whereClauses = append(whereClauses, "received_at >= now() - interval '24 hours'")
	}
	if toSet {
		whereClauses = append(whereClauses, fmt.Sprintf("received_at <= $%d", len(args)+1))
		args = append(args, toTime)
	}

	groupExpr := "kind"
	if groupBy == "tenant" {
		groupExpr = "coalesce(envelope_tenant_id,'')"
	}
	query := "select " + groupExpr + " as g, count(*)::bigint from event_ingest\n"
	if len(whereClauses) > 0 {
		query += "where " + strings.Join(whereClauses, " and ") + "\n"
	}
	query += "group by g\n"

	rows, err := s.db.QueryContext(r.Context(), query, args...)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "dashboard_group_query_failed"})
		return
	}
	defer rows.Close()

	type groupItem struct {
		Key   string
		Count int64
	}
	grouped := make([]groupItem, 0)
	var total int64
	for rows.Next() {
		var key string
		var count int64
		if err := rows.Scan(&key, &count); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "dashboard_group_scan_failed"})
			return
		}
		total += count
		grouped = append(grouped, groupItem{Key: key, Count: count})
	}
	if includeZero && groupBy == "kind" {
		seen := map[string]struct{}{}
		for _, gi := range grouped {
			seen[gi.Key] = struct{}{}
		}
		for _, k := range []string{"scan", "artifact", "verify"} {
			if _, ok := seen[k]; !ok {
				grouped = append(grouped, groupItem{Key: k, Count: 0})
			}
		}
	}
	sort.Slice(grouped, func(i, j int) bool {
		a, b := grouped[i], grouped[j]
		switch sortBy {
		case "count_asc":
			if a.Count != b.Count {
				return a.Count < b.Count
			}
			return a.Key < b.Key
		case "key_asc":
			if a.Key != b.Key {
				return a.Key < b.Key
			}
			return a.Count > b.Count
		case "key_desc":
			if a.Key != b.Key {
				return a.Key > b.Key
			}
			return a.Count > b.Count
		default: // count_desc
			if a.Count != b.Count {
				return a.Count > b.Count
			}
			return a.Key < b.Key
		}
	})
	truncated := false
	if topNSet && topN >= 0 && len(grouped) > topN {
		grouped = grouped[:topN]
		truncated = true
	}
	items := make([]map[string]any, 0, len(grouped))
	for _, gi := range grouped {
		items = append(items, map[string]any{"key": gi.Key, "count": gi.Count})
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
		"group_by":          groupBy,
		"items":             items,
		"total_events":      total,
		"returned_groups":   len(items),
		"sort":              sortBy,
		"top_n":             topN,
		"truncated":         truncated,
		"include_zero":      includeZero,
		"tenant_id":         tenantID,
		"kind":              firstOrEmpty(kindFilters),
		"kinds":             kindFilters,
		"kind_filter_state": kindFilterState(kindFilters),
		"window":            window,
		"source":            "event_ingest",
		"generated_at":      time.Now().UTC().Format(time.RFC3339),
		"authz":             scope,
		"tenant_isolation": map[string]any{
			"enforced":             scope.Enforced,
			"cross_tenant_allowed": scope.Role == dashboardRoleAdmin,
			"effective_tenant_id":  tenantID,
		},
	})
}
