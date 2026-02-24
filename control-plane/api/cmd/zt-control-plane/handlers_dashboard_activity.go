package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"strings"
	"time"
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
	limit := 20
	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	kindFilter := strings.TrimSpace(r.URL.Query().Get("kind"))
	if kindFilter != "" && !isDashboardKind(kindFilter) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_kind"})
		return
	}
	kindFilter = strings.ToLower(kindFilter)
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
	if v := strings.TrimSpace(r.URL.Query().Get("limit")); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 0 && n <= 200 {
			limit = n
		}
	}

	type recentRow struct {
		Kind             string    `json:"kind"`
		EventID          string    `json:"event_id,omitempty"`
		EnvelopeTenant   string    `json:"envelope_tenant_id,omitempty"`
		EnvelopeKeyID    string    `json:"envelope_key_id,omitempty"`
		EnvelopeVerified bool      `json:"envelope_verified"`
		ReceivedAt       time.Time `json:"received_at"`
	}
	recent := make([]recentRow, 0, limit)
	recentSQL := `
select kind, coalesce(event_id,''), coalesce(envelope_tenant_id,''), coalesce(envelope_key_id,''), envelope_verified, received_at
from event_ingest
`
	recentClauses := make([]string, 0, 4)
	recentArgs := make([]any, 0, 5)
	if kindFilter != "" {
		recentClauses = append(recentClauses, fmt.Sprintf("kind = $%d", len(recentArgs)+1))
		recentArgs = append(recentArgs, kindFilter)
	}
	if tenantID != "" {
		recentClauses = append(recentClauses, fmt.Sprintf("envelope_tenant_id = $%d", len(recentArgs)+1))
		recentArgs = append(recentArgs, tenantID)
	}
	if fromSet {
		recentClauses = append(recentClauses, fmt.Sprintf("received_at >= $%d", len(recentArgs)+1))
		recentArgs = append(recentArgs, fromTime)
	}
	if toSet {
		recentClauses = append(recentClauses, fmt.Sprintf("received_at <= $%d", len(recentArgs)+1))
		recentArgs = append(recentArgs, toTime)
	}
	if len(recentClauses) > 0 {
		recentSQL += "where " + strings.Join(recentClauses, " and ") + "\n"
	}
	recentSQL += fmt.Sprintf("order by received_at desc\nlimit $%d\n", len(recentArgs)+1)
	recentArgs = append(recentArgs, limit)
	var rows *sql.Rows
	rows, err = s.db.QueryContext(r.Context(), recentSQL, recentArgs...)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "dashboard_query_failed"})
		return
	}
	defer rows.Close()
	for rows.Next() {
		var rr recentRow
		if err := rows.Scan(&rr.Kind, &rr.EventID, &rr.EnvelopeTenant, &rr.EnvelopeKeyID, &rr.EnvelopeVerified, &rr.ReceivedAt); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "dashboard_scan_failed"})
			return
		}
		recent = append(recent, rr)
	}

	kindCounts := map[string]int64{}
	countSQL := `
select kind, count(*)::bigint
from event_ingest
`
	countClauses := make([]string, 0, 4)
	countArgs := make([]any, 0, 4)
	if kindFilter != "" {
		countClauses = append(countClauses, fmt.Sprintf("kind = $%d", len(countArgs)+1))
		countArgs = append(countArgs, kindFilter)
	}
	if tenantID != "" {
		countClauses = append(countClauses, fmt.Sprintf("envelope_tenant_id = $%d", len(countArgs)+1))
		countArgs = append(countArgs, tenantID)
	}
	if fromSet {
		countClauses = append(countClauses, fmt.Sprintf("received_at >= $%d", len(countArgs)+1))
		countArgs = append(countArgs, fromTime)
	} else {
		countClauses = append(countClauses, "received_at >= now() - interval '24 hours'")
	}
	if toSet {
		countClauses = append(countClauses, fmt.Sprintf("received_at <= $%d", len(countArgs)+1))
		countArgs = append(countArgs, toTime)
	}
	if len(countClauses) > 0 {
		countSQL += "where " + strings.Join(countClauses, " and ") + "\n"
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

	var total int64
	totalSQL := `select count(*)::bigint from event_ingest`
	totalClauses := make([]string, 0, 4)
	totalArgs := make([]any, 0, 4)
	if kindFilter != "" {
		totalClauses = append(totalClauses, fmt.Sprintf("kind = $%d", len(totalArgs)+1))
		totalArgs = append(totalArgs, kindFilter)
	}
	if tenantID != "" {
		totalClauses = append(totalClauses, fmt.Sprintf("envelope_tenant_id = $%d", len(totalArgs)+1))
		totalArgs = append(totalArgs, tenantID)
	}
	if fromSet {
		totalClauses = append(totalClauses, fmt.Sprintf("received_at >= $%d", len(totalArgs)+1))
		totalArgs = append(totalArgs, fromTime)
	}
	if toSet {
		totalClauses = append(totalClauses, fmt.Sprintf("received_at <= $%d", len(totalArgs)+1))
		totalArgs = append(totalArgs, toTime)
	}
	if len(totalClauses) > 0 {
		totalSQL += " where " + strings.Join(totalClauses, " and ")
	}
	_ = s.db.QueryRowContext(r.Context(), totalSQL, totalArgs...).Scan(&total)

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
		"total_events":    total,
		"last_24h_counts": kindCounts,
		"recent":          recent,
		"limit":           limit,
		"kind":            kindFilter,
		"tenant_id":       tenantID,
		"window":          window,
		"source":          "event_ingest",
		"generated_at":    time.Now().UTC().Format(time.RFC3339),
	})
}
