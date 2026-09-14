package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"zt-control-plane-api/internal/eventkeyspec"
)

func (s *server) handleAdminEventKeyHistory(w http.ResponseWriter, r *http.Request, keyID string) {
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "key_id_required"})
		return
	}
	limit, set, err := parsePositiveIntQuery(r, "limit", 500)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_limit"})
		return
	}
	if !set {
		limit = 50
	}
	actionFilters := parseRepeatedCSVQuery(r, "action")
	for i := range actionFilters {
		actionFilters[i] = strings.ToLower(strings.TrimSpace(actionFilters[i]))
		if actionFilters[i] == "" || !eventkeyspec.IsValidAuditAction(actionFilters[i]) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_action"})
			return
		}
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
	whereClauses := []string{"key_id = $1"}
	args := []any{keyID}
	if len(actionFilters) > 0 {
		holders := make([]string, 0, len(actionFilters))
		for _, a := range actionFilters {
			args = append(args, a)
			holders = append(holders, fmt.Sprintf("$%d", len(args)))
		}
		whereClauses = append(whereClauses, "action in ("+strings.Join(holders, ",")+")")
	}
	if fromSet {
		args = append(args, fromTime)
		whereClauses = append(whereClauses, fmt.Sprintf("occurred_at >= $%d", len(args)))
	}
	if toSet {
		args = append(args, toTime)
		whereClauses = append(whereClauses, fmt.Sprintf("occurred_at <= $%d", len(args)))
	}
	args = append(args, limit)
	query := `
select audit_id, key_id, action, coalesce(tenant_id,''), enabled, coalesce(source,''), coalesce(updated_by,''), coalesce(update_reason,''), coalesce(meta_json::text,''), occurred_at
from event_signing_key_audit
where ` + strings.Join(whereClauses, " and ") + `
order by occurred_at desc, audit_id desc
limit $` + fmt.Sprintf("%d", len(args))
	rows, err := s.db.QueryContext(r.Context(), query, args...)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "event_key_history_query_failed"})
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var auditID int64
		var rowKeyID, action, tenantID, source, updatedBy, reason, metaJSON string
		var enabled sql.NullBool
		var occurredAt time.Time
		if err := rows.Scan(&auditID, &rowKeyID, &action, &tenantID, &enabled, &source, &updatedBy, &reason, &metaJSON, &occurredAt); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "event_key_history_scan_failed"})
			return
		}
		item := map[string]any{
			"audit_id":    auditID,
			"key_id":      rowKeyID,
			"action":      action,
			"tenant_id":   tenantID,
			"source":      source,
			"updated_by":  updatedBy,
			"reason":      reason,
			"occurred_at": occurredAt.UTC().Format(time.RFC3339),
		}
		if enabled.Valid {
			item["enabled"] = enabled.Bool
		}
		if strings.TrimSpace(metaJSON) != "" {
			var meta any
			if err := json.Unmarshal([]byte(metaJSON), &meta); err == nil {
				item["meta"] = meta
			} else {
				item["meta_raw"] = metaJSON
			}
		}
		items = append(items, item)
	}
	window := map[string]any{"mode": "all"}
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
		"key_id":  keyID,
		"items":   items,
		"count":   len(items),
		"limit":   limit,
		"action":  firstOrEmpty(actionFilters),
		"actions": actionFilters,
		"window":  window,
	})
}

func (s *server) handleAdminEventKeysGet(w http.ResponseWriter, r *http.Request, keyIDInPath string) {
	if keyIDInPath != "" {
		row := s.db.QueryRowContext(r.Context(), `
select key_id, coalesce(tenant_id,''), coalesce(alg,''), public_key_b64, enabled, source, created_at, updated_at, coalesce(updated_by,''), coalesce(update_reason,'')
from event_signing_keys
where key_id = $1
`, keyIDInPath)
		var e eventKeyRegistryEntry
		var enabled bool
		var source string
		var createdAt, updatedAt time.Time
		if err := row.Scan(&e.KeyID, &e.TenantID, &e.Alg, &e.PublicKeyB64, &enabled, &source, &createdAt, &updatedAt, &e.UpdatedBy, &e.UpdateReason); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				writeJSON(w, http.StatusNotFound, map[string]any{"error": "event_key_not_found", "key_id": keyIDInPath})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "event_key_lookup_failed"})
			return
		}
		e.Enabled = &enabled
		item := publicEventKeyEntry(e)
		item["source"] = source
		item["created_at"] = createdAt.UTC().Format(time.RFC3339)
		item["updated_at"] = updatedAt.UTC().Format(time.RFC3339)
		writeJSON(w, http.StatusOK, map[string]any{"item": item})
		return
	}

	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	rows, err := s.db.QueryContext(r.Context(), `
select key_id, coalesce(tenant_id,''), coalesce(alg,''), public_key_b64, enabled, source, created_at, updated_at, coalesce(updated_by,''), coalesce(update_reason,'')
from event_signing_keys
where ($1 = '' or tenant_id = $1)
order by tenant_id asc nulls first, key_id asc
`, tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "event_key_list_failed"})
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var e eventKeyRegistryEntry
		var enabled bool
		var source string
		var createdAt, updatedAt time.Time
		if err := rows.Scan(&e.KeyID, &e.TenantID, &e.Alg, &e.PublicKeyB64, &enabled, &source, &createdAt, &updatedAt, &e.UpdatedBy, &e.UpdateReason); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "event_key_list_scan_failed"})
			return
		}
		e.Enabled = &enabled
		item := publicEventKeyEntry(e)
		item["source"] = source
		item["created_at"] = createdAt.UTC().Format(time.RFC3339)
		item["updated_at"] = updatedAt.UTC().Format(time.RFC3339)
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":     items,
		"tenant_id": tenantID,
		"count":     len(items),
	})
}
