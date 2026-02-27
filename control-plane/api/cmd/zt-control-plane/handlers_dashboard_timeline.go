package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

type dashboardTimeseriesBucket struct {
	BucketStart        string  `json:"bucket_start"`
	BucketEnd          string  `json:"bucket_end"`
	TotalEvents        int64   `json:"total_events"`
	VerifyEvents       int64   `json:"verify_events"`
	VerifySucceeded    int64   `json:"verify_succeeded"`
	SignatureAnomalies int64   `json:"signature_anomalies"`
	TenantDriftEvents  int64   `json:"tenant_drift_events"`
	BacklogProxyEvents int64   `json:"backlog_proxy_events"`
	SLOVerifyRatio     float64 `json:"slo_verify_ratio"`
	DriftRatio         float64 `json:"drift_ratio"`
	BacklogRatio       float64 `json:"backlog_ratio"`
}

func (s *server) handleDashboardTimeseries(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}
	if s.db == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "postgres_not_configured",
			"note":  "dashboard timeseries endpoint requires ZT_CP_POSTGRES_DSN",
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
	bucketMinutes := 15
	if v, ok, err := parsePositiveIntQuery(r, "bucket_minutes", 24*60); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_bucket_minutes"})
		return
	} else if ok {
		bucketMinutes = v
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
	now := time.Now().UTC()
	if !toSet {
		toTime = now
	}
	if !fromSet {
		fromTime = toTime.Add(-24 * time.Hour)
	}
	if toTime.Before(fromTime) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_time_range"})
		return
	}
	if toTime.Sub(fromTime) > 31*24*time.Hour {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "time_range_too_large"})
		return
	}

	whereClauses := make([]string, 0, 8)
	args := make([]any, 0, 10)
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
	whereClauses = append(whereClauses, fmt.Sprintf("received_at >= $%d", len(args)+1))
	args = append(args, fromTime)
	whereClauses = append(whereClauses, fmt.Sprintf("received_at <= $%d", len(args)+1))
	args = append(args, toTime)

	query := `
select received_at, kind, envelope_present, envelope_verified, coalesce(envelope_tenant_id,''), coalesce(payload_json->>'result','')
from event_ingest
where ` + strings.Join(whereClauses, " and ") + `
order by received_at asc
`
	rows, err := s.db.QueryContext(r.Context(), query, args...)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "dashboard_timeseries_query_failed"})
		return
	}
	defer rows.Close()

	step := time.Duration(bucketMinutes) * time.Minute
	start := truncateTimeStep(fromTime, step)
	end := truncateTimeStep(toTime, step)
	bucketMap := map[int64]*dashboardTimeseriesBucket{}
	tenantLeakDropped := 0

	for rows.Next() {
		var receivedAt time.Time
		var kind string
		var envelopePresent bool
		var envelopeVerified bool
		var envelopeTenantID string
		var result string
		if err := rows.Scan(&receivedAt, &kind, &envelopePresent, &envelopeVerified, &envelopeTenantID, &result); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "dashboard_timeseries_scan_failed"})
			return
		}
		if tenantID != "" && strings.TrimSpace(envelopeTenantID) != "" && strings.TrimSpace(envelopeTenantID) != tenantID {
			tenantLeakDropped++
			continue
		}
		bucketStart := truncateTimeStep(receivedAt.UTC(), step)
		k := bucketStart.Unix()
		b, ok := bucketMap[k]
		if !ok {
			b = &dashboardTimeseriesBucket{
				BucketStart: bucketStart.Format(time.RFC3339),
				BucketEnd:   bucketStart.Add(step).Format(time.RFC3339),
			}
			bucketMap[k] = b
		}
		b.TotalEvents++
		if strings.EqualFold(strings.TrimSpace(kind), "verify") {
			b.VerifyEvents++
			if strings.EqualFold(strings.TrimSpace(result), "verified") {
				b.VerifySucceeded++
			}
		}
		if envelopePresent && !envelopeVerified {
			b.SignatureAnomalies++
		}
		if strings.TrimSpace(envelopeTenantID) == "" {
			b.TenantDriftEvents++
		}
		if !envelopeVerified {
			b.BacklogProxyEvents++
		}
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "dashboard_timeseries_scan_failed"})
		return
	}

	buckets := make([]dashboardTimeseriesBucket, 0, 256)
	for ts := start; !ts.After(end); ts = ts.Add(step) {
		k := ts.Unix()
		b := bucketMap[k]
		if b == nil {
			b = &dashboardTimeseriesBucket{
				BucketStart: ts.Format(time.RFC3339),
				BucketEnd:   ts.Add(step).Format(time.RFC3339),
			}
		}
		if b.VerifyEvents > 0 {
			b.SLOVerifyRatio = float64(b.VerifySucceeded) / float64(b.VerifyEvents)
		}
		if b.TotalEvents > 0 {
			b.DriftRatio = float64(b.TenantDriftEvents) / float64(b.TotalEvents)
			b.BacklogRatio = float64(b.BacklogProxyEvents) / float64(b.TotalEvents)
		}
		buckets = append(buckets, *b)
	}
	sort.Slice(buckets, func(i, j int) bool {
		return buckets[i].BucketStart < buckets[j].BucketStart
	})

	var summaryTotal int64
	var summaryVerify int64
	var summaryVerified int64
	var summaryDrift int64
	var summaryBacklog int64
	var summarySig int64
	for _, b := range buckets {
		summaryTotal += b.TotalEvents
		summaryVerify += b.VerifyEvents
		summaryVerified += b.VerifySucceeded
		summaryDrift += b.TenantDriftEvents
		summaryBacklog += b.BacklogProxyEvents
		summarySig += b.SignatureAnomalies
	}
	summary := map[string]any{
		"total_events":                summaryTotal,
		"verify_events":               summaryVerify,
		"verify_succeeded":            summaryVerified,
		"signature_anomalies":         summarySig,
		"tenant_drift_events":         summaryDrift,
		"backlog_proxy_events":        summaryBacklog,
		"slo_verify_ratio":            safeRatio(summaryVerified, summaryVerify),
		"drift_ratio":                 safeRatio(summaryDrift, summaryTotal),
		"backlog_ratio":               safeRatio(summaryBacklog, summaryTotal),
		"backlog_proxy_note":          "control-plane has no queue state; backlog_proxy_events counts non-verified envelopes",
		"recommended_alert_threshold": 0.10,
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"tenant_id":      tenantID,
		"kind":           firstOrEmpty(kindFilters),
		"kinds":          kindFilters,
		"bucket_minutes": bucketMinutes,
		"from":           fromTime.UTC().Format(time.RFC3339),
		"to":             toTime.UTC().Format(time.RFC3339),
		"buckets":        buckets,
		"summary":        summary,
		"generated_at":   now.Format(time.RFC3339),
		"source":         "event_ingest",
		"authz":          scope,
		"tenant_isolation": map[string]any{
			"enforced":             scope.Enforced,
			"cross_tenant_allowed": scope.Role == dashboardRoleAdmin,
			"effective_tenant_id":  tenantID,
			"dropped_leak_rows":    tenantLeakDropped,
		},
	})
}

func (s *server) handleDashboardDrilldown(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}
	if s.db == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "postgres_not_configured",
			"note":  "dashboard drilldown endpoint requires ZT_CP_POSTGRES_DSN",
		})
		return
	}
	requestedTenant := r.URL.Query().Get("tenant_id")
	scope, tenantID, err := s.resolveDashboardAccess(r, requestedTenant)
	if err != nil {
		writeDashboardAuthzError(w, err)
		return
	}
	eventID := strings.TrimSpace(r.URL.Query().Get("event_id"))
	ingestID := strings.TrimSpace(r.URL.Query().Get("ingest_id"))
	if eventID == "" && ingestID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "event_id_required"})
		return
	}

	where := make([]string, 0, 3)
	args := make([]any, 0, 4)
	if ingestID != "" {
		where = append(where, fmt.Sprintf("ingest_id = $%d", len(args)+1))
		args = append(args, ingestID)
	} else {
		where = append(where, fmt.Sprintf("event_id = $%d", len(args)+1))
		args = append(args, eventID)
	}
	if tenantID != "" {
		where = append(where, fmt.Sprintf("envelope_tenant_id = $%d", len(args)+1))
		args = append(args, tenantID)
	}

	query := `
select ingest_id, kind, coalesce(event_id,''), received_at, payload_json, envelope_present, envelope_verified, coalesce(envelope_tenant_id,''), coalesce(envelope_key_id,'')
from event_ingest
where ` + strings.Join(where, " and ") + `
order by received_at desc
limit 1
`
	var rowIngestID string
	var rowKind string
	var rowEventID string
	var rowReceivedAt time.Time
	var payloadRaw []byte
	var envelopePresent bool
	var envelopeVerified bool
	var envelopeTenantID string
	var envelopeKeyID string
	err = s.db.QueryRowContext(r.Context(), query, args...).Scan(
		&rowIngestID,
		&rowKind,
		&rowEventID,
		&rowReceivedAt,
		&payloadRaw,
		&envelopePresent,
		&envelopeVerified,
		&envelopeTenantID,
		&envelopeKeyID,
	)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "event_not_found"})
		return
	}
	if tenantID != "" && strings.TrimSpace(envelopeTenantID) != "" && strings.TrimSpace(envelopeTenantID) != tenantID {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "event_not_found"})
		return
	}
	payload := map[string]any{}
	_ = json.Unmarshal(payloadRaw, &payload)

	receiptID := drilldownString(payload, "receipt_id", "verification_receipt_id")
	receiptPath := drilldownString(payload, "receipt_path", "receipt")
	policyResult := drilldownString(payload, "policy_result", "result")
	policyReason := drilldownString(payload, "reason", "policy_reason")
	runbook := recommendedRunbook(rowKind, policyResult, envelopePresent && !envelopeVerified)

	writeJSON(w, http.StatusOK, map[string]any{
		"event": map[string]any{
			"ingest_id":         rowIngestID,
			"event_id":          rowEventID,
			"kind":              rowKind,
			"received_at":       rowReceivedAt.UTC().Format(time.RFC3339),
			"tenant_id":         envelopeTenantID,
			"key_id":            envelopeKeyID,
			"envelope_present":  envelopePresent,
			"envelope_verified": envelopeVerified,
			"signature_anomaly": envelopePresent && !envelopeVerified,
			"payload":           payload,
		},
		"receipt": map[string]any{
			"receipt_id": receiptID,
			"path":       receiptPath,
			"present":    receiptID != "" || receiptPath != "",
		},
		"policy": map[string]any{
			"result": policyResult,
			"reason": policyReason,
		},
		"runbook": runbook,
		"lineage": map[string]any{
			"event_id":      rowEventID,
			"receipt_id":    receiptID,
			"policy_result": policyResult,
			"runbook_id":    drilldownString(runbook, "id"),
		},
		"tenant_id":    tenantID,
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"authz":        scope,
	})
}

func truncateTimeStep(v time.Time, step time.Duration) time.Time {
	if step <= 0 {
		return v.UTC()
	}
	u := v.UTC()
	unix := u.Unix()
	stepSec := int64(step / time.Second)
	if stepSec <= 0 {
		return u
	}
	return time.Unix((unix/stepSec)*stepSec, 0).UTC()
}

func safeRatio(num, den int64) float64 {
	if den <= 0 {
		return 0
	}
	return float64(num) / float64(den)
}

func drilldownString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		v, ok := m[k]
		if !ok {
			continue
		}
		s, ok := v.(string)
		if !ok {
			continue
		}
		s = strings.TrimSpace(s)
		if s != "" {
			return s
		}
	}
	return ""
}

func recommendedRunbook(kind, result string, signatureAnomaly bool) map[string]any {
	if signatureAnomaly {
		return map[string]any{
			"id":       "rbk_signature_anomaly",
			"title":    "Signature anomaly investigation",
			"doc_path": "docs/V0.9.2_ABNORMAL_USECASES.md",
			"commands": []string{"zt config doctor --json", "zt sync --force --json"},
		}
	}
	if strings.EqualFold(strings.TrimSpace(kind), "verify") && !strings.EqualFold(strings.TrimSpace(result), "verified") {
		return map[string]any{
			"id":       "rbk_verify_failure",
			"title":    "Verification failure triage",
			"doc_path": "docs/OPERATIONS.md",
			"commands": []string{"zt verify <packet.spkg.tgz>", "zt audit verify --require-signature"},
		}
	}
	if strings.EqualFold(strings.TrimSpace(kind), "artifact") {
		return map[string]any{
			"id":       "rbk_artifact_trace",
			"title":    "Artifact trace and provenance",
			"doc_path": "docs/OPERATIONS.md",
			"commands": []string{"zt sync --force --json", "zt config doctor --json"},
		}
	}
	return map[string]any{
		"id":       "rbk_standard_observe",
		"title":    "Standard dashboard observation",
		"doc_path": "docs/OPERATIONS.md",
		"commands": []string{"zt dashboard --json", "zt config doctor --json"},
	}
}
