package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type dashboardControlPlaneStatus struct {
	Configured  bool           `json:"configured"`
	BaseURL     string         `json:"base_url,omitempty"`
	Role        string         `json:"role,omitempty"`
	TenantID    string         `json:"tenant_id,omitempty"`
	Activity    map[string]any `json:"activity,omitempty"`
	Groups      map[string]any `json:"groups,omitempty"`
	Timeseries  map[string]any `json:"timeseries,omitempty"`
	LastError   string         `json:"last_error,omitempty"`
	GeneratedAt string         `json:"generated_at,omitempty"`
}

type dashboardKPIStatus struct {
	TenantID            string  `json:"tenant_id,omitempty"`
	ExchangeTotal       int     `json:"exchange_total"`
	SendCount           int     `json:"send_count"`
	ReceiveCount        int     `json:"receive_count"`
	VerifyReceiptsTotal int     `json:"verify_receipts_total"`
	VerifyPassCount     int     `json:"verify_pass_count"`
	VerifyFailCount     int     `json:"verify_fail_count"`
	VerifyPassRatio     float64 `json:"verify_pass_ratio"`
	AuditTotal          int     `json:"audit_total"`
	AuditInvalid        int     `json:"audit_invalid"`
	AuditInvalidRatio   float64 `json:"audit_invalid_ratio"`
	BacklogBreached     bool    `json:"backlog_breached"`
	BacklogThresholdSec int64   `json:"backlog_threshold_seconds"`
	BacklogSLOMet       bool    `json:"backlog_slo_met"`
	VerifyPassSLOTarget float64 `json:"verify_pass_slo_target"`
	VerifyPassSLOMet    bool    `json:"verify_pass_slo_met"`
	DangerHighCount     int     `json:"danger_high_count"`
	DangerMediumCount   int     `json:"danger_medium_count"`
	ControlPlaneSLO     float64 `json:"control_plane_slo_ratio,omitempty"`
	ControlPlaneBacklog float64 `json:"control_plane_backlog_ratio,omitempty"`
}

type dashboardIncidentStatus struct {
	Path             string                    `json:"path"`
	Present          bool                      `json:"present"`
	TotalCount       int                       `json:"total_count"`
	ActiveBreakGlass bool                      `json:"active_break_glass"`
	BreakGlassUntil  string                    `json:"break_glass_until,omitempty"`
	Recent           []dashboardIncidentRecord `json:"recent"`
	Error            string                    `json:"error,omitempty"`
}

type dashboardIncidentRecord struct {
	Action     string `json:"action"`
	Reason     string `json:"reason,omitempty"`
	IncidentID string `json:"incident_id,omitempty"`
	ApprovedBy string `json:"approved_by,omitempty"`
	ExpiresAt  string `json:"expires_at,omitempty"`
	Actor      string `json:"actor,omitempty"`
	Timestamp  string `json:"timestamp"`
}

type dashboardAlertStatus struct {
	Level                string               `json:"level"`
	Count                int                  `json:"count"`
	Items                []dashboardAlertItem `json:"items"`
	ExternalDispatch     bool                 `json:"external_dispatch_enabled"`
	ExternalDispatchSafe bool                 `json:"external_dispatch_safe"`
}

type dashboardAlertItem struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Source   string `json:"source"`
	Message  string `json:"message"`
}

const (
	dashboardAlertDispatchAuditEndpoint = "/v1/events/dashboard/alert-dispatch"
	dashboardAlertDispatchCommand       = "dashboard_alert_dispatch"
)

func collectDashboardControlPlaneStatus(repoRoot string, now time.Time) dashboardControlPlaneStatus {
	baseURL, apiKey, bearerToken := resolveDashboardControlPlaneClient(repoRoot)
	role := strings.TrimSpace(os.Getenv("ZT_DASHBOARD_ROLE"))
	if role == "" {
		role = "viewer"
	}
	tenantID := resolveDashboardTenantScope(repoRoot)

	out := dashboardControlPlaneStatus{
		Configured:  strings.TrimSpace(baseURL) != "",
		BaseURL:     strings.TrimSpace(baseURL),
		Role:        role,
		TenantID:    tenantID,
		GeneratedAt: now.Format(time.RFC3339),
	}
	if !out.Configured {
		return out
	}

	headers := map[string]string{}
	if strings.TrimSpace(bearerToken) != "" {
		headers["Authorization"] = "Bearer " + strings.TrimSpace(bearerToken)
	} else if strings.TrimSpace(apiKey) != "" {
		headers["X-API-Key"] = strings.TrimSpace(apiKey)
	}
	headers["X-ZT-Dashboard-Role"] = role
	if tenantID != "" {
		headers["X-ZT-Tenant-ID"] = tenantID
	}

	activityURL := strings.TrimRight(baseURL, "/") + "/v1/dashboard/activity?page_size=20&page=1&sort=received_at_desc"
	if m, err := fetchDashboardJSON(activityURL, headers); err != nil {
		out.LastError = appendDashboardError(out.LastError, err)
	} else {
		out.Activity = m
	}

	groupsURL := strings.TrimRight(baseURL, "/") + "/v1/dashboard/activity/groups?group_by=kind&include_zero=true&top_n=10"
	if m, err := fetchDashboardJSON(groupsURL, headers); err != nil {
		out.LastError = appendDashboardError(out.LastError, err)
	} else {
		out.Groups = m
	}

	timeseriesURL := strings.TrimRight(baseURL, "/") + "/v1/dashboard/timeseries?bucket_minutes=15"
	if m, err := fetchDashboardJSON(timeseriesURL, headers); err != nil {
		out.LastError = appendDashboardError(out.LastError, err)
	} else {
		out.Timeseries = m
	}
	return out
}

func fetchDashboardJSON(rawURL string, headers map[string]string) (map[string]any, error) {
	req, err := http.NewRequest(http.MethodGet, strings.TrimSpace(rawURL), nil)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		if strings.TrimSpace(v) == "" {
			continue
		}
		req.Header.Set(k, v)
	}
	client := &http.Client{Timeout: 4 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		code, _ := body["error"].(string)
		if strings.TrimSpace(code) == "" {
			code = fmt.Sprintf("http_%d", resp.StatusCode)
		}
		return nil, errors.New(code)
	}
	return body, nil
}

func resolveDashboardControlPlaneClient(repoRoot string) (string, string, string) {
	if cpEvents != nil {
		if strings.TrimSpace(cpEvents.cfg.BaseURL) != "" {
			return strings.TrimSpace(cpEvents.cfg.BaseURL), strings.TrimSpace(cpEvents.cfg.APIKey), strings.TrimSpace(os.Getenv("ZT_CONTROL_PLANE_BEARER_TOKEN"))
		}
	}
	cfg, err := loadZTClientConfig(repoRoot)
	if err != nil {
		return "", "", ""
	}
	cpURL, _ := resolveControlPlaneURL(cfg)
	apiKey, _ := resolveControlPlaneAPIKey(cfg)
	bearerToken, _ := resolveControlPlaneBearerToken(cfg)
	return cpURL, apiKey, bearerToken
}

func resolveDashboardTenantScope(repoRoot string) string {
	if v := strings.TrimSpace(os.Getenv("ZT_DASHBOARD_TENANT_ID")); v != "" {
		return v
	}
	polPath := teamBoundaryPolicyPath(repoRoot)
	if !fileExists(polPath) {
		return ""
	}
	pol, err := loadTeamBoundaryPolicy(polPath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(pol.TenantID)
}

func appendDashboardError(prev string, err error) string {
	msg := strings.TrimSpace(prev)
	next := ""
	if err != nil {
		next = strings.TrimSpace(err.Error())
	}
	if next == "" {
		return msg
	}
	if msg == "" {
		return next
	}
	return msg + "; " + next
}

func dashboardIncidentAuditPath(repoRoot string) string {
	return filepath.Join(repoRoot, ".zt-spool", "dashboard_incidents.jsonl")
}

func appendDashboardIncidentRecord(repoRoot string, record dashboardIncidentRecord) error {
	record.Action = strings.TrimSpace(strings.ToLower(record.Action))
	record.Reason = strings.TrimSpace(record.Reason)
	record.IncidentID = strings.TrimSpace(record.IncidentID)
	record.ApprovedBy = strings.TrimSpace(record.ApprovedBy)
	record.ExpiresAt = strings.TrimSpace(record.ExpiresAt)
	record.Actor = strings.TrimSpace(record.Actor)
	record.Timestamp = strings.TrimSpace(record.Timestamp)
	if record.Timestamp == "" {
		record.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	if record.Action == "" {
		return fmt.Errorf("incident action is required")
	}
	return appendJSONLine(dashboardIncidentAuditPath(repoRoot), record)
}

func collectDashboardIncidentStatus(repoRoot string, now time.Time, limit int) dashboardIncidentStatus {
	path := dashboardIncidentAuditPath(repoRoot)
	out := dashboardIncidentStatus{
		Path:   path,
		Recent: make([]dashboardIncidentRecord, 0, limit),
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return out
		}
		out.Error = err.Error()
		return out
	}
	defer f.Close()
	out.Present = true

	scanner := bufio.NewScanner(f)
	all := make([]dashboardIncidentRecord, 0, 128)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		out.TotalCount++
		var rec dashboardIncidentRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		all = append(all, rec)
	}
	if err := scanner.Err(); err != nil {
		out.Error = err.Error()
		return out
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Timestamp > all[j].Timestamp })
	if len(all) > limit {
		out.Recent = append(out.Recent, all[:limit]...)
	} else {
		out.Recent = append(out.Recent, all...)
	}
	out.ActiveBreakGlass, out.BreakGlassUntil = resolveActiveBreakGlass(all, now)
	return out
}

func resolveActiveBreakGlass(records []dashboardIncidentRecord, now time.Time) (bool, string) {
	if len(records) == 0 {
		return false, ""
	}
	asc := append([]dashboardIncidentRecord(nil), records...)
	sort.Slice(asc, func(i, j int) bool { return asc[i].Timestamp < asc[j].Timestamp })
	active := false
	until := ""
	for _, rec := range asc {
		action := strings.TrimSpace(strings.ToLower(rec.Action))
		switch action {
		case "break_glass_start", "break-glass-start":
			active = true
			until = strings.TrimSpace(rec.ExpiresAt)
		case "break_glass_end", "break-glass-end", "break_glass_revoke":
			active = false
			until = ""
		}
	}
	if !active {
		return false, ""
	}
	if until != "" {
		if t, err := time.Parse(time.RFC3339, until); err == nil {
			if !t.After(now) {
				return false, ""
			}
			return true, t.UTC().Format(time.RFC3339)
		}
	}
	return true, until
}

func collectDashboardKPIStatus(
	repoRoot string,
	danger dashboardDangerStatus,
	eventSync dashboardEventSyncStatus,
	audit dashboardAuditStatus,
	receipts []dashboardVerificationRecord,
	cp dashboardControlPlaneStatus,
) dashboardKPIStatus {
	kpi := dashboardKPIStatus{
		VerifyReceiptsTotal: len(receipts),
		AuditTotal:          audit.TotalCount,
		AuditInvalid:        audit.InvalidCount,
		BacklogThresholdSec: syncBacklogSLOSeconds(),
		VerifyPassSLOTarget: resolveDashboardVerifyPassSLOTarget(),
	}
	tenantID, code := resolveDashboardClientTenantScope(repoRoot, "")
	if code == "" && strings.TrimSpace(tenantID) != "" {
		kpi.TenantID = tenantID
		if localSOR != nil && localSOR.db != nil {
			if metrics, err := localSOR.collectExchangeMetrics(tenantID); err == nil {
				kpi.ExchangeTotal = metrics.ExchangeTotal
				kpi.SendCount = metrics.SendCount
				kpi.ReceiveCount = metrics.ReceiveCount
				kpi.VerifyReceiptsTotal = metrics.VerifyCount
				kpi.VerifyPassCount = metrics.VerifyPass
				kpi.VerifyFailCount = metrics.VerifyFail
			}
		}
	}
	if kpi.VerifyReceiptsTotal == 0 {
		for _, r := range receipts {
			if !strings.EqualFold(strings.TrimSpace(r.PolicyResult), "pass") && !(r.SignatureValid && !r.TamperDetected && strings.Contains(strings.ToLower(strings.TrimSpace(r.PolicyResult)), "pass")) {
				if !r.SignatureValid || r.TamperDetected || strings.Contains(strings.ToLower(strings.TrimSpace(r.PolicyResult)), "fail") || strings.Contains(strings.ToLower(strings.TrimSpace(r.PolicyResult)), "deny") {
					kpi.VerifyFailCount++
				}
			}
			if r.SignatureValid && !r.TamperDetected && strings.Contains(strings.ToLower(strings.TrimSpace(r.PolicyResult)), "pass") {
				kpi.VerifyPassCount++
			}
		}
		kpi.VerifyReceiptsTotal = len(receipts)
		if kpi.ExchangeTotal == 0 {
			kpi.ExchangeTotal = kpi.VerifyReceiptsTotal
		}
	}
	kpi.VerifyPassRatio = dashboardRatio(float64(kpi.VerifyPassCount), float64(kpi.VerifyReceiptsTotal))
	kpi.AuditInvalidRatio = dashboardRatio(float64(kpi.AuditInvalid), float64(kpi.AuditTotal))
	kpi.BacklogBreached = eventSync.PendingCount > 0 && eventSync.OldestPendingAgeSec > kpi.BacklogThresholdSec
	kpi.BacklogSLOMet = !kpi.BacklogBreached
	kpi.VerifyPassSLOMet = kpi.VerifyPassRatio >= kpi.VerifyPassSLOTarget

	for _, sig := range danger.Signals {
		switch strings.TrimSpace(strings.ToLower(sig.Level)) {
		case "high":
			kpi.DangerHighCount++
		case "medium":
			kpi.DangerMediumCount++
		}
	}
	if summary, ok := cp.Timeseries["summary"].(map[string]any); ok {
		kpi.ControlPlaneSLO = dashboardAnyFloat(summary["slo_verify_ratio"])
		kpi.ControlPlaneBacklog = dashboardAnyFloat(summary["backlog_ratio"])
	}
	return kpi
}

func resolveDashboardVerifyPassSLOTarget() float64 {
	raw := strings.TrimSpace(os.Getenv("ZT_DASHBOARD_SLO_VERIFY_PASS_TARGET"))
	if raw == "" {
		return 0.99
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0.99
	}
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func collectDashboardAlertStatus(
	danger dashboardDangerStatus,
	eventSync dashboardEventSyncStatus,
	incidents dashboardIncidentStatus,
	kpi dashboardKPIStatus,
	cp dashboardControlPlaneStatus,
) dashboardAlertStatus {
	items := make([]dashboardAlertItem, 0, 24)
	add := func(severity, code, source, message string) {
		items = append(items, dashboardAlertItem{
			Severity: strings.TrimSpace(strings.ToLower(severity)),
			Code:     strings.TrimSpace(code),
			Source:   strings.TrimSpace(source),
			Message:  strings.TrimSpace(message),
		})
	}

	for _, sig := range danger.Signals {
		if strings.TrimSpace(strings.ToLower(sig.Code)) == "healthy" {
			continue
		}
		add(sig.Level, sig.Code, "danger", sig.Message)
	}
	if eventSync.FailClosedCount > 0 {
		add("high", "event_sync_fail_closed_backlog", "event_sync", fmt.Sprintf("fail-closed backlog=%d", eventSync.FailClosedCount))
	}
	if kpi.BacklogBreached {
		add("medium", "sync_backlog_slo_breached", "kpi", fmt.Sprintf("oldest backlog age=%ds threshold=%ds", eventSync.OldestPendingAgeSec, kpi.BacklogThresholdSec))
	}
	if incidents.ActiveBreakGlass {
		add("high", "break_glass_active", "incident", "break-glass mode is active")
	}
	if cp.Configured && cp.LastError != "" {
		add("medium", "control_plane_dashboard_unreachable", "control_plane", cp.LastError)
	}

	level := "low"
	for _, item := range items {
		switch item.Severity {
		case "high":
			level = "high"
		case "medium":
			if level != "high" {
				level = "medium"
			}
		}
	}
	if len(items) == 0 {
		items = append(items, dashboardAlertItem{Severity: "low", Code: "healthy", Source: "dashboard", Message: "no alert conditions"})
	}

	allowHosts := parseDashboardAlertAllowHosts(os.Getenv("ZT_DASHBOARD_ALERT_WEBHOOK_ALLOW_HOSTS"))
	return dashboardAlertStatus{
		Level:                level,
		Count:                len(items),
		Items:                items,
		ExternalDispatch:     envBool("ZT_DASHBOARD_ALERT_DISPATCH_ENABLED"),
		ExternalDispatchSafe: len(allowHosts) > 0,
	}
}

func dashboardRatio(num, den float64) float64 {
	if den <= 0 {
		return 0
	}
	return num / den
}

func dashboardAnyFloat(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case float32:
		return float64(x)
	case int:
		return float64(x)
	case int64:
		return float64(x)
	case json.Number:
		f, _ := x.Float64()
		return f
	default:
		return 0
	}
}

func parseDashboardAlertAllowHosts(raw string) map[string]struct{} {
	parts := strings.Split(raw, ",")
	out := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		h := strings.ToLower(strings.TrimSpace(part))
		if h == "" {
			continue
		}
		out[h] = struct{}{}
	}
	return out
}

func appendDashboardAlertDispatchAudit(repoRoot, result, reasonCode, channel, webhookHost string, dryRun bool, alert dashboardAlertStatus) error {
	payload := map[string]any{
		"event_id":      fmt.Sprintf("evt_dashboard_alert_dispatch_%d", time.Now().UTC().UnixNano()),
		"command":       dashboardAlertDispatchCommand,
		"result":        strings.TrimSpace(result),
		"reason_code":   strings.TrimSpace(reasonCode),
		"channel":       strings.TrimSpace(strings.ToLower(channel)),
		"webhook_host":  strings.TrimSpace(strings.ToLower(webhookHost)),
		"dry_run":       dryRun,
		"alert_level":   strings.TrimSpace(strings.ToLower(alert.Level)),
		"alert_count":   alert.Count,
		"tenant_id":     resolveDashboardTenantScope(repoRoot),
		"alert_codes":   dashboardAlertCodes(alert.Items, 8),
		"recorded_from": "dashboard",
	}
	spool := cpEvents
	if spool == nil {
		spool = newEventSpool(repoRoot)
	}
	return spool.appendAuditEvent(dashboardAlertDispatchAuditEndpoint, payload)
}

func dashboardAlertCodes(items []dashboardAlertItem, max int) []string {
	if max <= 0 {
		return nil
	}
	out := make([]string, 0, max)
	seen := make(map[string]struct{}, max)
	for _, item := range items {
		code := strings.TrimSpace(item.Code)
		if code == "" {
			continue
		}
		if _, ok := seen[code]; ok {
			continue
		}
		seen[code] = struct{}{}
		out = append(out, code)
		if len(out) >= max {
			break
		}
	}
	return out
}

func dispatchDashboardAlerts(repoRoot string, alert dashboardAlertStatus, req dashboardAlertDispatchRequest) (out map[string]any, err error) {
	channel := strings.ToLower(strings.TrimSpace(req.Channel))
	if channel == "" {
		channel = "webhook"
	}
	auditResult := "rejected"
	auditReasonCode := "dispatch_rejected"
	webhookHost := ""
	defer func() {
		auditErr := appendDashboardAlertDispatchAudit(repoRoot, auditResult, auditReasonCode, channel, webhookHost, req.DryRun, alert)
		if auditErr == nil {
			return
		}
		if err == nil {
			out = nil
			err = fmt.Errorf("alert_dispatch_audit_append_failed: %w", auditErr)
			return
		}
		err = fmt.Errorf("%s (alert_dispatch_audit_append_failed: %v)", strings.TrimSpace(err.Error()), auditErr)
	}()

	if !envBool("ZT_DASHBOARD_ALERT_DISPATCH_ENABLED") {
		auditReasonCode = "external_dispatch_disabled"
		return nil, fmt.Errorf("external_dispatch_disabled")
	}
	if channel != "slack" && channel != "discord" && channel != "line" && channel != "webhook" {
		auditReasonCode = "invalid_channel"
		return nil, fmt.Errorf("invalid_channel")
	}
	webhookURL := strings.TrimSpace(req.WebhookURL)
	if webhookURL == "" {
		switch channel {
		case "slack":
			webhookURL = strings.TrimSpace(os.Getenv("ZT_DASHBOARD_ALERT_SLACK_WEBHOOK_URL"))
		case "discord":
			webhookURL = strings.TrimSpace(os.Getenv("ZT_DASHBOARD_ALERT_DISCORD_WEBHOOK_URL"))
		case "line":
			webhookURL = strings.TrimSpace(os.Getenv("ZT_DASHBOARD_ALERT_LINE_WEBHOOK_URL"))
		default:
			webhookURL = strings.TrimSpace(os.Getenv("ZT_DASHBOARD_ALERT_WEBHOOK_URL"))
		}
	}
	if webhookURL == "" {
		auditReasonCode = "webhook_url_required"
		return nil, fmt.Errorf("webhook_url_required")
	}
	u, err := url.Parse(webhookURL)
	if err != nil || strings.ToLower(strings.TrimSpace(u.Scheme)) != "https" {
		auditReasonCode = "webhook_https_required"
		return nil, fmt.Errorf("webhook_https_required")
	}
	allowHosts := parseDashboardAlertAllowHosts(os.Getenv("ZT_DASHBOARD_ALERT_WEBHOOK_ALLOW_HOSTS"))
	if len(allowHosts) == 0 {
		auditReasonCode = "webhook_allow_hosts_required"
		return nil, fmt.Errorf("webhook_allow_hosts_required")
	}
	webhookHost = strings.ToLower(strings.TrimSpace(u.Hostname()))
	if _, ok := allowHosts[webhookHost]; !ok {
		auditReasonCode = "webhook_host_not_allowed"
		return nil, fmt.Errorf("webhook_host_not_allowed")
	}

	text := buildDashboardAlertMessage(alert)
	payload := map[string]any{"text": text}
	switch channel {
	case "discord":
		payload = map[string]any{"content": text}
	case "line":
		payload = map[string]any{"message": text}
	}
	body, _ := json.Marshal(payload)
	if req.DryRun {
		auditResult = "dry_run"
		auditReasonCode = "dispatch_dry_run"
		return map[string]any{
			"ok":           true,
			"dry_run":      true,
			"channel":      channel,
			"webhook_host": webhookHost,
			"payload":      payload,
		}, nil
	}
	if err := postWebhookJSON(webhookURL, body); err != nil {
		auditResult = "failed"
		auditReasonCode = "webhook_dispatch_failed"
		return nil, err
	}
	auditResult = "sent"
	auditReasonCode = "dispatch_success"
	return map[string]any{
		"ok":           true,
		"dry_run":      false,
		"channel":      channel,
		"webhook_host": webhookHost,
		"count":        alert.Count,
		"level":        alert.Level,
	}, nil
}

func buildDashboardAlertMessage(alert dashboardAlertStatus) string {
	lines := []string{fmt.Sprintf("[zt-dashboard] level=%s count=%d", strings.ToUpper(alert.Level), alert.Count)}
	max := len(alert.Items)
	if max > 5 {
		max = 5
	}
	for i := 0; i < max; i++ {
		it := alert.Items[i]
		lines = append(lines, fmt.Sprintf("- [%s] %s (%s)", strings.ToUpper(it.Severity), it.Code, it.Source))
	}
	if len(alert.Items) > max {
		lines = append(lines, fmt.Sprintf("- ... and %d more", len(alert.Items)-max))
	}
	return strings.Join(lines, "\n")
}

type dashboardAlertDispatchRequest struct {
	Channel    string `json:"channel"`
	WebhookURL string `json:"webhook_url"`
	DryRun     bool   `json:"dry_run"`
}
