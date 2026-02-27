package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type dashboardOptions struct {
	Addr string
	JSON bool
}

type dashboardSnapshot struct {
	SchemaVersion    int                              `json:"schema_version"`
	GeneratedAt      string                           `json:"generated_at"`
	RootKey          dashboardRootKeyStatus           `json:"root_key"`
	Unlock           unlockTokenVerification          `json:"unlock"`
	Lock             dashboardLockStatus              `json:"lock"`
	Danger           dashboardDangerStatus            `json:"danger"`
	Policy           dashboardPolicyStatus            `json:"policy"`
	EventSync        dashboardEventSyncStatus         `json:"event_sync"`
	Audit            dashboardAuditStatus             `json:"audit"`
	Receipts         []dashboardVerificationRecord    `json:"receipts"`
	ControlPlane     dashboardControlPlaneStatus      `json:"control_plane"`
	Clients          dashboardClientSnapshot          `json:"clients"`
	Keys             dashboardKeySnapshot             `json:"keys"`
	SignatureHolders dashboardSignatureHolderSnapshot `json:"signature_holders"`
	KeyRepair        dashboardKeyRepairSnapshot       `json:"key_repair"`
	Incidents        dashboardIncidentStatus          `json:"incidents"`
	KPI              dashboardKPIStatus               `json:"kpi"`
	Alerts           dashboardAlertStatus             `json:"alerts"`
}

type dashboardRootKeyStatus struct {
	BaseDir           string   `json:"base_dir"`
	ToolsLock         string   `json:"tools_lock"`
	ToolsLockSig      string   `json:"tools_lock_sig"`
	RootPubKey        string   `json:"root_pubkey"`
	MissingFiles      []string `json:"missing_files,omitempty"`
	GPGAvailable      bool     `json:"gpg_available"`
	ActualFingerprint string   `json:"actual_fingerprint,omitempty"`
	AllowedPins       []string `json:"allowed_pins,omitempty"`
	PinSource         string   `json:"pin_source,omitempty"`
	PinMatch          bool     `json:"pin_match"`
	PinError          string   `json:"pin_error,omitempty"`
	SignatureVerified bool     `json:"signature_verified"`
	SignatureError    string   `json:"signature_error,omitempty"`
}

type dashboardPolicyStatus struct {
	OverallSetConsistency string             `json:"overall_set_consistency"`
	OverallFreshnessState string             `json:"overall_freshness_state"`
	CriticalKinds         []string           `json:"critical_kinds,omitempty"`
	SyncErrorCode         string             `json:"sync_error_code,omitempty"`
	Extension             policyStatusResult `json:"extension"`
	Scan                  policyStatusResult `json:"scan"`
	Error                 string             `json:"error,omitempty"`
}

type dashboardEventSyncStatus struct {
	SpoolDir               string `json:"spool_dir"`
	ControlPlaneConfigured bool   `json:"control_plane_configured"`
	ControlPlaneURL        string `json:"control_plane_url,omitempty"`
	PendingCount           int    `json:"pending_count"`
	RetryableCount         int    `json:"retryable_count"`
	FailClosedCount        int    `json:"fail_closed_count"`
	OldestPendingAgeSec    int64  `json:"oldest_pending_age_seconds"`
	NextRetryAt            string `json:"next_retry_at,omitempty"`
	Error                  string `json:"error,omitempty"`
}

type dashboardAuditStatus struct {
	Path         string                      `json:"path"`
	Present      bool                        `json:"present"`
	TotalCount   int                         `json:"total_count"`
	InvalidCount int                         `json:"invalid_count"`
	LastEventAt  string                      `json:"last_event_at,omitempty"`
	Recent       []dashboardAuditEventRecord `json:"recent"`
	Error        string                      `json:"error,omitempty"`
}

type dashboardAuditEventRecord struct {
	EventID        string `json:"event_id"`
	EventType      string `json:"event_type"`
	Timestamp      string `json:"timestamp"`
	Result         string `json:"result"`
	SignatureKeyID string `json:"signature_key_id,omitempty"`
}

type dashboardVerificationRecord struct {
	Path           string `json:"path"`
	ReceiptID      string `json:"receipt_id"`
	VerifiedAt     string `json:"verified_at"`
	Client         string `json:"client"`
	PolicyResult   string `json:"policy_result"`
	SignatureValid bool   `json:"signature_valid"`
	TamperDetected bool   `json:"tamper_detected"`
}

type dashboardLockStatus struct {
	Path       string `json:"path"`
	Locked     bool   `json:"locked"`
	Reason     string `json:"reason,omitempty"`
	LockedAt   string `json:"locked_at,omitempty"`
	UpdatedAt  string `json:"updated_at,omitempty"`
	UpdatedBy  string `json:"updated_by,omitempty"`
	UnlockedAt string `json:"unlocked_at,omitempty"`
	Error      string `json:"error,omitempty"`
}

type dashboardDangerStatus struct {
	Level   string                `json:"level"`
	Count   int                   `json:"count"`
	Signals []dashboardDangerItem `json:"signals,omitempty"`
}

type dashboardDangerItem struct {
	Level   string `json:"level"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func runDashboardCommand(repoRoot string, args []string) error {
	opts, err := parseDashboardArgs(args)
	if err != nil {
		return err
	}
	listenAddr := normalizeDashboardListenAddr(opts.Addr)
	if opts.JSON {
		s := collectDashboardSnapshotWithListenAddr(repoRoot, time.Now().UTC(), listenAddr)
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(s)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(r.URL.Path)), "/api/") {
			http.NotFound(w, r)
			return
		}
		serveDashboardUI(w, r)
	})
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		s := collectDashboardSnapshotWithListenAddr(repoRoot, time.Now().UTC(), listenAddr)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(s)
	})
	mux.HandleFunc("/api/lock", func(w http.ResponseWriter, r *http.Request) {
		handleDashboardLockAPI(repoRoot, listenAddr, w, r)
	})
	mux.HandleFunc("/api/incident", func(w http.ResponseWriter, r *http.Request) {
		handleDashboardIncidentAPI(repoRoot, listenAddr, w, r)
	})
	mux.HandleFunc("/api/alerts/dispatch", func(w http.ResponseWriter, r *http.Request) {
		handleDashboardAlertDispatchAPI(repoRoot, listenAddr, w, r)
	})
	mux.HandleFunc("/api/clients", func(w http.ResponseWriter, r *http.Request) {
		handleDashboardClientsAPI(repoRoot, w, r)
	})
	mux.HandleFunc("/api/clients/", func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/api/clients/")
		rest = strings.TrimSpace(strings.Trim(rest, "/"))
		if rest == "" {
			handleDashboardClientsAPI(repoRoot, w, r)
			return
		}
		parts := strings.Split(rest, "/")
		clientID := strings.TrimSpace(parts[0])
		if len(parts) == 2 && strings.EqualFold(strings.TrimSpace(parts[1]), "signature-holders") {
			handleDashboardClientSignatureHoldersAPI(repoRoot, clientID, w, r)
			return
		}
		handleDashboardClientDetailAPI(repoRoot, clientID, w, r)
	})
	mux.HandleFunc("/api/keys", func(w http.ResponseWriter, r *http.Request) {
		handleDashboardKeysAPI(repoRoot, w, r)
	})
	mux.HandleFunc("/api/keys/", func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/api/keys/")
		rest = strings.TrimSpace(strings.Trim(rest, "/"))
		if rest == "" {
			handleDashboardKeysAPI(repoRoot, w, r)
			return
		}
		parts := strings.Split(rest, "/")
		keyID := strings.TrimSpace(parts[0])
		if len(parts) == 2 && strings.EqualFold(strings.TrimSpace(parts[1]), "status") {
			handleDashboardKeyStatusAPI(repoRoot, listenAddr, keyID, w, r)
			return
		}
		handleDashboardKeyDetailAPI(repoRoot, keyID, w, r)
	})
	mux.HandleFunc("/api/key-repair/jobs", func(w http.ResponseWriter, r *http.Request) {
		handleDashboardKeyRepairJobsAPI(repoRoot, listenAddr, w, r)
	})
	mux.HandleFunc("/api/key-repair/jobs/", func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/api/key-repair/jobs/")
		rest = strings.TrimSpace(strings.Trim(rest, "/"))
		if rest == "" {
			handleDashboardKeyRepairJobsAPI(repoRoot, listenAddr, w, r)
			return
		}
		parts := strings.Split(rest, "/")
		jobID := strings.TrimSpace(parts[0])
		if len(parts) == 2 && strings.EqualFold(strings.TrimSpace(parts[1]), "transition") {
			handleDashboardKeyRepairJobTransitionAPI(repoRoot, listenAddr, jobID, w, r)
			return
		}
		handleDashboardKeyRepairJobDetailAPI(repoRoot, jobID, w, r)
	})
	mux.HandleFunc("/api/kpi", func(w http.ResponseWriter, r *http.Request) {
		handleDashboardKPIAPI(repoRoot, w, r)
	})
	mux.HandleFunc("/api/signature-holders", func(w http.ResponseWriter, r *http.Request) {
		handleDashboardSignatureHoldersAPI(repoRoot, w, r)
	})
	mux.HandleFunc("/api/files/holders", func(w http.ResponseWriter, r *http.Request) {
		handleDashboardFileHoldersAPI(repoRoot, w, r)
	})
	mux.HandleFunc("/api/files/holders/timeseries", func(w http.ResponseWriter, r *http.Request) {
		handleDashboardFileHoldersTimelineAPI(repoRoot, w, r)
	})
	mux.HandleFunc("/api/saas/config", func(w http.ResponseWriter, r *http.Request) {
		handleDashboardSaaSConfigAPI(w, r)
	})
	mux.HandleFunc("/api/saas/economics", func(w http.ResponseWriter, r *http.Request) {
		handleDashboardSaaSEconomicsAPI(w, r)
	})
	mux.HandleFunc("/api/saas/stripe-price", func(w http.ResponseWriter, r *http.Request) {
		handleDashboardSaaSStripePriceAPI(w, r)
	})
	mux.HandleFunc("/api/saas/economics/quote.pdf", func(w http.ResponseWriter, r *http.Request) {
		handleDashboardSaaSQuotePDFAPI(w, r)
	})
	mux.HandleFunc("/api/auth/providers", func(w http.ResponseWriter, r *http.Request) {
		handleDashboardSSOProvidersAPI(w, r)
	})
	mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		handleDashboardSSOLoginAPI(w, r)
	})
	mux.HandleFunc("/api/auth/callback", func(w http.ResponseWriter, r *http.Request) {
		handleDashboardSSOCallbackAPI(w, r)
	})

	fmt.Printf("[DASHBOARD] listening on http://%s\n", listenAddr)
	return http.ListenAndServe(listenAddr, mux)
}

func parseDashboardArgs(args []string) (dashboardOptions, error) {
	fs := flagSet("dashboard")
	var opts dashboardOptions
	fs.StringVar(&opts.Addr, "addr", dashboardDefaultListenAddr, "Listen address")
	fs.BoolVar(&opts.JSON, "json", false, "Emit JSON snapshot instead of serving UI")
	if err := fs.Parse(args); err != nil {
		return dashboardOptions{}, err
	}
	if len(fs.Args()) != 0 {
		return dashboardOptions{}, fmt.Errorf(cliDashboardUsage)
	}
	return opts, nil
}

func handleDashboardLockAPI(repoRoot, listenAddr string, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if ok, _ := requireDashboardMutationAuth(w, r, listenAddr); !ok {
		return
	}
	defer r.Body.Close()
	var req struct {
		Action string `json:"action"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil && err != io.EOF {
		http.Error(w, fmt.Sprintf("invalid JSON: %v", err), http.StatusBadRequest)
		return
	}
	action := strings.ToLower(strings.TrimSpace(req.Action))
	var locked bool
	switch action {
	case "lock", "on", "enable":
		locked = true
	case "unlock", "off", "disable":
		locked = false
	default:
		http.Error(w, "action must be lock|unlock", http.StatusBadRequest)
		return
	}
	state, err := writeLocalOperationLock(repoRoot, locked, req.Reason, "dashboard", time.Now().UTC())
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to update local lock: %v", err), http.StatusInternalServerError)
		return
	}
	recordAction := "unlock"
	if state.Locked {
		recordAction = "lock"
	}
	_ = appendDashboardIncidentRecord(repoRoot, dashboardIncidentRecord{
		Action:    recordAction,
		Reason:    req.Reason,
		Actor:     "dashboard",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	out := dashboardLockStatus{
		Path:       state.Path,
		Locked:     state.Locked,
		Reason:     state.Reason,
		LockedAt:   state.LockedAt,
		UnlockedAt: state.UnlockedAt,
		UpdatedAt:  state.UpdatedAt,
		UpdatedBy:  state.UpdatedBy,
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}

func handleDashboardIncidentAPI(repoRoot, listenAddr string, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if ok, _ := requireDashboardMutationAuth(w, r, listenAddr); !ok {
		return
	}
	defer r.Body.Close()
	var req struct {
		Action     string `json:"action"`
		Reason     string `json:"reason"`
		IncidentID string `json:"incident_id"`
		ApprovedBy string `json:"approved_by"`
		ExpiresAt  string `json:"expires_at"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&req); err != nil && err != io.EOF {
		http.Error(w, fmt.Sprintf("invalid JSON: %v", err), http.StatusBadRequest)
		return
	}
	action := strings.ToLower(strings.TrimSpace(req.Action))
	switch action {
	case "lock", "unlock", "break_glass_start", "break_glass_end", "break-glass-start", "break-glass-end":
	default:
		http.Error(w, "action must be lock|unlock|break_glass_start|break_glass_end", http.StatusBadRequest)
		return
	}
	if strings.HasPrefix(action, "break") && strings.TrimSpace(req.Reason) == "" {
		http.Error(w, "reason is required for break-glass incident operations", http.StatusBadRequest)
		return
	}
	if err := appendDashboardIncidentRecord(repoRoot, dashboardIncidentRecord{
		Action:     action,
		Reason:     req.Reason,
		IncidentID: req.IncidentID,
		ApprovedBy: req.ApprovedBy,
		ExpiresAt:  req.ExpiresAt,
		Actor:      "dashboard",
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		http.Error(w, fmt.Sprintf("failed to append incident record: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(map[string]any{
		"ok":           true,
		"action":       action,
		"incident_id":  strings.TrimSpace(req.IncidentID),
		"recorded_at":  time.Now().UTC().Format(time.RFC3339),
		"audit_path":   dashboardIncidentAuditPath(repoRoot),
		"next_runbook": "docs/OPERATIONS.md",
	})
}

func handleDashboardAlertDispatchAPI(repoRoot, listenAddr string, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if ok, reason := requireDashboardMutationAuth(w, r, listenAddr); !ok {
		channel, dryRun := parseDashboardAlertDispatchAuditFields(r)
		alert := collectDashboardSnapshotWithListenAddr(repoRoot, time.Now().UTC(), listenAddr).Alerts
		_ = appendDashboardAlertDispatchAudit(repoRoot, "rejected", reason, channel, "", dryRun, alert)
		return
	}
	defer r.Body.Close()
	var req dashboardAlertDispatchRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&req); err != nil && err != io.EOF {
		http.Error(w, fmt.Sprintf("invalid JSON: %v", err), http.StatusBadRequest)
		return
	}
	alert := collectDashboardSnapshotWithListenAddr(repoRoot, time.Now().UTC(), listenAddr).Alerts
	out, err := dispatchDashboardAlerts(repoRoot, alert, req)
	if err != nil {
		writeDashboardClientJSON(w, http.StatusForbidden, map[string]any{"error": strings.TrimSpace(err.Error())})
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}

func parseDashboardAlertDispatchAuditFields(r *http.Request) (string, bool) {
	if r == nil || r.Body == nil {
		return "", false
	}
	var req struct {
		Channel string `json:"channel"`
		DryRun  bool   `json:"dry_run"`
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 1024))
	if err := dec.Decode(&req); err != nil && err != io.EOF {
		return "", false
	}
	return strings.TrimSpace(req.Channel), req.DryRun
}

func collectDashboardSnapshot(repoRoot string, now time.Time) dashboardSnapshot {
	return collectDashboardSnapshotWithListenAddr(repoRoot, now, "")
}

func collectDashboardSnapshotWithListenAddr(repoRoot string, now time.Time, listenAddr string) dashboardSnapshot {
	root, unlock := collectDashboardRootKeyStatus(repoRoot, now)
	lock := collectDashboardLockStatus(repoRoot)
	policy := collectDashboardPolicyStatus(repoRoot, now)
	eventSync := collectDashboardEventSyncStatus(repoRoot, now)
	audit := collectDashboardAuditStatus(repoRoot, 20)
	receipts := collectDashboardReceipts(repoRoot, 20)
	ingestDashboardReceiptsToLocalSOR(repoRoot, receipts, now)
	clients := collectDashboardClientSnapshot(repoRoot, now)
	keys := collectDashboardKeySnapshot(repoRoot, now)
	signatureHolders := collectDashboardSignatureHolderSnapshot(repoRoot, now)
	keyRepair := collectDashboardKeyRepairSnapshot(repoRoot, now)
	danger := collectDashboardDangerStatus(root, unlock, lock, policy, eventSync, audit, receipts, keys, keyRepair, signatureHolders)
	controlPlane := collectDashboardControlPlaneStatus(repoRoot, now)
	incidents := collectDashboardIncidentStatus(repoRoot, now, 30)
	if incidents.ActiveBreakGlass {
		msg := "break-glass mode is active"
		if strings.TrimSpace(incidents.BreakGlassUntil) != "" {
			msg += " until " + strings.TrimSpace(incidents.BreakGlassUntil)
		}
		danger.Signals = append(danger.Signals, dashboardDangerItem{
			Level:   "high",
			Code:    "break_glass_active",
			Message: msg,
		})
		danger.Level = "high"
		danger.Count = len(danger.Signals)
	}
	applyDashboardExternalDispatchGuardrail(&danger)
	applyDashboardMutationGuardrail(&danger, listenAddr)
	kpi := collectDashboardKPIStatus(repoRoot, danger, eventSync, audit, receipts, controlPlane, now)
	alerts := collectDashboardAlertStatus(danger, eventSync, incidents, kpi, controlPlane)
	return dashboardSnapshot{
		SchemaVersion:    7,
		GeneratedAt:      now.Format(time.RFC3339),
		RootKey:          root,
		Unlock:           unlock,
		Lock:             lock,
		Danger:           danger,
		Policy:           policy,
		EventSync:        eventSync,
		Audit:            audit,
		Receipts:         receipts,
		ControlPlane:     controlPlane,
		Clients:          clients,
		Keys:             keys,
		SignatureHolders: signatureHolders,
		KeyRepair:        keyRepair,
		Incidents:        incidents,
		KPI:              kpi,
		Alerts:           alerts,
	}
}

func applyDashboardExternalDispatchGuardrail(danger *dashboardDangerStatus) {
	if danger == nil {
		return
	}
	if !envBool("ZT_DASHBOARD_ALERT_DISPATCH_ENABLED") {
		return
	}
	if len(parseDashboardAlertAllowHosts(os.Getenv("ZT_DASHBOARD_ALERT_WEBHOOK_ALLOW_HOSTS"))) > 0 {
		return
	}
	for _, sig := range danger.Signals {
		if strings.EqualFold(strings.TrimSpace(sig.Code), "dashboard_alert_dispatch_unsafe_config") {
			return
		}
	}
	danger.Signals = append(danger.Signals, dashboardDangerItem{
		Level:   "high",
		Code:    "dashboard_alert_dispatch_unsafe_config",
		Message: "external alert dispatch is enabled but ZT_DASHBOARD_ALERT_WEBHOOK_ALLOW_HOSTS is empty",
	})
	danger.Level = "high"
	danger.Count = len(danger.Signals)
}

func applyDashboardMutationGuardrail(danger *dashboardDangerStatus, listenAddr string) {
	if danger == nil {
		return
	}
	if !dashboardRemoteMutationLockActive(listenAddr) {
		return
	}
	for _, sig := range danger.Signals {
		if strings.EqualFold(strings.TrimSpace(sig.Code), "dashboard_remote_bind_mutation_locked") {
			return
		}
	}
	danger.Signals = append(danger.Signals, dashboardDangerItem{
		Level:   "high",
		Code:    "dashboard_remote_bind_mutation_locked",
		Message: "dashboard is bound to non-loopback address without ZT_DASHBOARD_MUTATION_TOKEN; mutating APIs are locked",
	})
	danger.Level = "high"
	danger.Count = len(danger.Signals)
}

func collectDashboardRootKeyStatus(repoRoot string, now time.Time) (dashboardRootKeyStatus, unlockTokenVerification) {
	info, err := inspectSecurePackSupplyChainFiles(repoRoot)
	out := dashboardRootKeyStatus{
		BaseDir:      info.BaseDir,
		ToolsLock:    info.ToolsLock,
		ToolsLockSig: info.ToolsLockSig,
		RootPubKey:   info.RootPubKey,
		MissingFiles: append([]string(nil), info.Missing...),
	}
	unlock, unlockErr := loadUnlockRootPinOverrides(repoRoot, now)
	if unlockErr != nil && unlock.Reason == "" {
		unlock.Reason = unlockErr.Error()
	}
	if !unlock.Present {
		unlock.Path = resolveUnlockTokenPath(repoRoot)
	}
	if err != nil {
		out.PinError = err.Error()
		return out, unlock
	}

	_, gpgErr := exec.LookPath("gpg")
	out.GPGAvailable = gpgErr == nil
	basePins, source, pinErr := resolveSecurePackRootPubKeyFingerprintPinsWithSource()
	effectivePins, source, mergedUnlock := mergeRootPinsWithUnlockToken(repoRoot, basePins, source, now)
	if mergedUnlock != nil {
		unlock = *mergedUnlock
	}
	out.AllowedPins = effectivePins
	out.PinSource = source
	if pinErr != nil {
		out.PinError = pinErr.Error()
	}
	if !out.GPGAvailable {
		return out, unlock
	}
	if _, err := os.Stat(info.RootPubKey); err == nil {
		if fp, err := readRootPubKeyFingerprint(info.RootPubKey); err == nil {
			out.ActualFingerprint = fp
			out.PinMatch = fingerprintPinned(fp, effectivePins)
		} else {
			out.PinError = err.Error()
		}
	}
	if len(info.Missing) == 0 {
		if err := verifySecurePackToolsLockSignature(info.ToolsLockSig, info.ToolsLock, info.RootPubKey); err == nil {
			out.SignatureVerified = true
		} else {
			out.SignatureError = err.Error()
		}
	}
	return out, unlock
}

func collectDashboardPolicyStatus(repoRoot string, now time.Time) dashboardPolicyStatus {
	ext, extErr := loadPolicyStatusForKind(repoRoot, "extension", now)
	scan, scanErr := loadPolicyStatusForKind(repoRoot, "scan", now)
	store := newPolicyActivationStore(repoRoot)
	overallSet, _ := computePolicySetConsistencyWithReason(store)
	overallFreshness, criticalKinds := computeOverallPolicyFreshness(ext, scan)
	syncErr := policySyncErrorCodeNone
	if ext.SyncError != policySyncErrorCodeNone {
		syncErr = ext.SyncError
	}
	if scan.SyncError != policySyncErrorCodeNone {
		syncErr = scan.SyncError
	}
	out := dashboardPolicyStatus{
		OverallSetConsistency: overallSet,
		OverallFreshnessState: overallFreshness,
		CriticalKinds:         criticalKinds,
		SyncErrorCode:         syncErr,
		Extension:             ext,
		Scan:                  scan,
	}
	if extErr != nil || scanErr != nil {
		if extErr != nil {
			out.Error = extErr.Error()
		} else {
			out.Error = scanErr.Error()
		}
	}
	return out
}

func collectDashboardEventSyncStatus(repoRoot string, now time.Time) dashboardEventSyncStatus {
	spoolDir := strings.TrimSpace(os.Getenv("ZT_EVENT_SPOOL_DIR"))
	if spoolDir == "" {
		spoolDir = filepath.Join(repoRoot, ".zt-spool")
	}
	out := dashboardEventSyncStatus{
		SpoolDir: spoolDir,
	}

	if cpEvents != nil {
		out.ControlPlaneURL = strings.TrimSpace(cpEvents.cfg.BaseURL)
	}
	if out.ControlPlaneURL == "" {
		out.ControlPlaneURL = strings.TrimSpace(os.Getenv("ZT_CONTROL_PLANE_URL"))
	}
	out.ControlPlaneConfigured = out.ControlPlaneURL != ""

	pendingPath := filepath.Join(spoolDir, "pending.jsonl")
	items, err := readQueuedEvents(pendingPath)
	if err != nil && !os.IsNotExist(err) {
		out.Error = err.Error()
		return out
	}
	var res syncResult
	populateSyncBacklogMetrics(&res, items, now)
	out.PendingCount = res.PendingCount
	out.RetryableCount = res.RetryableCount
	out.FailClosedCount = res.FailClosedCount
	out.OldestPendingAgeSec = res.OldestPendingAgeSeconds
	out.NextRetryAt = res.NextRetryAt
	return out
}

func collectDashboardLockStatus(repoRoot string) dashboardLockStatus {
	lock, err := loadLocalOperationLock(repoRoot)
	out := dashboardLockStatus{
		Path:       lock.Path,
		Locked:     lock.Locked,
		Reason:     lock.Reason,
		LockedAt:   lock.LockedAt,
		UnlockedAt: lock.UnlockedAt,
		UpdatedAt:  lock.UpdatedAt,
		UpdatedBy:  lock.UpdatedBy,
	}
	if err != nil {
		out.Error = err.Error()
	}
	return out
}

func collectDashboardDangerStatus(
	root dashboardRootKeyStatus,
	unlock unlockTokenVerification,
	lock dashboardLockStatus,
	policy dashboardPolicyStatus,
	eventSync dashboardEventSyncStatus,
	audit dashboardAuditStatus,
	receipts []dashboardVerificationRecord,
	keys dashboardKeySnapshot,
	keyRepair dashboardKeyRepairSnapshot,
	signatureHolders dashboardSignatureHolderSnapshot,
) dashboardDangerStatus {
	signals := make([]dashboardDangerItem, 0, 16)
	add := func(level, code, message string) {
		signals = append(signals, dashboardDangerItem{
			Level:   strings.TrimSpace(level),
			Code:    strings.TrimSpace(code),
			Message: strings.TrimSpace(message),
		})
	}

	if lock.Error != "" {
		add("high", "local_lock_state_invalid", lock.Error)
	}
	if lock.Locked {
		msg := "local lock is active"
		if strings.TrimSpace(lock.Reason) != "" {
			msg += " (" + strings.TrimSpace(lock.Reason) + ")"
		}
		add("high", "local_lock_active", msg)
	}
	if len(root.MissingFiles) > 0 {
		add("high", "secure_pack_supply_chain_files_missing", "required secure-pack files are missing: "+strings.Join(root.MissingFiles, ","))
	}
	if root.PinError != "" {
		add("high", "root_pin_error", root.PinError)
	}
	if root.ActualFingerprint != "" && len(root.AllowedPins) > 0 && !root.PinMatch {
		add("high", "root_pin_mismatch", "ROOT_PUBKEY fingerprint does not match allowed pins")
	}
	if !root.GPGAvailable {
		add("medium", "gpg_unavailable", "gpg not available; detached signature verification cannot run")
	}
	if len(root.MissingFiles) == 0 && !root.SignatureVerified {
		msg := "tools.lock signature is not verified"
		if strings.TrimSpace(root.SignatureError) != "" {
			msg += ": " + strings.TrimSpace(root.SignatureError)
		}
		add("high", "tools_lock_signature_unverified", msg)
	}

	if policy.OverallSetConsistency != "" && policy.OverallSetConsistency != policySetConsistencyConsistent {
		add("high", "policy_set_inconsistent", "policy set consistency="+policy.OverallSetConsistency)
	}
	if policy.OverallFreshnessState == policyFreshnessCritical {
		add("high", "policy_freshness_critical", "policy freshness is critical")
	}
	if policy.Error != "" {
		add("medium", "policy_status_error", policy.Error)
	}
	if eventSync.FailClosedCount > 0 {
		add("high", "event_sync_fail_closed_backlog", fmt.Sprintf("fail-closed backlog=%d", eventSync.FailClosedCount))
	} else if eventSync.PendingCount > 0 {
		add("medium", "event_sync_pending_backlog", fmt.Sprintf("pending backlog=%d", eventSync.PendingCount))
	}
	if eventSync.Error != "" {
		add("medium", "event_sync_error", eventSync.Error)
	}
	if audit.Error != "" {
		add("high", "audit_error", audit.Error)
	}
	if audit.InvalidCount > 0 {
		add("high", "audit_invalid_records", fmt.Sprintf("invalid audit records=%d", audit.InvalidCount))
	}
	for _, r := range receipts {
		if r.TamperDetected {
			add("high", "receipt_tamper_detected", "tamper detected at "+r.Path)
			continue
		}
		if !r.SignatureValid {
			add("high", "receipt_signature_invalid", "signature invalid at "+r.Path)
		}
	}
	if strings.TrimSpace(keys.Error) != "" {
		add("medium", "key_lifecycle_snapshot_error", keys.Error)
	}
	if keys.CompromisedCount > 0 {
		add("high", "local_sor_keys_compromised", fmt.Sprintf("compromised keys=%d", keys.CompromisedCount))
	}
	if strings.TrimSpace(keyRepair.Error) != "" {
		add("medium", "key_repair_snapshot_error", keyRepair.Error)
	}
	if keyRepair.OpenJobs > 0 {
		add("high", "key_repair_in_progress", fmt.Sprintf("open key repair jobs=%d", keyRepair.OpenJobs))
	}
	if signatureHolders.RealtimeSLOSeconds > 0 && !signatureHolders.RealtimeSLOMet {
		add(
			"medium",
			"signature_holders_realtime_slo_breached",
			fmt.Sprintf(
				"delayed signatures=%d max_lag=%ds slo=%ds",
				signatureHolders.RealtimeDelayedCount,
				signatureHolders.RealtimeMaxLagSeconds,
				signatureHolders.RealtimeSLOSeconds,
			),
		)
	}
	switch unlock.Badge {
	case "pending":
		add("medium", "unlock_pending", "unlock token exists but approvals are insufficient")
	case "expired":
		add("medium", "unlock_expired", "unlock token is expired")
	case "inactive":
		add("medium", "unlock_inactive", "unlock token is inactive; verify trusted signer config")
	}

	level := "low"
	for _, s := range signals {
		switch s.Level {
		case "high":
			level = "high"
		case "medium":
			if level != "high" {
				level = "medium"
			}
		}
	}
	if len(signals) == 0 {
		signals = append(signals, dashboardDangerItem{
			Level:   "low",
			Code:    "healthy",
			Message: "no critical danger signals",
		})
	}
	return dashboardDangerStatus{
		Level:   level,
		Count:   len(signals),
		Signals: signals,
	}
}

func collectDashboardAuditStatus(repoRoot string, limit int) dashboardAuditStatus {
	path := defaultAuditEventsPath(repoRoot)
	out := dashboardAuditStatus{Path: path, Recent: make([]dashboardAuditEventRecord, 0, limit)}
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

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		out.TotalCount++
		var rec auditEventRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			out.InvalidCount++
			continue
		}
		if rec.Timestamp > out.LastEventAt {
			out.LastEventAt = rec.Timestamp
		}
		item := dashboardAuditEventRecord{
			EventID:        rec.EventID,
			EventType:      rec.EventType,
			Timestamp:      rec.Timestamp,
			Result:         rec.Result,
			SignatureKeyID: rec.SignatureKeyID,
		}
		if len(out.Recent) < limit {
			out.Recent = append(out.Recent, item)
		} else {
			copy(out.Recent, out.Recent[1:])
			out.Recent[len(out.Recent)-1] = item
		}
	}
	if err := sc.Err(); err != nil {
		out.Error = err.Error()
	}
	sort.Slice(out.Recent, func(i, j int) bool { return out.Recent[i].Timestamp > out.Recent[j].Timestamp })
	return out
}

func collectDashboardReceipts(repoRoot string, limit int) []dashboardVerificationRecord {
	var candidates []string
	rootMatches, _ := filepath.Glob(filepath.Join(repoRoot, "receipt*.json"))
	candidates = append(candidates, rootMatches...)
	candidates = append(candidates, walkReceiptJSON(filepath.Join(repoRoot, "receipt"), 3)...)
	candidates = append(candidates, walkReceiptJSON(filepath.Join(repoRoot, ".zt-spool"), 4)...)

	seen := map[string]struct{}{}
	records := make([]dashboardVerificationRecord, 0, limit)
	for _, p := range candidates {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		rec, ok := parseDashboardReceipt(p)
		if !ok {
			continue
		}
		records = append(records, rec)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].VerifiedAt > records[j].VerifiedAt })
	if len(records) > limit {
		records = records[:limit]
	}
	return records
}

func walkReceiptJSON(root string, maxDepth int) []string {
	root = strings.TrimSpace(root)
	if root == "" {
		return nil
	}
	var out []string
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr == nil && rel != "." {
			depth := strings.Count(rel, string(os.PathSeparator)) + 1
			if d.IsDir() && depth > maxDepth {
				return filepath.SkipDir
			}
		}
		if d.IsDir() {
			return nil
		}
		if strings.ToLower(filepath.Ext(path)) != ".json" {
			return nil
		}
		name := strings.ToLower(filepath.Base(path))
		if strings.Contains(name, "receipt") {
			out = append(out, path)
		}
		return nil
	})
	return out
}

func parseDashboardReceipt(path string) (dashboardVerificationRecord, bool) {
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return dashboardVerificationRecord{}, false
	}
	if !strings.Contains(string(data), `"receipt_version"`) {
		return dashboardVerificationRecord{}, false
	}
	var receipt verificationReceipt
	if err := json.Unmarshal(data, &receipt); err != nil {
		return dashboardVerificationRecord{}, false
	}
	if strings.TrimSpace(receipt.ReceiptVersion) == "" || strings.TrimSpace(receipt.ReceiptID) == "" {
		return dashboardVerificationRecord{}, false
	}
	return dashboardVerificationRecord{
		Path:           path,
		ReceiptID:      receipt.ReceiptID,
		VerifiedAt:     receipt.VerifiedAt,
		Client:         receipt.Provenance.Client,
		PolicyResult:   receipt.Verification.PolicyResult,
		SignatureValid: receipt.Verification.SignatureValid,
		TamperDetected: receipt.Verification.TamperDetected,
	}, true
}

func flagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}
