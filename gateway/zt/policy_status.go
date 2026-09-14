package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

type policyStatusRef struct {
	ManifestID string `json:"manifest_id,omitempty"`
	ExpiresAt  string `json:"expires_at,omitempty"`
	PolicySet  string `json:"policy_set_id,omitempty"`
}

type policyStatusResult struct {
	OK             bool            `json:"ok"`
	ErrorCode      string          `json:"error_code,omitempty"`
	SchemaVer      int             `json:"schema_version"`
	GeneratedAt    string          `json:"generated_at"`
	Command        string          `json:"command"`
	Argv           []string        `json:"argv"`
	ExitCode       int             `json:"exit_code"`
	Kind           string          `json:"kind"`
	Active         policyStatusRef `json:"active"`
	Staged         policyStatusRef `json:"staged"`
	LastKnownGood  policyStatusRef `json:"last_known_good"`
	LastSyncAt     string          `json:"last_sync_at,omitempty"`
	NextSyncAt     string          `json:"next_sync_at,omitempty"`
	SyncError      string          `json:"sync_error_code"`
	SetConsistency string          `json:"set_consistency"`
	LastSyncAgeSec int64           `json:"last_sync_age_seconds"`
	FreshnessSLO   int64           `json:"freshness_slo_seconds"`
	FreshnessState string          `json:"freshness_state"`
	QuickFixBundle *quickFixBundle `json:"quick_fix_bundle,omitempty"`
}

type policyStatusAllResult struct {
	OK                    bool               `json:"ok"`
	ErrorCode             string             `json:"error_code,omitempty"`
	SchemaVer             int                `json:"schema_version"`
	GeneratedAt           string             `json:"generated_at"`
	Command               string             `json:"command"`
	Argv                  []string           `json:"argv"`
	ExitCode              int                `json:"exit_code"`
	Kind                  string             `json:"kind"`
	Extension             policyStatusResult `json:"extension"`
	Scan                  policyStatusResult `json:"scan"`
	OverallSetConsistency string             `json:"overall_set_consistency"`
	SetConsistencyReason  string             `json:"set_consistency_reason"`
	OverallFreshnessState string             `json:"overall_freshness_state"`
	CriticalKinds         []string           `json:"critical_kinds"`
	SyncError             string             `json:"sync_error_code"`
	QuickFixBundle        *quickFixBundle    `json:"quick_fix_bundle,omitempty"`
}

const (
	policySetConsistencyUnknown      = "unknown"
	policySetConsistencyConsistent   = "consistent"
	policySetConsistencySkewDetected = "skew_detected"

	policySetConsistencyReasonNone             = "none"
	policySetConsistencyReasonUnknown          = "unknown"
	policySetConsistencyReasonMissingExtension = "missing_extension"
	policySetConsistencyReasonMissingScan      = "missing_scan"
	policySetConsistencyReasonSetIDMissing     = "set_id_missing"
	policySetConsistencyReasonSkewDetected     = "skew_detected"

	policyFreshnessFresh    = "fresh"
	policyFreshnessStale    = "stale"
	policyFreshnessCritical = "critical"
)

func runPolicyCommand(repoRoot string, args []string) error {
	if len(args) == 0 {
		printZTErrorCode(ztErrorCodePolicyUsage)
		return fmt.Errorf(cliPolicyUsage)
	}
	switch args[0] {
	case "status":
		return runPolicyStatusCommand(repoRoot, args[1:])
	default:
		printZTErrorCode(ztErrorCodePolicyUsage)
		return fmt.Errorf(cliPolicyUsage)
	}
}

func runPolicyStatusCommand(repoRoot string, args []string) error {
	fs := flag.NewFlagSet("policy status", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var jsonOut bool
	var kind string
	fs.BoolVar(&jsonOut, "json", false, "Emit machine-readable JSON output")
	fs.StringVar(&kind, "kind", "extension", "Policy kind: extension|scan|all")
	if err := fs.Parse(args); err != nil {
		printZTErrorCode(ztErrorCodePolicyUsage)
		return err
	}
	if len(fs.Args()) != 0 {
		printZTErrorCode(ztErrorCodePolicyUsage)
		return fmt.Errorf(cliPolicyStatusUsage)
	}
	normKind := strings.ToLower(strings.TrimSpace(kind))
	if normKind == "all" {
		return runPolicyStatusAllCommand(repoRoot, jsonOut)
	}
	normKind, err := normalizePolicyStateKind(kind)
	if err != nil || (normKind != "extension" && normKind != "scan") {
		printZTErrorCode(ztErrorCodePolicyUsage)
		return fmt.Errorf(cliPolicyStatusUsage)
	}
	result, err := loadPolicyStatusForKind(repoRoot, normKind, time.Now().UTC())
	if err != nil {
		if jsonOut {
			emitPolicyStatusJSON(result)
			return fmt.Errorf("policy status failed")
		}
		printZTErrorCode(result.ErrorCode)
		return err
	}
	if jsonOut && result.QuickFixBundle == nil && result.SyncError != policySyncErrorCodeNone {
		result.QuickFixBundle = buildQuickFixBundleWithCode("policy attention required", policyStatusQuickFixes(result.SyncError, normKind), fmt.Sprintf("zt policy status --kind %s --json", normKind), result.SyncError)
	}

	if !jsonOut {
		fmt.Printf("[POLICY] kind=%s\n", result.Kind)
		fmt.Printf("  active.manifest_id=%s\n", emptyIfBlank(result.Active.ManifestID, "(none)"))
		fmt.Printf("  active.expires_at=%s\n", emptyIfBlank(result.Active.ExpiresAt, "(none)"))
		fmt.Printf("  active.policy_set_id=%s\n", emptyIfBlank(result.Active.PolicySet, "(none)"))
		fmt.Printf("  staged.manifest_id=%s\n", emptyIfBlank(result.Staged.ManifestID, "(none)"))
		fmt.Printf("  last_known_good.manifest_id=%s\n", emptyIfBlank(result.LastKnownGood.ManifestID, "(none)"))
		fmt.Printf("  last_sync_at=%s\n", emptyIfBlank(result.LastSyncAt, "(none)"))
		fmt.Printf("  next_sync_at=%s\n", emptyIfBlank(result.NextSyncAt, "(none)"))
		fmt.Printf("  set_consistency=%s\n", emptyIfBlank(result.SetConsistency, policySetConsistencyUnknown))
		fmt.Printf("  freshness_state=%s\n", emptyIfBlank(result.FreshnessState, policyFreshnessCritical))
		fmt.Printf("  freshness_slo_seconds=%d\n", result.FreshnessSLO)
		fmt.Printf("  last_sync_age_seconds=%d\n", result.LastSyncAgeSec)
		fmt.Printf("  sync_error_code=%s\n", emptyIfBlank(result.SyncError, policySyncErrorCodeNone))
		return nil
	}
	emitPolicyStatusJSON(result)
	return nil
}

func runPolicyStatusAllCommand(repoRoot string, jsonOut bool) error {
	now := time.Now().UTC()
	ext, extErr := loadPolicyStatusForKind(repoRoot, "extension", now)
	scan, scanErr := loadPolicyStatusForKind(repoRoot, "scan", now)
	store := newPolicyActivationStore(repoRoot)
	setConsistency, setConsistencyReason := computePolicySetConsistencyWithReason(store)
	overallFreshness, criticalKinds := computeOverallPolicyFreshness(ext, scan)
	syncErr := policySyncErrorCodeNone
	switch {
	case setConsistency == policySetConsistencySkewDetected:
		syncErr = "policy_set_skew_detected"
	case setConsistency == policySetConsistencyUnknown && (setConsistencyReason == policySetConsistencyReasonMissingExtension || setConsistencyReason == policySetConsistencyReasonMissingScan):
		syncErr = "policy_set_missing_kind"
	case setConsistency == policySetConsistencyUnknown && setConsistencyReason == policySetConsistencyReasonSetIDMissing:
		syncErr = "policy_set_id_missing"
	case overallFreshness == policyFreshnessCritical:
		syncErr = "policy_sync_slo_breached"
	}
	result := policyStatusAllResult{
		OK:                    true,
		SchemaVer:             1,
		GeneratedAt:           now.Format(time.RFC3339),
		Command:               "zt policy status",
		Argv:                  append([]string(nil), os.Args...),
		Kind:                  "all",
		Extension:             ext,
		Scan:                  scan,
		OverallSetConsistency: setConsistency,
		SetConsistencyReason:  setConsistencyReason,
		OverallFreshnessState: overallFreshness,
		CriticalKinds:         criticalKinds,
		SyncError:             syncErr,
	}
	if extErr != nil || scanErr != nil {
		result.OK = false
		result.ErrorCode = ztErrorCodePolicyStatusFailed
		result.ExitCode = 1
		if syncErr == policySyncErrorCodeNone {
			result.SyncError = "policy_status_active_load_failed"
		}
		result.QuickFixBundle = buildQuickFixBundleWithCode("policy status failed", []string{
			"Run `zt setup --json` and fix policy health errors.",
			fmt.Sprintf("Remove/repair broken state file: %s", store.activePath("extension")),
			fmt.Sprintf("Remove/repair broken state file: %s", store.activePath("scan")),
		}, "zt policy status --kind all --json", result.SyncError)
		if jsonOut {
			emitPolicyStatusAllJSON(result)
			return fmt.Errorf("policy status failed")
		}
		printZTErrorCode(result.ErrorCode)
		if extErr != nil {
			return extErr
		}
		return scanErr
	}
	if jsonOut && result.SyncError != policySyncErrorCodeNone {
		result.QuickFixBundle = buildQuickFixBundleWithCode("policy attention required", policyStatusQuickFixes(result.SyncError, "all"), "zt policy status --kind all --json", result.SyncError)
	}
	if !jsonOut {
		fmt.Println("[POLICY] kind=all")
		fmt.Printf("  extension.set_consistency=%s\n", emptyIfBlank(ext.SetConsistency, policySetConsistencyUnknown))
		fmt.Printf("  extension.freshness_state=%s\n", emptyIfBlank(ext.FreshnessState, policyFreshnessCritical))
		fmt.Printf("  extension.sync_error_code=%s\n", emptyIfBlank(ext.SyncError, policySyncErrorCodeNone))
		fmt.Printf("  scan.set_consistency=%s\n", emptyIfBlank(scan.SetConsistency, policySetConsistencyUnknown))
		fmt.Printf("  scan.freshness_state=%s\n", emptyIfBlank(scan.FreshnessState, policyFreshnessCritical))
		fmt.Printf("  scan.sync_error_code=%s\n", emptyIfBlank(scan.SyncError, policySyncErrorCodeNone))
		fmt.Printf("  overall_set_consistency=%s\n", emptyIfBlank(result.OverallSetConsistency, policySetConsistencyUnknown))
		fmt.Printf("  set_consistency_reason=%s\n", emptyIfBlank(result.SetConsistencyReason, policySetConsistencyReasonUnknown))
		fmt.Printf("  overall_freshness_state=%s\n", emptyIfBlank(result.OverallFreshnessState, policyFreshnessCritical))
		fmt.Printf("  critical_kinds=%s\n", strings.Join(result.CriticalKinds, ","))
		fmt.Printf("  sync_error_code=%s\n", emptyIfBlank(result.SyncError, policySyncErrorCodeNone))
		return nil
	}
	emitPolicyStatusAllJSON(result)
	return nil
}

func loadPolicyStatusForKind(repoRoot, normKind string, now time.Time) (policyStatusResult, error) {
	store := newPolicyActivationStore(repoRoot)
	result := policyStatusResult{
		OK:             true,
		SchemaVer:      1,
		GeneratedAt:    now.Format(time.RFC3339),
		Command:        "zt policy status",
		Argv:           append([]string(nil), os.Args...),
		Kind:           normKind,
		SyncError:      policySyncErrorCodeNone,
		SetConsistency: policySetConsistencyUnknown,
		FreshnessState: policyFreshnessCritical,
	}
	activeProfile := trustProfileInternal
	activeFreshnessSLO := int64(0)

	if active, exists, readErr := readSignedPolicyBundleFileIfExists(store.activePath(normKind)); readErr != nil {
		result.OK = false
		result.ErrorCode = ztErrorCodePolicyStatusFailed
		result.ExitCode = 1
		result.SyncError = "policy_status_active_load_failed"
		result.QuickFixBundle = buildQuickFixBundleWithCode("policy status failed", []string{
			"Run `zt setup --json` and fix policy health errors.",
			fmt.Sprintf("Remove/repair broken state file: %s", store.activePath(normKind)),
		}, fmt.Sprintf("zt policy status --kind %s --json", normKind), result.SyncError)
		return result, readErr
	} else if exists {
		result.Active.ManifestID = active.ManifestID
		result.Active.ExpiresAt = active.ExpiresAt
		result.Active.PolicySet = strings.TrimSpace(active.PolicySetID)
		if p := strings.TrimSpace(active.Profile); p != "" {
			activeProfile = p
		}
		if active.FreshnessSLOSec > 0 {
			activeFreshnessSLO = active.FreshnessSLOSec
		}
	}
	if staged, exists, readErr := store.readStagedIfExists(normKind); readErr == nil && exists {
		result.Staged.ManifestID = staged.ManifestID
		result.Staged.PolicySet = strings.TrimSpace(staged.PolicySetID)
	}
	if lkg, exists, readErr := store.readLastKnownGoodIfExists(normKind); readErr == nil && exists {
		result.LastKnownGood.ManifestID = lkg.ManifestID
		result.LastKnownGood.PolicySet = strings.TrimSpace(lkg.PolicySetID)
	}
	if meta, err := readMetaOrDefault(store, normKind); err == nil {
		result.LastSyncAt = strings.TrimSpace(meta.LastSuccess)
		result.SyncError = strings.TrimSpace(meta.LastError)
		if result.SyncError == "" {
			result.SyncError = policySyncErrorCodeNone
		}
		if t, parseErr := time.Parse(time.RFC3339, strings.TrimSpace(meta.LastFetchAt)); parseErr == nil {
			result.NextSyncAt = t.Add(policySyncInterval()).Format(time.RFC3339)
		}
	}
	result.SetConsistency = computePolicySetConsistency(store)
	if result.SetConsistency == policySetConsistencySkewDetected {
		result.SyncError = "policy_set_skew_detected"
	}
	result.FreshnessSLO = policyStatusFreshnessSLOSeconds(activeProfile)
	if activeFreshnessSLO > 0 {
		result.FreshnessSLO = activeFreshnessSLO
	}
	result.LastSyncAgeSec, result.FreshnessState = computePolicyFreshnessState(result.LastSyncAt, result.FreshnessSLO, now)
	if result.FreshnessState == policyFreshnessCritical && result.SyncError == policySyncErrorCodeNone {
		result.SyncError = "policy_sync_slo_breached"
	}
	return result, nil
}

func policyStatusQuickFixes(syncErrorCode, kind string) []string {
	switch strings.TrimSpace(syncErrorCode) {
	case "policy_set_skew_detected", "policy_set_missing_kind", "policy_set_id_missing":
		return []string{
			"Run `zt policy status --json --kind all` and confirm extension/scan consistency.",
			"Align Control Plane publish set (`policy_set_id`) for extension/scan and run `zt sync --force --json`.",
		}
	case "policy_sync_slo_breached":
		return []string{
			"Run `zt sync --force --json` to refresh policy state.",
			fmt.Sprintf("Recheck `zt policy status --json --kind %s` and confirm freshness recovers.", kind),
		}
	default:
		return []string{
			fmt.Sprintf("Check `zt policy status --json --kind %s` and follow docs/OPERATIONS.md runbook.", kind),
		}
	}
}

func emitPolicyStatusJSON(v policyStatusResult) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func emitPolicyStatusAllJSON(v policyStatusAllResult) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func emptyIfBlank(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func computePolicySetConsistency(store *policyActivationStore) string {
	consistency, _ := computePolicySetConsistencyWithReason(store)
	return consistency
}

func computePolicySetConsistencyWithReason(store *policyActivationStore) (string, string) {
	if store == nil {
		return policySetConsistencyUnknown, policySetConsistencyReasonUnknown
	}
	ext, extExists, extErr := readSignedPolicyBundleFileIfExists(store.activePath("extension"))
	scan, scanExists, scanErr := readSignedPolicyBundleFileIfExists(store.activePath("scan"))
	if extErr != nil || scanErr != nil {
		return policySetConsistencyUnknown, policySetConsistencyReasonUnknown
	}
	if !extExists {
		return policySetConsistencyUnknown, policySetConsistencyReasonMissingExtension
	}
	if !scanExists {
		return policySetConsistencyUnknown, policySetConsistencyReasonMissingScan
	}
	extSetID := strings.TrimSpace(ext.PolicySetID)
	scanSetID := strings.TrimSpace(scan.PolicySetID)
	if extSetID == "" || scanSetID == "" {
		return policySetConsistencyUnknown, policySetConsistencyReasonSetIDMissing
	}
	if extSetID == scanSetID {
		return policySetConsistencyConsistent, policySetConsistencyReasonNone
	}
	return policySetConsistencySkewDetected, policySetConsistencyReasonSkewDetected
}

func computeOverallPolicyFreshness(ext, scan policyStatusResult) (string, []string) {
	critical := make([]string, 0, 2)
	if ext.FreshnessState == policyFreshnessCritical {
		critical = append(critical, "extension")
	}
	if scan.FreshnessState == policyFreshnessCritical {
		critical = append(critical, "scan")
	}
	switch {
	case len(critical) > 0:
		return policyFreshnessCritical, critical
	case ext.FreshnessState == policyFreshnessStale || scan.FreshnessState == policyFreshnessStale:
		return policyFreshnessStale, critical
	default:
		return policyFreshnessFresh, critical
	}
}

func policyStatusFreshnessSLOSeconds(profile string) int64 {
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case trustProfileConfidential, trustProfileRegulated:
		return int64((6 * time.Hour) / time.Second)
	default:
		return int64((24 * time.Hour) / time.Second)
	}
}

func computePolicyFreshnessState(lastSyncRaw string, sloSeconds int64, now time.Time) (int64, string) {
	if sloSeconds <= 0 {
		sloSeconds = int64((24 * time.Hour) / time.Second)
	}
	lastSync, err := time.Parse(time.RFC3339, strings.TrimSpace(lastSyncRaw))
	if err != nil {
		return 0, policyFreshnessCritical
	}
	age := now.UTC().Unix() - lastSync.UTC().Unix()
	if age < 0 {
		age = 0
	}
	switch {
	case age > (2 * sloSeconds):
		return age, policyFreshnessCritical
	case age > sloSeconds:
		return age, policyFreshnessStale
	default:
		return age, policyFreshnessFresh
	}
}
