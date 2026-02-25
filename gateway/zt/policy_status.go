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
}

type policyStatusResult struct {
	OK            bool            `json:"ok"`
	ErrorCode     string          `json:"error_code,omitempty"`
	SchemaVer     int             `json:"schema_version"`
	GeneratedAt   string          `json:"generated_at"`
	Command       string          `json:"command"`
	Argv          []string        `json:"argv"`
	ExitCode      int             `json:"exit_code"`
	Kind          string          `json:"kind"`
	Active        policyStatusRef `json:"active"`
	Staged        policyStatusRef `json:"staged"`
	LastKnownGood policyStatusRef `json:"last_known_good"`
	LastSyncAt    string          `json:"last_sync_at,omitempty"`
	NextSyncAt    string          `json:"next_sync_at,omitempty"`
	SyncError     string          `json:"sync_error_code"`
}

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
	fs.StringVar(&kind, "kind", "extension", "Policy kind: extension|scan")
	if err := fs.Parse(args); err != nil {
		printZTErrorCode(ztErrorCodePolicyUsage)
		return err
	}
	if len(fs.Args()) != 0 {
		printZTErrorCode(ztErrorCodePolicyUsage)
		return fmt.Errorf(cliPolicyStatusUsage)
	}
	normKind, err := normalizePolicyStateKind(kind)
	if err != nil || (normKind != "extension" && normKind != "scan") {
		printZTErrorCode(ztErrorCodePolicyUsage)
		return fmt.Errorf(cliPolicyStatusUsage)
	}
	store := newPolicyActivationStore(repoRoot)
	result := policyStatusResult{
		OK:          true,
		SchemaVer:   1,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Command:     "zt policy status",
		Argv:        append([]string(nil), os.Args...),
		Kind:        normKind,
		SyncError:   policySyncErrorCodeNone,
	}

	if active, exists, readErr := readSignedPolicyBundleFileIfExists(store.activePath(normKind)); readErr != nil {
		result.OK = false
		result.ErrorCode = ztErrorCodePolicyStatusFailed
		result.ExitCode = 1
		result.SyncError = "policy_status_active_load_failed"
		if jsonOut {
			emitPolicyStatusJSON(result)
			return fmt.Errorf("policy status failed")
		}
		printZTErrorCode(result.ErrorCode)
		return readErr
	} else if exists {
		result.Active.ManifestID = active.ManifestID
		result.Active.ExpiresAt = active.ExpiresAt
	}
	if staged, exists, readErr := store.readStagedIfExists(normKind); readErr == nil && exists {
		result.Staged.ManifestID = staged.ManifestID
	}
	if lkg, exists, readErr := store.readLastKnownGoodIfExists(normKind); readErr == nil && exists {
		result.LastKnownGood.ManifestID = lkg.ManifestID
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

	if !jsonOut {
		fmt.Printf("[POLICY] kind=%s\n", result.Kind)
		fmt.Printf("  active.manifest_id=%s\n", emptyIfBlank(result.Active.ManifestID, "(none)"))
		fmt.Printf("  active.expires_at=%s\n", emptyIfBlank(result.Active.ExpiresAt, "(none)"))
		fmt.Printf("  staged.manifest_id=%s\n", emptyIfBlank(result.Staged.ManifestID, "(none)"))
		fmt.Printf("  last_known_good.manifest_id=%s\n", emptyIfBlank(result.LastKnownGood.ManifestID, "(none)"))
		fmt.Printf("  last_sync_at=%s\n", emptyIfBlank(result.LastSyncAt, "(none)"))
		fmt.Printf("  next_sync_at=%s\n", emptyIfBlank(result.NextSyncAt, "(none)"))
		fmt.Printf("  sync_error_code=%s\n", emptyIfBlank(result.SyncError, policySyncErrorCodeNone))
		return nil
	}
	emitPolicyStatusJSON(result)
	return nil
}

func emitPolicyStatusJSON(v policyStatusResult) {
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
