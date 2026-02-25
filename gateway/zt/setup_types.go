package main

import (
	"encoding/json"
	"os"
)

type setupCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

type setupResolved struct {
	AutoSync        bool   `json:"auto_sync"`
	AutoSyncSource  string `json:"auto_sync_source"`
	ControlPlaneURL string `json:"control_plane_url"`
	ControlPlaneSrc string `json:"control_plane_url_source"`
	APIKeySet       bool   `json:"api_key_set"`
	APIKeySource    string `json:"api_key_source"`
	SpoolDir        string `json:"spool_dir"`
	Profile         string `json:"profile"`
	ProfileSource   string `json:"profile_source"`
	// Optional supply-chain pin details for machine-readable CI diagnostics.
	ActualRootFingerprint string `json:"actual_root_fingerprint,omitempty"`
	PinSource             string `json:"pin_source,omitempty"`
	PinMatchCount         int    `json:"pin_match_count,omitempty"`
}

type setupCompatibilityEnvironment struct {
	OS            string `json:"os"`
	PackageSource string `json:"package_source,omitempty"`
	PinSource     string `json:"pin_source,omitempty"`
}

type setupCompatibilityFixCandidate struct {
	Priority int    `json:"priority"`
	Command  string `json:"command"`
	Why      string `json:"why,omitempty"`
}

type setupCompatibilityResolver struct {
	Status        string                           `json:"status"`
	Category      string                           `json:"category,omitempty"`
	Reason        string                           `json:"reason,omitempty"`
	Environment   setupCompatibilityEnvironment    `json:"environment"`
	FixCandidates []setupCompatibilityFixCandidate `json:"fix_candidates,omitempty"`
}

type setupResult struct {
	OK             bool                        `json:"ok"`
	ErrorCode      string                      `json:"error_code,omitempty"`
	Summary        string                      `json:"summary,omitempty"`
	SchemaVersion  int                         `json:"schema_version"`
	GeneratedAt    string                      `json:"generated_at"`
	Command        string                      `json:"command"`
	Argv           []string                    `json:"argv"`
	RepoRoot       string                      `json:"repo_root"`
	ConfigSource   string                      `json:"config_source"`
	Failures       int                         `json:"failures"`
	Warnings       int                         `json:"warnings"`
	Resolved       setupResolved               `json:"resolved"`
	Checks         []setupCheck                `json:"checks"`
	Compatibility  *setupCompatibilityResolver `json:"compatibility,omitempty"`
	TrustStatus    trustStatus                 `json:"trust_status"`
	QuickFixBundle *quickFixBundle             `json:"quick_fix_bundle,omitempty"`
	QuickFixes     []string                    `json:"quick_fixes,omitempty"`
	Next           []string                    `json:"next,omitempty"`
}

func emitSetupJSON(v setupResult) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
