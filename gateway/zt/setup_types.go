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
}

type setupResult struct {
	OK            bool          `json:"ok"`
	SchemaVersion int           `json:"schema_version"`
	GeneratedAt   string        `json:"generated_at"`
	Command       string        `json:"command"`
	Argv          []string      `json:"argv"`
	RepoRoot      string        `json:"repo_root"`
	ConfigSource  string        `json:"config_source"`
	Failures      int           `json:"failures"`
	Warnings      int           `json:"warnings"`
	Resolved      setupResolved `json:"resolved"`
	Checks        []setupCheck  `json:"checks"`
	QuickFixes    []string      `json:"quick_fixes,omitempty"`
	Next          []string      `json:"next,omitempty"`
}

func emitSetupJSON(v setupResult) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
