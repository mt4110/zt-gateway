package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type doctorCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
	Source  string `json:"source,omitempty"`
}

type doctorResolved struct {
	AutoSync        bool   `json:"auto_sync"`
	AutoSyncSource  string `json:"auto_sync_source"`
	ControlPlaneURL string `json:"control_plane_url"`
	ControlPlaneSrc string `json:"control_plane_url_source"`
	APIKeySet       bool   `json:"api_key_set"`
	APIKeySource    string `json:"api_key_source"`
	SpoolDir        string `json:"spool_dir"`
}

type doctorResult struct {
	OK            bool           `json:"ok"`
	ErrorCode     string         `json:"error_code,omitempty"`
	SchemaVersion int            `json:"schema_version"`
	GeneratedAt   string         `json:"generated_at"`
	Command       string         `json:"command"`
	Argv          []string       `json:"argv"`
	ExitCode      int            `json:"exit_code"`
	Version       string         `json:"version"`
	RepoRoot      string         `json:"repo_root"`
	ConfigSource  string         `json:"config_source"`
	Failures      int            `json:"failures"`
	Warnings      int            `json:"warnings"`
	Resolved      doctorResolved `json:"resolved"`
	Checks        []doctorCheck  `json:"checks"`
}

func runConfigDoctor(repoRoot string, args []string) error {
	fs := flag.NewFlagSet("config doctor", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var jsonOut bool
	fs.BoolVar(&jsonOut, "json", false, "Emit machine-readable JSON output")
	if err := fs.Parse(args); err != nil {
		printZTErrorCode(ztErrorCodeConfigUsage)
		return err
	}
	if len(fs.Args()) != 0 {
		if jsonOut {
			result := doctorResult{
				OK:            false,
				ErrorCode:     ztErrorCodeConfigUsage,
				SchemaVersion: 1,
				GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
				Command:       "zt config doctor",
				Argv:          append([]string(nil), os.Args...),
				ExitCode:      1,
				Version:       ztVersion,
				RepoRoot:      repoRoot,
			}
			emitDoctorJSON(result)
			return fmt.Errorf("config doctor failed")
		}
		printZTErrorCode(ztErrorCodeConfigUsage)
		return fmt.Errorf("Usage: zt config doctor [--json]")
	}

	result := doctorResult{
		RepoRoot:      repoRoot,
		SchemaVersion: 1,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Command:       "zt config doctor",
		Argv:          append([]string(nil), os.Args...),
		Version:       ztVersion,
	}
	cfg, cfgErr := loadZTClientConfig(repoRoot)
	if cfgErr != nil {
		result.Failures++
		result.Checks = append(result.Checks, doctorCheck{
			Name:    "zt_client_config_parse",
			Status:  "fail",
			Message: cfgErr.Error(),
		})
		result.ConfigSource = "(parse_failed)"
		if jsonOut {
			result.OK = false
			result.ExitCode = 1
			result.ErrorCode = ztErrorCodeConfigDoctorFailed
			emitDoctorJSON(result)
			return fmt.Errorf("config doctor failed")
		}
		printZTErrorCode(ztErrorCodeConfigDoctorFailed)
		fmt.Printf("[FAIL] zt_client.toml parse error: %v\n", cfgErr)
		return fmt.Errorf("config doctor failed")
	}
	result.ConfigSource = cfg.Source
	autoSync, autoSyncSource := resolveEventAutoSyncDefault(cfg)
	cpURL, cpURLSource := resolveControlPlaneURL(cfg)
	cpAPIKey, cpAPIKeySource := resolveControlPlaneAPIKey(cfg)
	spoolDir := strings.TrimSpace(os.Getenv("ZT_EVENT_SPOOL_DIR"))
	if spoolDir == "" {
		spoolDir = filepath.Join(repoRoot, ".zt-spool")
	}

	result.Resolved = doctorResolved{
		AutoSync:        autoSync,
		AutoSyncSource:  autoSyncSource,
		ControlPlaneURL: cpURL,
		ControlPlaneSrc: cpURLSource,
		APIKeySet:       cpAPIKey != "",
		APIKeySource:    cpAPIKeySource,
		SpoolDir:        spoolDir,
	}

	result.Checks = append(result.Checks, doctorCheck{
		Name:    "auto_sync_resolution",
		Status:  "ok",
		Message: fmt.Sprintf("resolved=%t", autoSync),
		Source:  autoSyncSource,
	})

	if cpURL == "" {
		result.Warnings++
		result.Checks = append(result.Checks, doctorCheck{
			Name:    "control_plane_url",
			Status:  "warn",
			Message: "empty",
			Source:  cpURLSource,
		})
	} else {
		if u, err := url.Parse(cpURL); err != nil || u.Scheme == "" || u.Host == "" {
			result.Failures++
			result.Checks = append(result.Checks, doctorCheck{
				Name:    "control_plane_url",
				Status:  "fail",
				Message: fmt.Sprintf("invalid: %q", cpURL),
				Source:  cpURLSource,
			})
		} else {
			result.Checks = append(result.Checks, doctorCheck{
				Name:    "control_plane_url",
				Status:  "ok",
				Message: cpURL,
				Source:  cpURLSource,
			})
		}
	}

	if cpAPIKey == "" {
		result.Warnings++
		result.Checks = append(result.Checks, doctorCheck{
			Name:    "control_plane_api_key",
			Status:  "warn",
			Message: "empty",
			Source:  cpAPIKeySource,
		})
	} else {
		result.Checks = append(result.Checks, doctorCheck{
			Name:    "control_plane_api_key",
			Status:  "ok",
			Message: "configured",
			Source:  cpAPIKeySource,
		})
	}

	if err := os.MkdirAll(spoolDir, 0o755); err != nil {
		result.Failures++
		result.Checks = append(result.Checks, doctorCheck{
			Name:    "spool_dir",
			Status:  "fail",
			Message: fmt.Sprintf("mkdir failed: %s (%v)", spoolDir, err),
		})
	} else {
		tmp := filepath.Join(spoolDir, ".doctor-write-test")
		if err := os.WriteFile(tmp, []byte("ok\n"), 0o600); err != nil {
			result.Failures++
			result.Checks = append(result.Checks, doctorCheck{
				Name:    "spool_dir",
				Status:  "fail",
				Message: fmt.Sprintf("not writable: %s (%v)", spoolDir, err),
			})
		} else {
			_ = os.Remove(tmp)
			result.Checks = append(result.Checks, doctorCheck{
				Name:    "spool_dir",
				Status:  "ok",
				Message: "writable",
			})
		}
	}

	if signer, err := loadEventEnvelopeSignerFromEnv(); err != nil {
		result.Failures++
		result.Checks = append(result.Checks, doctorCheck{
			Name:    "event_signing_key_env",
			Status:  "fail",
			Message: err.Error(),
		})
	} else if signer == nil {
		result.Warnings++
		result.Checks = append(result.Checks, doctorCheck{
			Name:    "event_signing_key_env",
			Status:  "warn",
			Message: "not configured (ZT_EVENT_SIGNING_ED25519_PRIV_B64)",
		})
	} else {
		keyID := signer.KeyID
		if keyID == "" {
			keyID = "(empty)"
		}
		result.Checks = append(result.Checks, doctorCheck{
			Name:    "event_signing_key_env",
			Status:  "ok",
			Message: "loaded key_id=" + keyID,
		})
	}

	result.OK = result.Failures == 0
	if result.OK {
		result.ExitCode = 0
	} else {
		result.ExitCode = 1
		result.ErrorCode = ztErrorCodeConfigDoctorFailed
	}
	if jsonOut {
		emitDoctorJSON(result)
		if !result.OK {
			return fmt.Errorf("config doctor failed")
		}
		return nil
	}

	fmt.Println("[CONFIG] zt client doctor")
	fmt.Printf("  repo_root: %s\n", result.RepoRoot)
	fmt.Printf("  config_source: %s\n", result.ConfigSource)
	for _, c := range result.Checks {
		prefix := "[OK]"
		switch c.Status {
		case "warn":
			prefix = "[WARN]"
		case "fail":
			prefix = "[FAIL]"
		}
		line := fmt.Sprintf("%s %s", prefix, c.Name)
		if c.Message != "" {
			line += " " + c.Message
		}
		if c.Source != "" {
			line += " source=" + c.Source
		}
		fmt.Println(line)
	}
	fmt.Printf("[RESULT] failures=%d warnings=%d\n", result.Failures, result.Warnings)
	if result.Failures > 0 {
		printZTErrorCode(ztErrorCodeConfigDoctorFailed)
		return fmt.Errorf("config doctor failed")
	}
	return nil
}
