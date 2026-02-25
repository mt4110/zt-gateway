package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEmitDoctorJSON_IncludesErrorCodeField(t *testing.T) {
	tmp := t.TempDir()
	outPath := filepath.Join(tmp, "doctor.json")
	f, err := os.Create(outPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	origStdout := os.Stdout
	os.Stdout = f
	defer func() { os.Stdout = origStdout }()

	emitDoctorJSON(doctorResult{OK: false, ErrorCode: ztErrorCodeConfigDoctorFailed, SchemaVersion: 1})
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("json.Unmarshal failed: %v\n%s", err, data)
	}
	if got["error_code"] != ztErrorCodeConfigDoctorFailed {
		t.Fatalf("error_code = %v", got["error_code"])
	}
}

func TestRunConfigDoctor_JSONContract_Success(t *testing.T) {
	repoRoot := t.TempDir()
	out := captureStdout(t, func() {
		if err := runConfigDoctor(repoRoot, []string{"--json"}); err != nil {
			t.Fatalf("runConfigDoctor returned error: %v", err)
		}
	})
	var got doctorResult
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("json.Unmarshal failed: %v\n%s", err, out)
	}
	if !got.OK {
		t.Fatalf("OK = false, want true")
	}
	if got.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0", got.ExitCode)
	}
	if got.SchemaVersion != 1 {
		t.Fatalf("SchemaVersion = %d, want 1", got.SchemaVersion)
	}
	if got.Command != "zt config doctor" {
		t.Fatalf("Command = %q", got.Command)
	}
	if got.RepoRoot != repoRoot {
		t.Fatalf("RepoRoot = %q, want %q", got.RepoRoot, repoRoot)
	}
	if got.ConfigSource == "" {
		t.Fatalf("ConfigSource is empty")
	}
	checkNames := []string{
		"auto_sync_resolution",
		"control_plane_url",
		"control_plane_api_key",
		"spool_dir",
		"event_signing_key_env",
	}
	for _, name := range checkNames {
		if !doctorCheckExists(got.Checks, name) {
			t.Fatalf("missing check: %s (checks=%#v)", name, got.Checks)
		}
	}
}

func TestRunConfigDoctor_JSONContract_FailureOnParse(t *testing.T) {
	repoRoot := t.TempDir()
	cfgPath := filepath.Join(t.TempDir(), "zt_client.toml")
	if err := os.WriteFile(cfgPath, []byte("auto_sync = not_a_bool\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ZT_CLIENT_CONFIG_FILE", cfgPath)
	out := captureStdout(t, func() {
		err := runConfigDoctor(repoRoot, []string{"--json"})
		if err == nil {
			t.Fatalf("expected error")
		}
		if !strings.Contains(err.Error(), "config doctor failed") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	var got doctorResult
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("json.Unmarshal failed: %v\n%s", err, out)
	}
	if got.OK {
		t.Fatalf("OK = true, want false")
	}
	if got.ErrorCode != ztErrorCodeConfigDoctorFailed {
		t.Fatalf("ErrorCode = %q, want %q", got.ErrorCode, ztErrorCodeConfigDoctorFailed)
	}
	if got.ExitCode != 1 {
		t.Fatalf("ExitCode = %d, want 1", got.ExitCode)
	}
	if !doctorCheckExistsWithStatus(got.Checks, "zt_client_config_parse", "fail") {
		t.Fatalf("missing fail parse check: %#v", got.Checks)
	}
}

func doctorCheckExists(checks []doctorCheck, name string) bool {
	for _, c := range checks {
		if c.Name == name {
			return true
		}
	}
	return false
}

func doctorCheckExistsWithStatus(checks []doctorCheck, name, status string) bool {
	for _, c := range checks {
		if c.Name == name && c.Status == status {
			return true
		}
	}
	return false
}
