package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	cfgPath := filepath.Join(t.TempDir(), "zt_client.toml")
	if err := os.WriteFile(cfgPath, []byte("auto_sync=true\ncontrol_plane_url=\"https://cp.example\"\napi_key=\"test-key\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ZT_CLIENT_CONFIG_FILE", cfgPath)
	t.Setenv("ZT_EVENT_SIGNING_ED25519_PRIV_B64", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	t.Setenv(securePackSignerFingerprintZTEnv, "0123456789ABCDEF0123456789ABCDEF01234567")

	out := captureStdout(t, func() {
		if err := runConfigDoctor(repoRoot, []string{"--json"}); err != nil {
			t.Fatalf("runConfigDoctor returned error: %v", err)
		}
	})
	assertDoctorJSONRequiredFields(t, out)
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
	if got.Failures != 0 {
		t.Fatalf("Failures = %d, want 0", got.Failures)
	}
	if got.Warnings != 0 {
		t.Fatalf("Warnings = %d, want 0", got.Warnings)
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
		"team_boundary_policy_loaded",
		"team_boundary_recipient_contract",
		"team_boundary_signer_contract",
		"team_boundary_share_route_contract",
		teamBoundarySignerPinConsistencyCheckName,
		teamBoundaryBreakGlassGuardrailCheckName,
		auditTrailAppendabilityCheckName,
	}
	for _, name := range checkNames {
		if !doctorCheckExists(got.Checks, name) {
			t.Fatalf("missing check: %s (checks=%#v)", name, got.Checks)
		}
	}
	if !doctorCheckExistsWithStatus(got.Checks, "control_plane_url", "ok") {
		t.Fatalf("control_plane_url should be ok: %#v", got.Checks)
	}
	if !doctorCheckExistsWithStatus(got.Checks, "control_plane_api_key", "ok") {
		t.Fatalf("control_plane_api_key should be ok: %#v", got.Checks)
	}
	if !doctorCheckExistsWithStatus(got.Checks, "event_signing_key_env", "ok") {
		t.Fatalf("event_signing_key_env should be ok: %#v", got.Checks)
	}
}

func TestRunConfigDoctor_JSONContract_WarnMinimum(t *testing.T) {
	repoRoot := t.TempDir()
	out := captureStdout(t, func() {
		if err := runConfigDoctor(repoRoot, []string{"--json"}); err != nil {
			t.Fatalf("runConfigDoctor returned error: %v", err)
		}
	})
	assertDoctorJSONRequiredFields(t, out)

	var got doctorResult
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("json.Unmarshal failed: %v\n%s", err, out)
	}
	if !got.OK {
		t.Fatalf("OK = false, want true (warnings-only case)")
	}
	if got.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0", got.ExitCode)
	}
	if got.Failures != 0 {
		t.Fatalf("Failures = %d, want 0", got.Failures)
	}
	if got.Warnings < 1 {
		t.Fatalf("Warnings = %d, want >= 1", got.Warnings)
	}
	if !doctorCheckExistsWithStatus(got.Checks, "control_plane_url", "warn") {
		t.Fatalf("expected warn control_plane_url: %#v", got.Checks)
	}
	if !doctorCheckExistsWithStatus(got.Checks, "control_plane_api_key", "warn") {
		t.Fatalf("expected warn control_plane_api_key: %#v", got.Checks)
	}
	if !doctorCheckExistsWithStatus(got.Checks, "event_signing_key_env", "warn") {
		t.Fatalf("expected warn event_signing_key_env: %#v", got.Checks)
	}
}

func TestRunConfigDoctor_JSONContract_FailMinimum_InvalidURL(t *testing.T) {
	repoRoot := t.TempDir()
	cfgPath := filepath.Join(t.TempDir(), "zt_client.toml")
	if err := os.WriteFile(cfgPath, []byte("control_plane_url=\":bad\"\n"), 0o644); err != nil {
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
	assertDoctorJSONRequiredFields(t, out)

	var got doctorResult
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("json.Unmarshal failed: %v\n%s", err, out)
	}
	if got.OK {
		t.Fatalf("OK = true, want false")
	}
	if got.ExitCode != 1 {
		t.Fatalf("ExitCode = %d, want 1", got.ExitCode)
	}
	if got.ErrorCode != ztErrorCodeConfigDoctorFailed {
		t.Fatalf("ErrorCode = %q, want %q", got.ErrorCode, ztErrorCodeConfigDoctorFailed)
	}
	if got.Failures < 1 {
		t.Fatalf("Failures = %d, want >= 1", got.Failures)
	}
	if !doctorCheckExistsWithStatus(got.Checks, "control_plane_url", "fail") {
		t.Fatalf("expected fail control_plane_url: %#v", got.Checks)
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
	assertDoctorJSONRequiredFields(t, out)
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

func TestRunConfigDoctor_JSONContract_TeamBoundarySignerSplitBrainDetected(t *testing.T) {
	repoRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repoRoot, "policy"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repoRoot, "tools", "secure-pack"), 0o755); err != nil {
		t.Fatal(err)
	}
	policy := "" +
		"enabled = true\n" +
		"tenant_id = \"corp-example\"\n" +
		"team_id = \"secops\"\n" +
		"boundary_policy_version = \"2026-02-26\"\n" +
		"allowed_recipients = [\"clientA\"]\n" +
		"allowed_signer_fingerprints = [\"0123456789ABCDEF0123456789ABCDEF01234567\"]\n" +
		"allowed_share_routes = [\"stdout\"]\n"
	if err := os.WriteFile(filepath.Join(repoRoot, "policy", "team_boundary.toml"), []byte(policy), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(repoRoot, "tools", "secure-pack", "SIGNERS_ALLOWLIST.txt"),
		[]byte("89ABCDEF0123456789ABCDEF0123456789ABCDEF\n"),
		0o644,
	); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		err := runConfigDoctor(repoRoot, []string{"--json"})
		if err == nil {
			t.Fatalf("expected error")
		}
	})
	var got doctorResult
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("json.Unmarshal failed: %v\n%s", err, out)
	}
	if got.OK {
		t.Fatalf("OK = true, want false")
	}
	var splitCheck *doctorCheck
	for i := range got.Checks {
		if got.Checks[i].Name == teamBoundarySignerPinConsistencyCheckName {
			splitCheck = &got.Checks[i]
			break
		}
	}
	if splitCheck == nil {
		t.Fatalf("missing check: %s", teamBoundarySignerPinConsistencyCheckName)
	}
	if splitCheck.Status != "fail" {
		t.Fatalf("status = %q, want fail", splitCheck.Status)
	}
	if splitCheck.Code != teamBoundarySignerSplitBrainCode {
		t.Fatalf("code = %q, want %q", splitCheck.Code, teamBoundarySignerSplitBrainCode)
	}
}

func TestRunConfigDoctor_JSONContract_TeamBoundaryBreakGlassEnvPresentDetected(t *testing.T) {
	repoRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repoRoot, "policy"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repoRoot, "tools", "secure-pack"), 0o755); err != nil {
		t.Fatal(err)
	}
	const signerFP = "0123456789ABCDEF0123456789ABCDEF01234567"
	policy := "" +
		"enabled = true\n" +
		"tenant_id = \"corp-example\"\n" +
		"team_id = \"secops\"\n" +
		"boundary_policy_version = \"2026-02-26\"\n" +
		"allowed_recipients = [\"clientA\"]\n" +
		"allowed_signer_fingerprints = [\"" + signerFP + "\"]\n" +
		"allowed_share_routes = [\"stdout\"]\n" +
		"break_glass_enabled = true\n" +
		"break_glass_require_reason = true\n" +
		"break_glass_require_approver = true\n" +
		"break_glass_max_ttl_minutes = 60\n"
	if err := os.WriteFile(filepath.Join(repoRoot, "policy", "team_boundary.toml"), []byte(policy), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(repoRoot, "tools", "secure-pack", "SIGNERS_ALLOWLIST.txt"),
		[]byte(signerFP+"\n"),
		0o644,
	); err != nil {
		t.Fatal(err)
	}
	expiresAt := time.Now().UTC().Add(20 * time.Minute).Format(time.RFC3339)
	t.Setenv(teamBoundaryBreakGlassEnv, "incident=inc-env;approved_by=alice;expires_at="+expiresAt)

	out := captureStdout(t, func() {
		err := runConfigDoctor(repoRoot, []string{"--json"})
		if err == nil {
			t.Fatalf("expected error")
		}
	})
	var got doctorResult
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("json.Unmarshal failed: %v\n%s", err, out)
	}
	if got.OK {
		t.Fatalf("OK = true, want false")
	}
	var breakGlassCheck *doctorCheck
	for i := range got.Checks {
		if got.Checks[i].Name == teamBoundaryBreakGlassGuardrailCheckName {
			breakGlassCheck = &got.Checks[i]
			break
		}
	}
	if breakGlassCheck == nil {
		t.Fatalf("missing check: %s", teamBoundaryBreakGlassGuardrailCheckName)
	}
	if breakGlassCheck.Status != "fail" {
		t.Fatalf("status = %q, want fail", breakGlassCheck.Status)
	}
	if breakGlassCheck.Code != teamBoundaryBreakGlassEnvPresentCode {
		t.Fatalf("code = %q, want %q", breakGlassCheck.Code, teamBoundaryBreakGlassEnvPresentCode)
	}
}

func assertDoctorJSONRequiredFields(t *testing.T, out string) {
	t.Helper()
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("json.Unmarshal failed: %v\n%s", err, out)
	}
	required := []string{
		"ok",
		"schema_version",
		"generated_at",
		"command",
		"argv",
		"exit_code",
		"version",
		"repo_root",
		"config_source",
		"failures",
		"warnings",
		"resolved",
		"checks",
	}
	for _, key := range required {
		if _, ok := got[key]; !ok {
			t.Fatalf("missing required field %q in %s", key, out)
		}
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
