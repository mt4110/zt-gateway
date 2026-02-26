package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	teamBoundarySendEnvPresentHelperEnv      = "ZT_TEST_HELPER_SEND_BOUNDARY_BREAK_GLASS_ENV_PRESENT"
	teamBoundaryVerifyEnvPresentHelperEnv    = "ZT_TEST_HELPER_VERIFY_BOUNDARY_BREAK_GLASS_ENV_PRESENT"
	teamBoundarySendPolicyLoadFailHelperEnv  = "ZT_TEST_HELPER_SEND_BOUNDARY_POLICY_LOAD_FAIL"
	teamBoundaryVerifyPolicyLoadFailHelperEnv = "ZT_TEST_HELPER_VERIFY_BOUNDARY_POLICY_LOAD_FAIL"
	teamBoundaryHelperRepoRootEnv            = "ZT_TEST_HELPER_REPO_ROOT"
	teamBoundaryHelperInputPathEnv           = "ZT_TEST_HELPER_INPUT_PATH"
	teamBoundaryHelperArtifactPathEnv        = "ZT_TEST_HELPER_ARTIFACT_PATH"
)

func TestRunSend_TeamBoundaryBreakGlassEnvPresentFailFast(t *testing.T) {
	repoRoot := t.TempDir()
	writeTeamBoundaryCommandTestPolicy(t, repoRoot, false)
	inputPath := filepath.Join(repoRoot, "safe.txt")
	if err := os.WriteFile(inputPath, []byte("safe-content"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestRunSend_TeamBoundaryBreakGlassEnvPresentFailFast_Helper$")
	cmd.Env = append(os.Environ(),
		teamBoundarySendEnvPresentHelperEnv+"=1",
		teamBoundaryHelperRepoRootEnv+"="+repoRoot,
		teamBoundaryHelperInputPathEnv+"="+inputPath,
		teamBoundaryBreakGlassEnv+"=incident=inc-env;approved_by=alice;expires_at=2099-01-01T00:00:00Z",
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure; output=%s", string(out))
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("unexpected error type: %T (%v)", err, err)
	}
	if exitErr.ExitCode() != 1 {
		t.Fatalf("exit code = %d, want 1 (output=%s)", exitErr.ExitCode(), string(out))
	}
	if !strings.Contains(string(out), "ZT_ERROR_CODE="+ztErrorCodeSendBoundaryBreakGlassEnvPresent) {
		t.Fatalf("missing error code %s in output:\n%s", ztErrorCodeSendBoundaryBreakGlassEnvPresent, string(out))
	}
}

func TestRunSend_TeamBoundaryBreakGlassEnvPresentFailFast_Helper(t *testing.T) {
	if os.Getenv(teamBoundarySendEnvPresentHelperEnv) != "1" {
		t.Skip("helper subprocess")
	}
	repoRoot := strings.TrimSpace(os.Getenv(teamBoundaryHelperRepoRootEnv))
	inputPath := strings.TrimSpace(os.Getenv(teamBoundaryHelperInputPathEnv))
	if repoRoot == "" || inputPath == "" {
		t.Fatalf("missing helper env: repoRoot=%q inputPath=%q", repoRoot, inputPath)
	}
	prevEvents := cpEvents
	cpEvents = nil
	defer func() { cpEvents = prevEvents }()
	runSend(newToolAdapters(repoRoot), sendOptions{
		InputFile: inputPath,
		Client:    "clientA",
	})
	t.Fatalf("runSend returned without os.Exit")
}

func TestRunVerify_TeamBoundaryBreakGlassEnvPresentFailFast(t *testing.T) {
	repoRoot := t.TempDir()
	writeTeamBoundaryCommandTestPolicy(t, repoRoot, false)
	artifactPath := filepath.Join(repoRoot, "bundle_clientA_20260225T000000Z.spkg.tgz")
	if err := os.WriteFile(artifactPath, []byte("packet"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestRunVerify_TeamBoundaryBreakGlassEnvPresentFailFast_Helper$")
	cmd.Env = append(os.Environ(),
		teamBoundaryVerifyEnvPresentHelperEnv+"=1",
		teamBoundaryHelperRepoRootEnv+"="+repoRoot,
		teamBoundaryHelperArtifactPathEnv+"="+artifactPath,
		teamBoundaryBreakGlassEnv+"=incident=inc-env;approved_by=alice;expires_at=2099-01-01T00:00:00Z",
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure; output=%s", string(out))
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("unexpected error type: %T (%v)", err, err)
	}
	if exitErr.ExitCode() != 1 {
		t.Fatalf("exit code = %d, want 1 (output=%s)", exitErr.ExitCode(), string(out))
	}
	if !strings.Contains(string(out), "ZT_ERROR_CODE="+ztErrorCodeVerifyBoundaryBreakGlassEnvPresent) {
		t.Fatalf("missing error code %s in output:\n%s", ztErrorCodeVerifyBoundaryBreakGlassEnvPresent, string(out))
	}
}

func TestRunVerify_TeamBoundaryBreakGlassEnvPresentFailFast_Helper(t *testing.T) {
	if os.Getenv(teamBoundaryVerifyEnvPresentHelperEnv) != "1" {
		t.Skip("helper subprocess")
	}
	repoRoot := strings.TrimSpace(os.Getenv(teamBoundaryHelperRepoRootEnv))
	artifactPath := strings.TrimSpace(os.Getenv(teamBoundaryHelperArtifactPathEnv))
	if repoRoot == "" || artifactPath == "" {
		t.Fatalf("missing helper env: repoRoot=%q artifactPath=%q", repoRoot, artifactPath)
	}
	prevEvents := cpEvents
	cpEvents = nil
	defer func() { cpEvents = prevEvents }()
	runVerify(newToolAdapters(repoRoot), verifyOptions{
		ArtifactPath: artifactPath,
	})
	t.Fatalf("runVerify returned without os.Exit")
}

func writeTeamBoundaryCommandTestPolicy(t *testing.T, repoRoot string, breakGlassEnabled bool) {
	t.Helper()
	policyDir := filepath.Join(repoRoot, "policy")
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	content := "" +
		"enabled = true\n" +
		"tenant_id = \"corp-example\"\n" +
		"team_id = \"secops\"\n" +
		"boundary_policy_version = \"2026-02-26\"\n" +
		"allowed_recipients = [\"clientA\"]\n" +
		"allowed_signer_fingerprints = [\"0123456789ABCDEF0123456789ABCDEF01234567\"]\n" +
		"allowed_share_routes = [\"stdout\"]\n"
	if breakGlassEnabled {
		content += "" +
			"break_glass_enabled = true\n" +
			"break_glass_require_reason = true\n" +
			"break_glass_require_approver = true\n" +
			"break_glass_max_ttl_minutes = 60\n"
	} else {
		content += "break_glass_enabled = false\n"
	}
	if err := os.WriteFile(filepath.Join(policyDir, "team_boundary.toml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRunSend_TeamBoundaryPolicyLoadFailFastClosed(t *testing.T) {
	repoRoot := t.TempDir()
	policyDir := filepath.Join(repoRoot, "policy")
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Write an invalid policy (break_glass_enabled=true with weak guardrails) to trigger load failure.
	invalidPolicy := "" +
		"enabled = true\n" +
		"tenant_id = \"corp-example\"\n" +
		"team_id = \"secops\"\n" +
		"boundary_policy_version = \"2026-02-26\"\n" +
		"allowed_recipients = [\"clientA\"]\n" +
		"allowed_signer_fingerprints = [\"0123456789ABCDEF0123456789ABCDEF01234567\"]\n" +
		"allowed_share_routes = [\"stdout\"]\n" +
		"break_glass_enabled = true\n" +
		"break_glass_require_reason = true\n"
	if err := os.WriteFile(filepath.Join(policyDir, "team_boundary.toml"), []byte(invalidPolicy), 0o644); err != nil {
		t.Fatal(err)
	}
	inputPath := filepath.Join(repoRoot, "safe.txt")
	if err := os.WriteFile(inputPath, []byte("safe-content"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestRunSend_TeamBoundaryPolicyLoadFailFastClosed_Helper$")
	cmd.Env = append(os.Environ(),
		teamBoundarySendPolicyLoadFailHelperEnv+"=1",
		teamBoundaryHelperRepoRootEnv+"="+repoRoot,
		teamBoundaryHelperInputPathEnv+"="+inputPath,
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure; output=%s", string(out))
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("unexpected error type: %T (%v)", err, err)
	}
	if exitErr.ExitCode() != 1 {
		t.Fatalf("exit code = %d, want 1 (output=%s)", exitErr.ExitCode(), string(out))
	}
	if !strings.Contains(string(out), "ZT_ERROR_CODE="+ztErrorCodeSendBoundaryPolicy) {
		t.Fatalf("missing error code %s in output:\n%s", ztErrorCodeSendBoundaryPolicy, string(out))
	}
}

func TestRunSend_TeamBoundaryPolicyLoadFailFastClosed_Helper(t *testing.T) {
	if os.Getenv(teamBoundarySendPolicyLoadFailHelperEnv) != "1" {
		t.Skip("helper subprocess")
	}
	repoRoot := strings.TrimSpace(os.Getenv(teamBoundaryHelperRepoRootEnv))
	inputPath := strings.TrimSpace(os.Getenv(teamBoundaryHelperInputPathEnv))
	if repoRoot == "" || inputPath == "" {
		t.Fatalf("missing helper env: repoRoot=%q inputPath=%q", repoRoot, inputPath)
	}
	prevEvents := cpEvents
	cpEvents = nil
	defer func() { cpEvents = prevEvents }()
	runSend(newToolAdapters(repoRoot), sendOptions{
		InputFile: inputPath,
		Client:    "clientA",
	})
	t.Fatalf("runSend returned without os.Exit")
}

func TestRunVerify_TeamBoundaryPolicyLoadFailFastClosed(t *testing.T) {
	repoRoot := t.TempDir()
	policyDir := filepath.Join(repoRoot, "policy")
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Write an invalid policy (break_glass_enabled=true with weak guardrails) to trigger load failure.
	invalidPolicy := "" +
		"enabled = true\n" +
		"tenant_id = \"corp-example\"\n" +
		"team_id = \"secops\"\n" +
		"boundary_policy_version = \"2026-02-26\"\n" +
		"allowed_recipients = [\"clientA\"]\n" +
		"allowed_signer_fingerprints = [\"0123456789ABCDEF0123456789ABCDEF01234567\"]\n" +
		"allowed_share_routes = [\"stdout\"]\n" +
		"break_glass_enabled = true\n" +
		"break_glass_require_reason = true\n"
	if err := os.WriteFile(filepath.Join(policyDir, "team_boundary.toml"), []byte(invalidPolicy), 0o644); err != nil {
		t.Fatal(err)
	}
	artifactPath := filepath.Join(repoRoot, "bundle_clientA_20260225T000000Z.spkg.tgz")
	if err := os.WriteFile(artifactPath, []byte("packet"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestRunVerify_TeamBoundaryPolicyLoadFailFastClosed_Helper$")
	cmd.Env = append(os.Environ(),
		teamBoundaryVerifyPolicyLoadFailHelperEnv+"=1",
		teamBoundaryHelperRepoRootEnv+"="+repoRoot,
		teamBoundaryHelperArtifactPathEnv+"="+artifactPath,
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure; output=%s", string(out))
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("unexpected error type: %T (%v)", err, err)
	}
	if exitErr.ExitCode() != 1 {
		t.Fatalf("exit code = %d, want 1 (output=%s)", exitErr.ExitCode(), string(out))
	}
	if !strings.Contains(string(out), "ZT_ERROR_CODE="+ztErrorCodeVerifyBoundaryPolicy) {
		t.Fatalf("missing error code %s in output:\n%s", ztErrorCodeVerifyBoundaryPolicy, string(out))
	}
}

func TestRunVerify_TeamBoundaryPolicyLoadFailFastClosed_Helper(t *testing.T) {
	if os.Getenv(teamBoundaryVerifyPolicyLoadFailHelperEnv) != "1" {
		t.Skip("helper subprocess")
	}
	repoRoot := strings.TrimSpace(os.Getenv(teamBoundaryHelperRepoRootEnv))
	artifactPath := strings.TrimSpace(os.Getenv(teamBoundaryHelperArtifactPathEnv))
	if repoRoot == "" || artifactPath == "" {
		t.Fatalf("missing helper env: repoRoot=%q artifactPath=%q", repoRoot, artifactPath)
	}
	prevEvents := cpEvents
	cpEvents = nil
	defer func() { cpEvents = prevEvents }()
	runVerify(newToolAdapters(repoRoot), verifyOptions{
		ArtifactPath: artifactPath,
	})
	t.Fatalf("runVerify returned without os.Exit")
}
