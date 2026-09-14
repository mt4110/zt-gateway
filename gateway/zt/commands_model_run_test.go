package main

import (
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseModelRunArgsAllowsCapsuleBeforeFlagsAndRuntimeArgs(t *testing.T) {
	opts, err := parseModelRunArgs([]string{
		"demo.zmc",
		"--runtime", "fake",
		"--lease", "lease.json",
		"--permit-pubkey", "abc",
		"--",
		"echo", "ok",
	})
	if err != nil {
		t.Fatalf("parseModelRunArgs: %v", err)
	}
	if opts.CapsulePath != "demo.zmc" || opts.Runtime != "fake" || opts.LeasePath != "lease.json" {
		t.Fatalf("unexpected opts: %+v", opts)
	}
	if len(opts.RuntimeArgs) != 2 || opts.RuntimeArgs[0] != "echo" || opts.RuntimeArgs[1] != "ok" {
		t.Fatalf("runtime args=%v", opts.RuntimeArgs)
	}
}

func TestParseModelPermitIssueArgsAllowsCapsuleBeforeFlags(t *testing.T) {
	opts, err := parseModelPermitIssueArgs([]string{
		"demo.zmc",
		"--runtime", "llama.cpp",
		"--runtime-binary-sha256", strings.Repeat("a", 64),
		"--device", "dev-a",
		"--out", "lease.json",
		"--ttl", "30m",
	})
	if err != nil {
		t.Fatalf("parseModelPermitIssueArgs: %v", err)
	}
	if opts.CapsulePath != "demo.zmc" || opts.DeviceID != "dev-a" || opts.Out != "lease.json" {
		t.Fatalf("unexpected opts: %+v", opts)
	}
	if opts.Runtime != "llama.cpp" {
		t.Fatalf("runtime=%q, want llama.cpp", opts.Runtime)
	}
	if opts.RuntimeBinarySHA256 != strings.Repeat("a", 64) {
		t.Fatalf("runtime binary sha=%q", opts.RuntimeBinarySHA256)
	}
}

func TestParseModelRunArgsDefaultsToPolicyRuntime(t *testing.T) {
	opts, err := parseModelRunArgs([]string{
		"demo.zmc",
		"--lease", "lease.json",
		"--",
		"llama-server",
		"--port", "8080",
	})
	if err != nil {
		t.Fatalf("parseModelRunArgs: %v", err)
	}
	if opts.Runtime != defaultModelRuntimeName {
		t.Fatalf("runtime=%q, want %s", opts.Runtime, defaultModelRuntimeName)
	}
}

func TestParseModelRunArgsPrependsRuntimeBinary(t *testing.T) {
	opts, err := parseModelRunArgs([]string{
		"demo.zmc",
		"--runtime", "llama.cpp",
		"--runtime-binary", "/usr/local/bin/llama-server",
		"--lease", "lease.json",
		"--",
		"--port", "8080",
	})
	if err != nil {
		t.Fatalf("parseModelRunArgs: %v", err)
	}
	if opts.RuntimeBinary != "/usr/local/bin/llama-server" {
		t.Fatalf("runtime binary=%q", opts.RuntimeBinary)
	}
	want := []string{"/usr/local/bin/llama-server", "--port", "8080"}
	if strings.Join(opts.RuntimeArgs, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("runtime args=%v, want %v", opts.RuntimeArgs, want)
	}
}

func TestParseModelPermitIssueArgsDefaultsToPolicyRuntime(t *testing.T) {
	opts, err := parseModelPermitIssueArgs([]string{
		"demo.zmc",
		"--out", "lease.json",
	})
	if err != nil {
		t.Fatalf("parseModelPermitIssueArgs: %v", err)
	}
	if opts.Runtime != defaultModelRuntimeName {
		t.Fatalf("runtime=%q, want %s", opts.Runtime, defaultModelRuntimeName)
	}
}

func TestParseModelRunArgsRequiresCommandForNonFakeRuntime(t *testing.T) {
	_, err := parseModelRunArgs([]string{
		"demo.zmc",
		"--runtime", "llama.cpp",
		"--lease", "lease.json",
	})
	if err == nil || !strings.Contains(err.Error(), "requires an explicit runtime command") {
		t.Fatalf("err=%v, want runtime command required", err)
	}
}

func TestParseModelRunArgsCanonicalizesFakeRuntimeCase(t *testing.T) {
	opts, err := parseModelRunArgs([]string{
		"demo.zmc",
		"--runtime", "Fake",
		"--lease", "lease.json",
	})
	if err != nil {
		t.Fatalf("parseModelRunArgs: %v", err)
	}
	if opts.Runtime != "fake" {
		t.Fatalf("runtime=%q, want fake", opts.Runtime)
	}
}

func TestModelRuntimeStartedReasonCode(t *testing.T) {
	if got := modelRuntimeStartedReasonCode("fake", nil); got != "runtime.fake_started" {
		t.Fatalf("fake reason=%q", got)
	}
	if got := modelRuntimeStartedReasonCode("llama.cpp", []string{"llama-server"}); got != "runtime.child_started" {
		t.Fatalf("child reason=%q", got)
	}
	if got := modelRuntimeStartedReasonCode("fake", []string{"./fake-runtime"}); got != "runtime.child_started" {
		t.Fatalf("fake child reason=%q", got)
	}
}

func TestValidateRuntimeExecutableHashAllowsMatch(t *testing.T) {
	path := writeRuntimeExecutableFixture(t, "runtime-a")
	sha, err := fileSHA256Hex(path)
	if err != nil {
		t.Fatal(err)
	}
	permit := runtimePermitV1{Runtime: runtimePermitRuntime{BinarySHA256: sha}}
	args, err := validateRuntimeExecutableHash(permit, []string{path, "--flag"})
	if err != nil {
		t.Fatalf("validateRuntimeExecutableHash: %v", err)
	}
	if len(args) != 2 || args[0] != path || args[1] != "--flag" {
		t.Fatalf("runtime args=%v, want resolved executable plus original args", args)
	}
}

func TestValidateRuntimeExecutableHashRejectsMismatch(t *testing.T) {
	path := writeRuntimeExecutableFixture(t, "runtime-a")
	permit := runtimePermitV1{Runtime: runtimePermitRuntime{BinarySHA256: strings.Repeat("b", 64)}}
	_, err := validateRuntimeExecutableHash(permit, []string{path})
	if err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("err=%v, want mismatch", err)
	}
}

func TestValidateRuntimeExecutableHashRejectsPinnedPermitWithoutExecutable(t *testing.T) {
	permit := runtimePermitV1{Runtime: runtimePermitRuntime{BinarySHA256: strings.Repeat("a", 64)}}
	_, err := validateRuntimeExecutableHash(permit, nil)
	if err == nil || !strings.Contains(err.Error(), "runtime executable is required") {
		t.Fatalf("err=%v, want executable required", err)
	}
}

func TestValidateRuntimeExecutableHashResolvesUnpinnedRelativePath(t *testing.T) {
	callerDir := t.TempDir()
	workspace := t.TempDir()
	callerRuntime := filepath.Join(callerDir, "runtime")
	if err := os.WriteFile(callerRuntime, []byte("caller-runtime"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "runtime"), []byte("workspace-runtime"), 0700); err != nil {
		t.Fatal(err)
	}
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(callerDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })

	args, err := validateRuntimeExecutableHash(runtimePermitV1{}, []string{"./runtime", "--ok"})
	if err != nil {
		t.Fatalf("validateRuntimeExecutableHash: %v", err)
	}
	expectedRuntime, err := filepath.Abs("./runtime")
	if err != nil {
		t.Fatal(err)
	}
	if len(args) != 2 || args[0] != expectedRuntime || args[1] != "--ok" {
		t.Fatalf("runtime args=%v, want %s plus original args", args, expectedRuntime)
	}
}

func TestValidateRuntimeExecutableHashReturnsResolvedRelativePath(t *testing.T) {
	callerDir := t.TempDir()
	workspace := t.TempDir()
	callerRuntime := filepath.Join(callerDir, "runtime")
	if err := os.WriteFile(callerRuntime, []byte("caller-runtime"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "runtime"), []byte("workspace-runtime"), 0700); err != nil {
		t.Fatal(err)
	}
	sha, err := fileSHA256Hex(callerRuntime)
	if err != nil {
		t.Fatal(err)
	}
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(callerDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })

	permit := runtimePermitV1{Runtime: runtimePermitRuntime{BinarySHA256: sha}}
	args, err := validateRuntimeExecutableHash(permit, []string{"./runtime", "--ok"})
	if err != nil {
		t.Fatalf("validateRuntimeExecutableHash: %v", err)
	}
	expectedRuntime, err := filepath.Abs("./runtime")
	if err != nil {
		t.Fatal(err)
	}
	if len(args) != 2 || args[0] != expectedRuntime || args[1] != "--ok" {
		t.Fatalf("runtime args=%v, want %s plus original args", args, expectedRuntime)
	}
}

func TestStageModelRunPayloadClearsExistingModelDir(t *testing.T) {
	src := t.TempDir()
	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "current.gguf"), []byte("current"), 0600); err != nil {
		t.Fatal(err)
	}
	modelDir := filepath.Join(workspace, "model")
	if err := os.MkdirAll(modelDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(modelDir, "stale.gguf"), []byte("stale"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := stageModelRunPayload(src, workspace); err != nil {
		t.Fatalf("stageModelRunPayload: %v", err)
	}
	if _, err := os.Stat(filepath.Join(modelDir, "stale.gguf")); !os.IsNotExist(err) {
		t.Fatalf("stale file err=%v, want not exist", err)
	}
	if data, err := os.ReadFile(filepath.Join(modelDir, "current.gguf")); err != nil || string(data) != "current" {
		t.Fatalf("current file data=%q err=%v", data, err)
	}
}

func TestValidateRuntimeAllowedUID(t *testing.T) {
	if err := validateRuntimeAllowedUID(runtimePermitV1{}); err != nil {
		t.Fatalf("empty allowed_uid should pass: %v", err)
	}
	if err := validateRuntimeAllowedUID(runtimePermitV1{Runtime: runtimePermitRuntime{AllowedUID: os.Getuid()}}); err != nil {
		t.Fatalf("matching allowed_uid should pass: %v", err)
	}
	err := validateRuntimeAllowedUID(runtimePermitV1{Runtime: runtimePermitRuntime{AllowedUID: os.Getuid() + 1}})
	if err == nil || !strings.Contains(err.Error(), "allowed_uid mismatch") {
		t.Fatalf("err=%v, want allowed_uid mismatch", err)
	}
}

func TestValidateRuntimeShieldForRunAllowsAuditOnly(t *testing.T) {
	tier, err := validateRuntimeShieldForRun(modelCapsuleManifestV1{}, runtimePermitV1{
		Policy: runtimePermitPolicy{ShieldMinTier: runtimePermitShieldTierAuditOnly},
	})
	if err != nil {
		t.Fatalf("validateRuntimeShieldForRun: %v", err)
	}
	if tier != runtimePermitShieldTierAuditOnly {
		t.Fatalf("tier=%q, want audit_only", tier)
	}
}

func TestValidateRuntimeShieldForRunRejectsKernelShieldPolicy(t *testing.T) {
	manifest := modelCapsuleManifestV1{Policy: modelPolicyV1{RequireKernelShield: true}}
	_, err := validateRuntimeShieldForRun(manifest, runtimePermitV1{
		Policy: runtimePermitPolicy{ShieldMinTier: runtimePermitShieldTierKernelMode},
	})
	if err == nil || !strings.Contains(err.Error(), "kernel shield runtime isolation is required") {
		t.Fatalf("err=%v, want kernel shield deny", err)
	}
}

func TestValidateRuntimeShieldForRunRejectsUnsupportedPermitTier(t *testing.T) {
	_, err := validateRuntimeShieldForRun(modelCapsuleManifestV1{}, runtimePermitV1{
		Policy: runtimePermitPolicy{ShieldMinTier: "hardware_tee"},
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported runtime shield_min_tier") {
		t.Fatalf("err=%v, want unsupported shield tier deny", err)
	}
}

func TestRunModelRunFakeRuntimeReceivesInjectedModelPath(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("sh not available: %v", err)
	}
	dir := t.TempDir()
	manifest := testRuntimePermitManifest(t)
	signedRoot := writeSignedModelCapsuleMetadata(t, manifest, manifest.Policy)
	payloadPath := filepath.Join(dir, "payload.spkg.tgz")
	if err := os.WriteFile(payloadPath, []byte("signed-payload"), 0600); err != nil {
		t.Fatal(err)
	}
	capsulePath := filepath.Join(dir, "demo.zmc")
	if _, err := writeModelCapsuleArchive(capsulePath, manifest, payloadPath); err != nil {
		t.Fatalf("writeModelCapsuleArchive: %v", err)
	}

	pub, priv := generateRuntimePermitKey(t)
	now := time.Now().UTC().Add(-time.Minute)
	permit, err := newRuntimePermitForManifest(manifest, hostID(), "fake", "", now, time.Hour)
	if err != nil {
		t.Fatalf("newRuntimePermitForManifest: %v", err)
	}
	permit, err = signRuntimePermit(permit, "test-runtime-permit", priv)
	if err != nil {
		t.Fatalf("signRuntimePermit: %v", err)
	}
	leasePath := filepath.Join(dir, "lease.json")
	if err := writeRuntimeLeaseFile(leasePath, runtimeLeaseFileV1{
		SchemaVersion: runtimeLeaseSchemaV1,
		SavedAt:       now.Format(time.RFC3339),
		Permit:        permit,
	}); err != nil {
		t.Fatalf("writeRuntimeLeaseFile: %v", err)
	}

	argsOut := filepath.Join(dir, "runtime-args.txt")
	scriptPath := filepath.Join(dir, "capture-args.sh")
	if err := os.WriteFile(scriptPath, []byte("printf '%s\\n' \"$@\" > \"$ARGS_OUT\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARGS_OUT", argsOut)

	prevEvents := cpEvents
	prevSOR := localSOR
	cpEvents = nil
	localSOR = nil
	t.Cleanup(func() {
		cpEvents = prevEvents
		localSOR = prevSOR
	})

	workspace := filepath.Join(dir, "workspace")
	adapters := &toolAdapters{
		modernPackVerifyFn: func(string) ([]byte, error) {
			return []byte("ok"), nil
		},
		modernPackReceiveFn: func(_ string, outDir string) ([]byte, error) {
			if err := copyDir(signedRoot, outDir); err != nil {
				return nil, err
			}
			return []byte("ok"), nil
		},
	}
	err = runModelRun(adapters, modelRunOptions{
		CapsulePath:  capsulePath,
		Runtime:      "fake",
		LeasePath:    leasePath,
		PermitPubKey: base64.StdEncoding.EncodeToString(pub),
		Workspace:    workspace,
		RuntimeArgs:  []string{sh, scriptPath, "--model", modelRuntimeModelPlaceholder},
	})
	if err != nil {
		t.Fatalf("runModelRun: %v", err)
	}

	modelView, err := modelRunPrimaryModelView(workspace, manifest, true)
	if err != nil {
		t.Fatalf("modelRunPrimaryModelView: %v", err)
	}
	if _, err := os.Stat(modelView.Path); err != nil {
		t.Fatalf("injected model path stat: %v", err)
	}
	body, err := os.ReadFile(argsOut)
	if err != nil {
		t.Fatalf("read runtime args: %v", err)
	}
	want := strings.Join([]string{"--model", modelView.Path, ""}, "\n")
	if string(body) != want {
		t.Fatalf("runtime args=%q, want %q", body, want)
	}
}

func TestRunFakeRuntimeReportsChildPID(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("sh not available: %v", err)
	}
	gotPID := 0
	result, reason, err := runFakeRuntime(t.TempDir(), []string{sh, "-c", "exit 0"}, func(pid int) error {
		gotPID = pid
		return nil
	})
	if err != nil {
		t.Fatalf("runFakeRuntime: %v", err)
	}
	if result != "completed" || reason != "runtime.child_completed" {
		t.Fatalf("result=%q reason=%q", result, reason)
	}
	if gotPID <= 0 {
		t.Fatalf("pid=%d, want child pid", gotPID)
	}
}

func writeRuntimeExecutableFixture(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "runtime.sh")
	if err := os.WriteFile(path, []byte(body), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}
