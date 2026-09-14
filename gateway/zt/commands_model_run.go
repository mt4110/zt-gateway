package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type modelRunOptions struct {
	CapsulePath   string
	Runtime       string
	RuntimeBinary string
	LeasePath     string
	PermitPubKey  string
	Workspace     string
	KeepWorkspace bool
	NoExtract     bool
	RuntimeArgs   []string
	SyncNow       bool
	NoAutoSync    bool
}

type modelPermitIssueOptions struct {
	CapsulePath         string
	Runtime             string
	RuntimeBinarySHA256 string
	DeviceID            string
	Out                 string
	TTL                 time.Duration
}

func parseModelRunArgs(args []string) (modelRunOptions, error) {
	before, runtimeArgs := splitArgsAtDoubleDash(args)
	normalizedArgs, err := reorderInterspersedFlags(before, map[string]bool{
		"runtime": true, "runtime-binary": true, "lease": true, "permit-pubkey": true, "workspace": true,
	})
	if err != nil {
		return modelRunOptions{}, err
	}
	fs := flagSet("model run")
	var opts modelRunOptions
	fs.StringVar(&opts.Runtime, "runtime", defaultModelRuntimeName, "Runtime adapter name")
	fs.StringVar(&opts.RuntimeBinary, "runtime-binary", "", "Runtime executable path")
	fs.StringVar(&opts.LeasePath, "lease", "", "Runtime lease JSON file")
	fs.StringVar(&opts.PermitPubKey, "permit-pubkey", "", "Runtime permit Ed25519 public key (base64)")
	fs.StringVar(&opts.Workspace, "workspace", "", "Workspace directory for extracted model files")
	fs.BoolVar(&opts.KeepWorkspace, "keep-workspace", false, "Keep runtime workspace after exit")
	fs.BoolVar(&opts.NoExtract, "no-extract", false, "Skip model payload extraction into the runtime workspace; signed metadata is still verified in a temp dir")
	fs.BoolVar(&opts.SyncNow, "sync-now", false, "Force-sync local model runtime events after command")
	fs.BoolVar(&opts.NoAutoSync, "no-auto-sync", false, "Disable background auto-sync to control plane")
	if err := fs.Parse(normalizedArgs); err != nil {
		return modelRunOptions{}, err
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return modelRunOptions{}, fmt.Errorf(cliModelRunUsage)
	}
	opts.CapsulePath = rest[0]
	opts.RuntimeArgs = runtimeArgs
	if strings.TrimSpace(opts.RuntimeBinary) != "" {
		opts.RuntimeArgs = append([]string{strings.TrimSpace(opts.RuntimeBinary)}, opts.RuntimeArgs...)
	}
	opts.Runtime = normalizeModelRunRuntimeName(opts.Runtime)
	if opts.Runtime != "fake" && len(opts.RuntimeArgs) == 0 {
		return modelRunOptions{}, fmt.Errorf("runtime %q requires an explicit runtime command after --", opts.Runtime)
	}
	if strings.TrimSpace(opts.LeasePath) == "" {
		return modelRunOptions{}, fmt.Errorf("zt model run requires --lease <runtime-lease.json>")
	}
	return opts, nil
}

func parseModelPermitIssueArgs(args []string) (modelPermitIssueOptions, error) {
	normalizedArgs, err := reorderInterspersedFlags(args, map[string]bool{
		"runtime": true, "runtime-binary-sha256": true, "device": true, "out": true, "ttl": true,
	})
	if err != nil {
		return modelPermitIssueOptions{}, err
	}
	fs := flagSet("model permit issue")
	var opts modelPermitIssueOptions
	fs.StringVar(&opts.Runtime, "runtime", defaultModelRuntimeName, "Runtime adapter name")
	fs.StringVar(&opts.RuntimeBinarySHA256, "runtime-binary-sha256", "", "Runtime binary SHA-256 for hash-pinned policies")
	fs.StringVar(&opts.DeviceID, "device", hostID(), "Device ID")
	fs.StringVar(&opts.Out, "out", "", "Output runtime lease JSON path")
	fs.DurationVar(&opts.TTL, "ttl", time.Hour, "Permit TTL")
	if err := fs.Parse(normalizedArgs); err != nil {
		return modelPermitIssueOptions{}, err
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return modelPermitIssueOptions{}, fmt.Errorf(cliModelPermitIssueUsage)
	}
	opts.CapsulePath = rest[0]
	if strings.TrimSpace(opts.Out) == "" {
		return modelPermitIssueOptions{}, fmt.Errorf("zt model permit issue requires --out <lease.json>")
	}
	opts.Runtime = strings.TrimSpace(opts.Runtime)
	if opts.Runtime == "" {
		opts.Runtime = defaultModelRuntimeName
	}
	if opts.TTL <= 0 {
		return modelPermitIssueOptions{}, fmt.Errorf("--ttl must be positive")
	}
	return opts, nil
}

func runModelPermitCommand(repoRoot string, args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Println(cliModelPermitUsage)
		return nil
	}
	switch args[0] {
	case "issue":
		opts, err := parseModelPermitIssueArgs(args[1:])
		if err != nil {
			return err
		}
		return runModelPermitIssue(repoRoot, opts)
	default:
		return fmt.Errorf("unknown model permit command: %s\n%s", args[0], cliModelPermitUsage)
	}
}

func runModelPermitIssue(repoRoot string, opts modelPermitIssueOptions) error {
	capsulePath, err := filepath.Abs(opts.CapsulePath)
	if err != nil {
		return fmt.Errorf("invalid capsule path: %w", err)
	}
	tempDir, err := os.MkdirTemp("", "zt-model-permit-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)
	readResult, err := readModelCapsuleArchive(capsulePath, tempDir)
	if err != nil {
		return err
	}
	signedMetadataDir := filepath.Join(tempDir, "signed-metadata")
	receiveOut, receiveErr := newToolAdapters(repoRoot).modernPackReceive(readResult.Payload, signedMetadataDir)
	if receiveErr != nil {
		return fmt.Errorf("model payload metadata extraction failed: %w\n%s", receiveErr, strings.TrimSpace(string(receiveOut)))
	}
	if err := validateModelCapsuleSignedMetadata(readResult, signedMetadataDir); err != nil {
		return err
	}
	priv, err := loadRuntimePermitPrivateKeyFromEnv()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	permit, err := newRuntimePermitForManifest(readResult.Manifest, opts.DeviceID, opts.Runtime, opts.RuntimeBinarySHA256, now, opts.TTL)
	if err != nil {
		return err
	}
	permit, err = signRuntimePermit(permit, runtimePermitKeyIDFromEnv(), priv)
	if err != nil {
		return err
	}
	outPath, err := filepath.Abs(opts.Out)
	if err != nil {
		return fmt.Errorf("invalid lease output path: %w", err)
	}
	if err := writeRuntimeLeaseFile(outPath, runtimeLeaseFileV1{
		SchemaVersion: runtimeLeaseSchemaV1,
		SavedAt:       now.Format(time.RFC3339),
		Permit:        permit,
	}); err != nil {
		return err
	}
	fmt.Printf("[MODEL] runtime lease issued: %s\n", outPath)
	fmt.Printf("[MODEL] permit_id=%s capsule_id=%s expires_at=%s\n", permit.PermitID, permit.CapsuleID, permit.Validity.ExpiresAt)
	return nil
}

func runModelRun(adapters *toolAdapters, opts modelRunOptions) error {
	resetAuditAppendFailureState()
	if cpEvents != nil && opts.NoAutoSync {
		cpEvents.SetAutoSync(false)
	}
	capsulePath, err := filepath.Abs(opts.CapsulePath)
	if err != nil {
		return fmt.Errorf("invalid capsule path: %w", err)
	}
	tempDir, err := os.MkdirTemp("", "zt-model-run-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)
	readResult, err := readModelCapsuleArchive(capsulePath, tempDir)
	if err != nil {
		return err
	}
	out, verifyErr := adapters.modernPackVerify(readResult.Payload)
	if verifyErr != nil {
		emitModelEvent("runtime_denied", readResult.Manifest, readResult.Info, "denied", "runtime.payload_verify_failed", map[string]any{"secure_pack_output": strings.TrimSpace(string(out))})
		return fmt.Errorf("model payload verification failed: %w\n%s", verifyErr, strings.TrimSpace(string(out)))
	}

	signedMetadataDir := filepath.Join(tempDir, "signed-metadata")
	receiveOut, receiveErr := adapters.modernPackReceive(readResult.Payload, signedMetadataDir)
	if receiveErr != nil {
		emitModelEvent("runtime_denied", readResult.Manifest, readResult.Info, "denied", "runtime.payload_extract_failed", map[string]any{"secure_pack_output": strings.TrimSpace(string(receiveOut))})
		return fmt.Errorf("model payload metadata extraction failed: %w\n%s", receiveErr, strings.TrimSpace(string(receiveOut)))
	}
	if err := validateModelCapsuleSignedMetadata(readResult, signedMetadataDir); err != nil {
		emitModelEvent("runtime_denied", readResult.Manifest, readResult.Info, "denied", "runtime.signed_metadata_mismatch", map[string]any{"error": err.Error()})
		return err
	}
	runtimeName, ok := modelPolicyCanonicalRuntime(readResult.Manifest.Policy, opts.Runtime)
	if !ok {
		emitModelEvent("runtime_denied", readResult.Manifest, readResult.Info, "denied", "runtime.policy_runtime_denied", map[string]any{"runtime": opts.Runtime})
		return fmt.Errorf("runtime %q is not allowed by model policy", opts.Runtime)
	}
	pub, err := loadRuntimePermitPublicKey(opts.PermitPubKey)
	if err != nil {
		emitModelEvent("runtime_denied", readResult.Manifest, readResult.Info, "denied", "runtime.permit_public_key_missing", nil)
		return err
	}
	lease, err := validateRuntimeLeaseForManifest(opts.LeasePath, readResult.Manifest, hostID(), runtimeName, time.Now().UTC(), pub)
	if err != nil {
		emitModelEvent("runtime_denied", readResult.Manifest, readResult.Info, "denied", "runtime.permit_invalid", map[string]any{"error": err.Error()})
		return err
	}
	if err := validateRuntimeAllowedUID(lease.Permit); err != nil {
		emitModelEvent("runtime_denied", readResult.Manifest, readResult.Info, "denied", "runtime.allowed_uid_mismatch", map[string]any{"error": err.Error()})
		return err
	}
	shieldTier, err := validateRuntimeShieldForRun(readResult.Manifest, lease.Permit)
	if err != nil {
		emitModelEvent("runtime_denied", readResult.Manifest, readResult.Info, "denied", "runtime.kernel_shield_unavailable", map[string]any{"error": err.Error()})
		return err
	}
	runtimeAdapter, err := modelRuntimeAdapterFor(runtimeName)
	if err != nil {
		emitModelEvent("runtime_denied", readResult.Manifest, readResult.Info, "denied", "runtime.adapter_unsupported", map[string]any{"error": err.Error()})
		return err
	}

	workspace, cleanup, err := prepareModelRunWorkspace(opts)
	if err != nil {
		return err
	}
	if cleanup != nil {
		defer cleanup()
	}
	if !opts.NoExtract {
		if err := stageModelRunPayload(signedMetadataDir, workspace); err != nil {
			emitModelEvent("runtime_denied", readResult.Manifest, readResult.Info, "denied", "runtime.payload_stage_failed", map[string]any{"error": err.Error()})
			return fmt.Errorf("model payload staging failed: %w", err)
		}
	}
	modelView, err := modelRunPrimaryModelView(workspace, readResult.Manifest, !opts.NoExtract)
	if err != nil {
		emitModelEvent("runtime_denied", readResult.Manifest, readResult.Info, "denied", "runtime.model_view_unavailable", map[string]any{"error": err.Error()})
		return err
	}
	runtimeArgs, err := validateRuntimeExecutableHash(lease.Permit, opts.RuntimeArgs)
	if err != nil {
		emitModelEvent("runtime_denied", readResult.Manifest, readResult.Info, "denied", "runtime.binary_hash_mismatch", map[string]any{"error": err.Error()})
		return err
	}
	runtimeArgs, err = runtimeAdapter.BuildCommandArgs(modelRuntimeContext{
		Workspace: workspace,
		Runtime:   runtimeName,
	}, modelView, runtimeArgs)
	if err != nil {
		emitModelEvent("runtime_denied", readResult.Manifest, readResult.Info, "denied", "runtime.command_build_failed", map[string]any{"error": err.Error()})
		return err
	}
	emitModelEvent("runtime_start_requested", readResult.Manifest, readResult.Info, "requested", "runtime.permit_valid", map[string]any{
		"permit_id":  lease.Permit.PermitID,
		"runtime":    runtimeName,
		"model_path": modelView.Path,
	})
	if err := writeModelRunWorkspaceMetadata(workspace, readResult.Manifest, lease.Permit); err != nil {
		return err
	}

	sessionID := prefixedDigestID("sess", readResult.Manifest.CapsuleID, lease.Permit.PermitID, time.Now().UTC().Format(time.RFC3339Nano))
	startedAt := time.Now().UTC().Format(time.RFC3339)
	runtimePID := 0
	sessionStarted := false
	recordRuntimeStart := func(pid int) error {
		runtimePID = pid
		details := map[string]any{"workspace": workspace, "runtime": runtimeName, "pid": pid, "model_path": modelView.Path}
		if localSOR != nil && localSOR.db != nil {
			if err := localSOR.startRuntimeSession(runtimeSessionRecord{
				SessionID:   sessionID,
				TenantID:    readResult.Manifest.Distribution.TenantID,
				ModelID:     readResult.Manifest.Model.ModelID,
				CapsuleID:   readResult.Manifest.CapsuleID,
				PermitID:    lease.Permit.PermitID,
				DeviceID:    lease.Permit.DeviceID,
				RuntimeName: runtimeName,
				PID:         pid,
				ShieldTier:  shieldTier,
				StartedAt:   startedAt,
				Result:      "running",
			}, details); err != nil {
				emitModelEvent("runtime_denied", readResult.Manifest, readResult.Info, "denied", "runtime.session_record_failed", map[string]any{"error": err.Error()})
				return fmt.Errorf("local runtime session record failed: %w", err)
			}
		}
		sessionStarted = true
		emitModelEvent("runtime_started", readResult.Manifest, readResult.Info, "running", modelRuntimeStartedReasonCode(runtimeName, runtimeArgs), map[string]any{
			"session_id":  sessionID,
			"permit_id":   lease.Permit.PermitID,
			"runtime":     runtimeName,
			"workspace":   workspace,
			"model_path":  modelView.Path,
			"pid":         pid,
			"shield_tier": shieldTier,
		})
		return nil
	}
	result, reasonCode, err := runFakeRuntime(workspace, runtimeArgs, recordRuntimeStart)
	endedAt := time.Now().UTC().Format(time.RFC3339)
	var stopSessionErr error
	if sessionStarted && localSOR != nil && localSOR.db != nil {
		stopSessionErr = localSOR.stopRuntimeSession(sessionID, readResult.Manifest.Distribution.TenantID, readResult.Manifest.Model.ModelID, readResult.Manifest.CapsuleID, endedAt, result, reasonCode, map[string]any{"workspace": workspace, "runtime": runtimeName, "pid": runtimePID, "model_path": modelView.Path})
	}
	emitModelEvent("runtime_stopped", readResult.Manifest, readResult.Info, result, reasonCode, map[string]any{
		"session_id":  sessionID,
		"permit_id":   lease.Permit.PermitID,
		"runtime":     runtimeName,
		"workspace":   workspace,
		"model_path":  modelView.Path,
		"pid":         runtimePID,
		"shield_tier": shieldTier,
	})
	if auditFail := consumeAuditAppendFailureState(); auditFail != nil {
		return fmt.Errorf("runtime completed but audit append failed (endpoint=%s): %s", auditFail.Endpoint, auditFail.Message)
	}
	if opts.SyncNow {
		runSyncEvents(true)
	}
	if err != nil {
		return err
	}
	if stopSessionErr != nil {
		return fmt.Errorf("local runtime session close failed: %w", stopSessionErr)
	}
	fmt.Printf("TRUST: model_verified=true permit=valid shield=%s audit=recorded session=%s\n", shieldTier, sessionID)
	return nil
}

func modelRuntimeStartedReasonCode(runtimeName string, args []string) string {
	if strings.EqualFold(strings.TrimSpace(runtimeName), "fake") && len(args) == 0 {
		return "runtime.fake_started"
	}
	return "runtime.child_started"
}

func normalizeModelRunRuntimeName(runtimeName string) string {
	runtimeName = strings.TrimSpace(runtimeName)
	if runtimeName == "" {
		return defaultModelRuntimeName
	}
	if strings.EqualFold(runtimeName, "fake") {
		return "fake"
	}
	return runtimeName
}

func prepareModelRunWorkspace(opts modelRunOptions) (string, func(), error) {
	if strings.TrimSpace(opts.Workspace) != "" {
		workspace, err := filepath.Abs(opts.Workspace)
		if err != nil {
			return "", nil, err
		}
		if err := os.MkdirAll(workspace, 0700); err != nil {
			return "", nil, err
		}
		return workspace, nil, nil
	}
	workspace, err := os.MkdirTemp("", "zt-model-runtime-*")
	if err != nil {
		return "", nil, err
	}
	if opts.KeepWorkspace {
		return workspace, nil, nil
	}
	return workspace, func() { _ = os.RemoveAll(workspace) }, nil
}

func stageModelRunPayload(srcDir, workspace string) error {
	modelDir := filepath.Join(workspace, "model")
	if err := os.RemoveAll(modelDir); err != nil {
		return err
	}
	return copyDir(srcDir, modelDir)
}

func writeModelRunWorkspaceMetadata(workspace string, manifest modelCapsuleManifestV1, permit runtimePermitV1) error {
	manifestJSON, err := marshalModelJSON(manifest)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(workspace, modelCapsuleManifestName), manifestJSON, 0600); err != nil {
		return err
	}
	permitJSON, err := marshalModelJSON(permit)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(workspace, "runtime_permit.json"), permitJSON, 0600)
}

func validateRuntimeAllowedUID(permit runtimePermitV1) error {
	expected := permit.Runtime.AllowedUID
	if expected <= 0 {
		return nil
	}
	actual := os.Getuid()
	if actual != expected {
		return fmt.Errorf("runtime allowed_uid mismatch: expected %d, got %d", expected, actual)
	}
	return nil
}

func validateRuntimeShieldForRun(manifest modelCapsuleManifestV1, permit runtimePermitV1) (string, error) {
	requestedTier := strings.TrimSpace(permit.Policy.ShieldMinTier)
	if requestedTier == "" || requestedTier == runtimePermitShieldTierAuditOnly {
		if manifest.Policy.RequireKernelShield {
			return runtimePermitShieldTierAuditOnly, fmt.Errorf("kernel shield policy requires runtime isolation, but only audit_only runtime shield is available")
		}
		return runtimePermitShieldTierAuditOnly, nil
	}
	if requestedTier == runtimePermitShieldTierKernelMode {
		return runtimePermitShieldTierAuditOnly, fmt.Errorf("kernel shield runtime isolation is required but is not available in this runner")
	}
	return runtimePermitShieldTierAuditOnly, fmt.Errorf("unsupported runtime shield_min_tier %q", requestedTier)
}

func validateRuntimeExecutableHash(permit runtimePermitV1, args []string) ([]string, error) {
	expected := normalizeRuntimeSHA256(permit.Runtime.BinarySHA256)
	if len(args) == 0 {
		if expected == "" {
			return args, nil
		}
		return nil, fmt.Errorf("runtime executable is required for hash-pinned permits")
	}
	executable, err := resolveRuntimeExecutable(args[0])
	if err != nil {
		return nil, err
	}
	if expected != "" {
		actual, err := fileSHA256Hex(executable)
		if err != nil {
			return nil, fmt.Errorf("runtime executable sha256 failed: %w", err)
		}
		if actual != expected {
			return nil, fmt.Errorf("runtime executable sha256 mismatch: expected %s, got %s", expected, actual)
		}
	}
	runtimeArgs := append([]string{executable}, args[1:]...)
	return runtimeArgs, nil
}

func resolveRuntimeExecutable(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("runtime executable is required")
	}
	if filepath.IsAbs(name) || strings.ContainsRune(name, rune(os.PathSeparator)) {
		return filepath.Abs(name)
	}
	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("runtime executable lookup failed: %w", err)
	}
	return path, nil
}

func runFakeRuntime(workspace string, args []string, onStart func(pid int) error) (string, string, error) {
	if len(args) == 0 {
		if onStart != nil {
			if err := onStart(0); err != nil {
				return "failed", "runtime.session_record_failed", err
			}
		}
		fmt.Printf("[MODEL] fake runtime ready workspace=%s\n", workspace)
		return "completed", "runtime.fake_completed", nil
	}
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = workspace
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Start(); err != nil {
		return "failed", "runtime.child_start_failed", err
	}
	if onStart != nil {
		if err := onStart(cmd.Process.Pid); err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return "failed", "runtime.session_record_failed", err
		}
	}
	if err := cmd.Wait(); err != nil {
		return "failed", "runtime.child_failed", err
	}
	return "completed", "runtime.child_completed", nil
}

func splitArgsAtDoubleDash(args []string) ([]string, []string) {
	for i, arg := range args {
		if arg == "--" {
			return append([]string(nil), args[:i]...), append([]string(nil), args[i+1:]...)
		}
	}
	return append([]string(nil), args...), nil
}
