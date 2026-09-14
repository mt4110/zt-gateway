package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type modelPackOptions struct {
	ModelPath      string
	Name           string
	Version        string
	Format         string
	Client         string
	TenantID       string
	Profile        string
	Out            string
	SLSAProvenance string
	OMSSignature   string
	RuntimeFlags   multiStringFlag
	SyncNow        bool
	NoAutoSync     bool
}

type modelVerifyOptions struct {
	CapsulePath string
	ReceiptOut  string
	SyncNow     bool
	NoAutoSync  bool
}

type modelInventoryOptions struct {
	JSON     bool
	TenantID string
	Q        string
	Limit    int
	Offset   int
}

type modelStatusOptions struct {
	JSON     bool
	TenantID string
}

type modelInventoryResponse struct {
	SchemaVersion int                        `json:"schema_version"`
	GeneratedAt   string                     `json:"generated_at"`
	TenantID      string                     `json:"tenant_id"`
	Total         int                        `json:"total"`
	Items         []localSORModelAssetRecord `json:"items"`
	Source        string                     `json:"source"`
	Error         string                     `json:"error,omitempty"`
}

type modelStatusResponse struct {
	SchemaVersion int                           `json:"schema_version"`
	GeneratedAt   string                        `json:"generated_at"`
	TenantID      string                        `json:"tenant_id"`
	Metrics       localSORModelInventoryMetrics `json:"metrics"`
	ShieldTier    string                        `json:"shield_tier"`
	LocalSOR      string                        `json:"local_sor"`
	Error         string                        `json:"error,omitempty"`
}

type modelVerificationReceipt struct {
	SchemaVersion string                           `json:"schema_version"`
	ReceiptID     string                           `json:"receipt_id"`
	VerifiedAt    string                           `json:"verified_at"`
	Model         modelVerificationReceiptModel    `json:"model"`
	Artifact      modelVerificationReceiptArtifact `json:"artifact"`
	Verification  modelVerificationResult          `json:"verification"`
	Tooling       receiptTooling                   `json:"tooling"`
}

type modelVerificationReceiptModel struct {
	ModelID   string `json:"model_id"`
	CapsuleID string `json:"capsule_id"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Format    string `json:"format"`
	TenantID  string `json:"tenant_id"`
	ClientID  string `json:"client_id"`
}

type modelVerificationReceiptArtifact struct {
	Path             string `json:"path"`
	CapsuleSHA256    string `json:"capsule_sha256"`
	ArtifactSHA256   string `json:"artifact_sha256"`
	ManifestSHA256   string `json:"manifest_sha256"`
	SecurePackSHA256 string `json:"secure_pack_sha256"`
}

type modelVerificationResult struct {
	ManifestValid         bool   `json:"manifest_valid"`
	PolicyValid           bool   `json:"policy_valid"`
	PayloadSignatureValid bool   `json:"payload_signature_valid"`
	TamperDetected        bool   `json:"tamper_detected"`
	PolicyResult          string `json:"policy_result"`
	SignerFingerprint     string `json:"signer_fingerprint,omitempty"`
	ShieldTier            string `json:"shield_tier"`
}

func runModelCommand(repoRoot string, adapters *toolAdapters, args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		printModelUsage()
		return nil
	}
	switch args[0] {
	case "pack":
		opts, err := parseModelPackArgs(args[1:])
		if err != nil {
			return err
		}
		return runModelPack(repoRoot, adapters, opts)
	case "verify":
		opts, err := parseModelVerifyArgs(args[1:])
		if err != nil {
			return err
		}
		return runModelVerify(repoRoot, adapters, opts)
	case "run":
		opts, err := parseModelRunArgs(args[1:])
		if err != nil {
			return err
		}
		return runModelRun(adapters, opts)
	case "permit":
		return runModelPermitCommand(repoRoot, args[1:])
	case "inventory":
		opts, err := parseModelInventoryArgs(args[1:])
		if err != nil {
			return err
		}
		return runModelInventory(repoRoot, opts)
	case "status":
		opts, err := parseModelStatusArgs(args[1:])
		if err != nil {
			return err
		}
		return runModelStatus(repoRoot, opts)
	default:
		return fmt.Errorf("unknown model command: %s\n%s", args[0], cliModelUsage)
	}
}

func parseModelPackArgs(args []string) (modelPackOptions, error) {
	fs := flag.NewFlagSet("model pack", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var opts modelPackOptions
	fs.StringVar(&opts.Name, "name", "", "Model name")
	fs.StringVar(&opts.Version, "version", "", "Model version")
	fs.StringVar(&opts.Format, "format", "", "Model format: gguf|safetensors|pt|pth|bin|onnx")
	fs.StringVar(&opts.Client, "client", "", "Recipient client name")
	fs.StringVar(&opts.TenantID, "tenant", "local-default", "Tenant ID for model passport")
	fs.StringVar(&opts.Profile, "profile", defaultModelPolicyProfile, "Trust profile: public|internal|confidential|regulated")
	fs.StringVar(&opts.Out, "out", "", "Output .zmc path or directory")
	fs.StringVar(&opts.SLSAProvenance, "slsa-provenance", "", "SLSA provenance JSON file for signed provenance policies")
	fs.StringVar(&opts.OMSSignature, "oms-signature", "", "OMS detached signature file for signed provenance policies")
	fs.Var(&opts.RuntimeFlags, "runtime", "Allowed runtime name (repeatable or comma-separated)")
	fs.BoolVar(&opts.SyncNow, "sync-now", false, "Force-sync local model event spool to control plane after command")
	fs.BoolVar(&opts.NoAutoSync, "no-auto-sync", false, "Disable background auto-sync to control plane")
	normalizedArgs, err := reorderInterspersedFlags(args, map[string]bool{
		"name": true, "version": true, "format": true, "client": true,
		"tenant": true, "profile": true, "out": true, "slsa-provenance": true, "oms-signature": true, "runtime": true,
	})
	if err != nil {
		return modelPackOptions{}, err
	}
	if err := fs.Parse(normalizedArgs); err != nil {
		return modelPackOptions{}, err
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return modelPackOptions{}, fmt.Errorf(cliModelPackUsage)
	}
	opts.ModelPath = rest[0]
	opts.Client = strings.TrimSpace(opts.Client)
	if opts.Client == "" {
		return modelPackOptions{}, fmt.Errorf("zt model pack requires --client <name>")
	}
	opts.Name = strings.TrimSpace(opts.Name)
	if opts.Name == "" {
		return modelPackOptions{}, fmt.Errorf("zt model pack requires --name <name>")
	}
	opts.Version = strings.TrimSpace(opts.Version)
	if opts.Version == "" {
		return modelPackOptions{}, fmt.Errorf("zt model pack requires --version <version>")
	}
	profile, err := validateTrustProfile(opts.Profile)
	if err != nil {
		return modelPackOptions{}, err
	}
	opts.Profile = profile
	return opts, nil
}

func parseModelVerifyArgs(args []string) (modelVerifyOptions, error) {
	fs := flag.NewFlagSet("model verify", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var opts modelVerifyOptions
	fs.StringVar(&opts.ReceiptOut, "receipt-out", "", "Write model verification receipt JSON to file path")
	fs.BoolVar(&opts.SyncNow, "sync-now", false, "Force-sync local model event spool to control plane after command")
	fs.BoolVar(&opts.NoAutoSync, "no-auto-sync", false, "Disable background auto-sync to control plane")
	normalizedArgs, err := reorderInterspersedFlags(args, map[string]bool{"receipt-out": true})
	if err != nil {
		return modelVerifyOptions{}, err
	}
	if err := fs.Parse(normalizedArgs); err != nil {
		return modelVerifyOptions{}, err
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return modelVerifyOptions{}, fmt.Errorf(cliModelVerifyUsage)
	}
	opts.CapsulePath = rest[0]
	return opts, nil
}

func parseModelInventoryArgs(args []string) (modelInventoryOptions, error) {
	fs := flag.NewFlagSet("model inventory", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var opts modelInventoryOptions
	fs.BoolVar(&opts.JSON, "json", false, "Emit machine-readable JSON")
	fs.StringVar(&opts.TenantID, "tenant", "", "Tenant ID scope")
	fs.StringVar(&opts.Q, "q", "", "Filter by model id, name, version or format")
	fs.IntVar(&opts.Limit, "limit", 20, "Maximum rows")
	fs.IntVar(&opts.Offset, "offset", 0, "Row offset")
	if err := fs.Parse(args); err != nil {
		return modelInventoryOptions{}, err
	}
	if len(fs.Args()) != 0 {
		return modelInventoryOptions{}, fmt.Errorf(cliModelInventoryUsage)
	}
	return opts, nil
}

func parseModelStatusArgs(args []string) (modelStatusOptions, error) {
	fs := flag.NewFlagSet("model status", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var opts modelStatusOptions
	fs.BoolVar(&opts.JSON, "json", false, "Emit machine-readable JSON")
	fs.StringVar(&opts.TenantID, "tenant", "", "Tenant ID scope")
	if err := fs.Parse(args); err != nil {
		return modelStatusOptions{}, err
	}
	if len(fs.Args()) != 0 {
		return modelStatusOptions{}, fmt.Errorf(cliModelStatusUsage)
	}
	return opts, nil
}

func runModelPack(repoRoot string, adapters *toolAdapters, opts modelPackOptions) error {
	resetAuditAppendFailureState()
	if cpEvents != nil && opts.NoAutoSync {
		cpEvents.SetAutoSync(false)
	}
	modelPath, err := filepath.Abs(opts.ModelPath)
	if err != nil {
		return fmt.Errorf("invalid model path: %w", err)
	}
	stageDir, err := os.MkdirTemp("", "zt-model-stage-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stageDir)
	payloadDir, err := os.MkdirTemp("", "zt-model-payload-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(payloadDir)

	modelName := filepath.Base(modelPath)
	if isReservedModelArtifactName(modelName) {
		return fmt.Errorf("model artifact filename %q is reserved for capsule metadata", modelName)
	}
	stagedModelPath := filepath.Join(stageDir, modelName)
	if err := copyFile(modelPath, stagedModelPath); err != nil {
		return fmt.Errorf("stage model file: %w", err)
	}
	slsaProvenancePath, omsSignaturePath, err := stageModelPackProvenance(stageDir, opts)
	if err != nil {
		return err
	}
	manifest, err := buildModelCapsuleManifest(buildModelManifestInput{
		ModelPath:          stagedModelPath,
		Name:               opts.Name,
		Version:            opts.Version,
		Format:             opts.Format,
		ClientID:           opts.Client,
		TenantID:           opts.TenantID,
		Profile:            opts.Profile,
		Runtimes:           opts.RuntimeFlags.Values,
		RepoRoot:           repoRoot,
		CreatedAt:          time.Now().UTC(),
		SLSAProvenancePath: slsaProvenancePath,
		OMSSignaturePath:   omsSignaturePath,
	})
	if err != nil {
		return err
	}
	fmt.Println("[MODEL] Scanning model artifact...")
	scanOut, scanStderr, scanErr := adapters.modelScanCheckJSON(stagedModelPath, manifest.Policy.Profile)
	var scanRes ScanResult
	if len(scanOut) == 0 {
		if len(scanStderr) > 0 {
			return fmt.Errorf("model scan failed: %s", strings.TrimSpace(string(scanStderr)))
		}
		if scanErr != nil {
			return fmt.Errorf("model scan failed: %w", scanErr)
		}
		return fmt.Errorf("model scan produced no JSON output")
	}
	if err := json.Unmarshal(scanOut, &scanRes); err != nil {
		return fmt.Errorf("failed to parse model scan result: %w\n%s", err, strings.TrimSpace(string(scanOut)))
	}
	emitModelScanEvent(manifest, stagedModelPath, scanOut)
	if scanErr != nil && scanRes.Result == "" {
		return fmt.Errorf("model scan failed: %w\n%s", scanErr, strings.TrimSpace(string(scanOut)))
	}
	switch scanRes.Result {
	case "allow":
		if err := enforceModelScanPolicy(scanRes, manifest.Policy, manifest.Model.Format); err != nil {
			return fmt.Errorf("model scan denied by model policy: %w", err)
		}
		fmt.Printf("[MODEL] Scan passed: %s\n", scanRes.Reason)
	case "warn":
		if err := enforceModelScanPolicy(scanRes, manifest.Policy, manifest.Model.Format); err != nil {
			return fmt.Errorf("model scan denied by model policy: %w", err)
		}
		fmt.Printf("[MODEL] Scan warning: %s\n", scanRes.Reason)
	case "deny":
		return fmt.Errorf("model scan denied artifact: %s", scanRes.Reason)
	default:
		return fmt.Errorf("model scan returned unknown result %q", scanRes.Result)
	}

	outPath, err := resolveModelOutputPath(opts.Out, manifest.Model.Name, manifest.Model.Version)
	if err != nil {
		return err
	}
	manifestJSON, err := marshalModelJSON(manifest)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(stageDir, modelCapsuleManifestName), manifestJSON, 0644); err != nil {
		return err
	}
	policyJSON, err := marshalModelJSON(manifest.Policy)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(stageDir, modelCapsulePolicyName), policyJSON, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(stageDir, "scan_result.json"), scanOut, 0644); err != nil {
		return err
	}

	fmt.Printf("[MODEL] Packing %s as %s %s (%s)\n", modelPath, manifest.Model.Name, manifest.Model.Version, manifest.Model.Format)
	fmt.Printf("[MODEL] profile=%s client=%s tenant=%s\n", manifest.Policy.Profile, manifest.Distribution.ClientID, manifest.Distribution.TenantID)
	packetPath, packOut, packErr := adapters.modernPackDocsDir(stageDir, payloadDir, opts.Client)
	if packErr != nil {
		return fmt.Errorf("model secure-pack failed: %w\n%s", packErr, strings.TrimSpace(string(packOut)))
	}
	payloadSHA, err := fileSHA256Hex(packetPath)
	if err != nil {
		return err
	}
	manifest.Provenance.SecurePackSHA256 = payloadSHA
	info, err := writeModelCapsuleArchive(outPath, manifest, packetPath)
	if err != nil {
		return err
	}
	if localSOR != nil && localSOR.db != nil {
		if err := localSOR.upsertModelCapsule(manifest, info, "", time.Now().UTC()); err != nil {
			return fmt.Errorf("local model inventory update failed: %w", err)
		}
	}
	emitModelPassport(manifest)
	emitModelEvent("model_pack_completed", manifest, info, "success", "model.capsule_created", nil)
	if auditFail := consumeAuditAppendFailureState(); auditFail != nil {
		return fmt.Errorf("model capsule created but audit append failed (endpoint=%s): %s", auditFail.Endpoint, auditFail.Message)
	}
	if opts.SyncNow {
		runSyncEvents(true)
	}
	fmt.Printf("[MODEL] Capsule generated: %s\n", info.Path)
	fmt.Printf("[MODEL] model_id=%s capsule_id=%s artifact_sha256=%s\n", manifest.Model.ModelID, manifest.CapsuleID, manifest.Artifacts[0].SHA256)
	fmt.Printf("TRUST: model_verified=true permit=not_required shield=audit_only audit=recorded capsule=%s\n", manifest.CapsuleID)
	_ = repoRoot
	return nil
}

func enforceModelScanPolicy(scanRes ScanResult, policy modelPolicyV1, manifestFormat string) error {
	format := normalizeModelFormat(scanRes.ModelFormat)
	if format == "" {
		format = normalizeModelFormat(manifestFormat)
	}
	if policy.Formats != nil && stringListContainsNormalizedFormat(policy.Formats.Deny, format) {
		return fmt.Errorf("policy.formats.deny rejects model format %q", format)
	}
	if policy.Scan == nil {
		return nil
	}
	if policy.Scan.DenySecretPatterns && scanHasFindingCategory(scanRes, "secret") {
		return fmt.Errorf("policy.scan.deny_secret_patterns rejects secret findings")
	}
	if policy.Scan.DenyPickleSerialization && (isPickleModelFormat(format) || scanHasFindingCategory(scanRes, "unsafe_serialization")) {
		return fmt.Errorf("policy.scan.deny_pickle_serialization rejects unsafe serialization")
	}
	return nil
}

func scanHasFindingCategory(scanRes ScanResult, category string) bool {
	category = strings.TrimSpace(category)
	for _, finding := range scanRes.Findings {
		if strings.TrimSpace(finding.Category) == category {
			return true
		}
	}
	return false
}

func stringListContainsNormalizedFormat(values []string, format string) bool {
	format = normalizeModelFormat(format)
	if format == "" {
		return false
	}
	for _, value := range values {
		if normalizeModelFormat(value) == format {
			return true
		}
	}
	return false
}

func isPickleModelFormat(format string) bool {
	switch normalizeModelFormat(format) {
	case "pt", "pth", "bin":
		return true
	default:
		return false
	}
}

func stageModelPackProvenance(stageDir string, opts modelPackOptions) (string, string, error) {
	slsaPath, err := stageModelPackProvenanceFile(
		strings.TrimSpace(opts.SLSAProvenance),
		filepath.Join(stageDir, modelCapsuleProvenanceDir, modelCapsuleSLSAProvenanceName),
		"SLSA provenance",
	)
	if err != nil {
		return "", "", err
	}
	omsPath, err := stageModelPackProvenanceFile(
		strings.TrimSpace(opts.OMSSignature),
		filepath.Join(stageDir, modelCapsuleSignaturesDir, modelCapsuleOMSSignatureName),
		"OMS signature",
	)
	if err != nil {
		return "", "", err
	}
	return slsaPath, omsPath, nil
}

func stageModelPackProvenanceFile(src, dst, label string) (string, error) {
	if src == "" {
		return "", nil
	}
	srcPath, err := filepath.Abs(src)
	if err != nil {
		return "", fmt.Errorf("invalid %s path: %w", label, err)
	}
	info, err := os.Lstat(srcPath)
	if err != nil {
		return "", fmt.Errorf("%s file is required: %w", label, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s path must be a regular file: %s", label, srcPath)
	}
	if info.Size() == 0 {
		return "", fmt.Errorf("%s file must not be empty: %s", label, srcPath)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
		return "", err
	}
	if err := copyFile(srcPath, dst); err != nil {
		return "", fmt.Errorf("stage %s file: %w", label, err)
	}
	return dst, nil
}

func runModelVerify(repoRoot string, adapters *toolAdapters, opts modelVerifyOptions) error {
	resetAuditAppendFailureState()
	if cpEvents != nil && opts.NoAutoSync {
		cpEvents.SetAutoSync(false)
	}
	capsulePath, err := filepath.Abs(opts.CapsulePath)
	if err != nil {
		return fmt.Errorf("invalid capsule path: %w", err)
	}
	if !stringsHasSuffixFold(capsulePath, ".zmc") {
		return fmt.Errorf("zt model verify supports only .zmc capsules")
	}
	tempDir, err := os.MkdirTemp("", "zt-model-verify-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)
	readResult, err := readModelCapsuleArchive(capsulePath, tempDir)
	if err != nil {
		return err
	}

	fmt.Printf("[MODEL] Verifying capsule: %s\n", capsulePath)
	out, verifyErr := adapters.modernPackVerify(readResult.Payload)
	if verifyErr != nil {
		emitModelEvent("model_verify_completed", readResult.Manifest, readResult.Info, "failed", "model.secure_pack_verify_failed", map[string]any{
			"secure_pack_output": strings.TrimSpace(string(out)),
		})
		if opts.SyncNow {
			runSyncEvents(true)
		}
		return fmt.Errorf("model payload verification failed: %w\n%s", verifyErr, strings.TrimSpace(string(out)))
	}
	signedMetadataDir := filepath.Join(tempDir, "signed-metadata")
	receiveOut, receiveErr := adapters.modernPackReceive(readResult.Payload, signedMetadataDir)
	if receiveErr != nil {
		emitModelEvent("model_verify_completed", readResult.Manifest, readResult.Info, "failed", "model.payload_extract_failed", map[string]any{
			"secure_pack_output": strings.TrimSpace(string(receiveOut)),
		})
		if opts.SyncNow {
			runSyncEvents(true)
		}
		return fmt.Errorf("model payload metadata extraction failed: %w\n%s", receiveErr, strings.TrimSpace(string(receiveOut)))
	}
	if err := validateModelCapsuleSignedMetadata(readResult, signedMetadataDir); err != nil {
		emitModelEvent("model_verify_completed", readResult.Manifest, readResult.Info, "failed", "model.signed_metadata_mismatch", map[string]any{"error": err.Error()})
		if opts.SyncNow {
			runSyncEvents(true)
		}
		return err
	}
	signerFingerprint, signerErr := extractVerifiedSignerFingerprint(string(out))
	if signerErr != nil {
		return signerErr
	}
	receipt := buildModelVerificationReceipt(capsulePath, readResult, signerFingerprint)
	if strings.TrimSpace(opts.ReceiptOut) != "" {
		receiptPath, err := filepath.Abs(opts.ReceiptOut)
		if err != nil {
			return fmt.Errorf("invalid receipt path: %w", err)
		}
		if err := writeModelVerificationReceipt(receiptPath, receipt); err != nil {
			return err
		}
		fmt.Printf("[RECEIPT] saved: %s\n", receiptPath)
	} else {
		fmt.Printf("[RECEIPT] id=%s verified_at=%s\n", receipt.ReceiptID, receipt.VerifiedAt)
	}
	if localSOR != nil && localSOR.db != nil {
		if err := localSOR.recordModelVerify(readResult.Manifest, readResult.Info, signerFingerprint, "verified", "model.verified", time.Now().UTC()); err != nil {
			return fmt.Errorf("local model inventory update failed: %w", err)
		}
	}
	emitModelEvent("model_verify_completed", readResult.Manifest, readResult.Info, "verified", "model.verified", map[string]any{
		"signer_fingerprint": signerFingerprint,
	})
	if auditFail := consumeAuditAppendFailureState(); auditFail != nil {
		return fmt.Errorf("model verify succeeded but audit append failed (endpoint=%s): %s", auditFail.Endpoint, auditFail.Message)
	}
	if opts.SyncNow {
		runSyncEvents(true)
	}
	fmt.Println("[VERIFIED] Model capsule trust established.")
	fmt.Printf("TRUST: model_verified=true permit=not_required shield=audit_only audit=recorded capsule=%s\n", readResult.Manifest.CapsuleID)
	_ = repoRoot
	return nil
}

func runModelInventory(repoRoot string, opts modelInventoryOptions) error {
	tenantID := resolveModelTenantScope(repoRoot, opts.TenantID)
	resp := modelInventoryResponse{
		SchemaVersion: 1,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		TenantID:      tenantID,
		Source:        "local_sor",
		Items:         []localSORModelAssetRecord{},
	}
	if localSOR == nil || localSOR.db == nil {
		resp.Error = "local_sor_unavailable"
		return emitModelInventoryResponse(resp, opts.JSON)
	}
	items, total, err := localSOR.listModelAssets(tenantID, opts.Q, opts.Limit, opts.Offset, false)
	if err != nil {
		resp.Error = err.Error()
		return emitModelInventoryResponse(resp, opts.JSON)
	}
	resp.Items = items
	resp.Total = total
	return emitModelInventoryResponse(resp, opts.JSON)
}

func runModelStatus(repoRoot string, opts modelStatusOptions) error {
	tenantID := resolveModelTenantScope(repoRoot, opts.TenantID)
	resp := modelStatusResponse{
		SchemaVersion: 1,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		TenantID:      tenantID,
		ShieldTier:    "audit_only",
		LocalSOR:      "available",
	}
	if localSOR == nil || localSOR.db == nil {
		resp.LocalSOR = "unavailable"
		resp.Error = "local_sor_unavailable"
		return emitModelStatusResponse(resp, opts.JSON)
	}
	metrics, err := localSOR.collectModelInventoryMetrics(tenantID, time.Now().UTC())
	if err != nil {
		resp.Error = err.Error()
		return emitModelStatusResponse(resp, opts.JSON)
	}
	resp.Metrics = metrics
	return emitModelStatusResponse(resp, opts.JSON)
}

func resolveModelOutputPath(raw, name, version string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		return filepath.Join(cwd, modelCapsuleOutputName(name, version)), nil
	}
	out := strings.TrimSpace(raw)
	if info, err := os.Stat(out); err == nil && info.IsDir() {
		return filepath.Join(out, modelCapsuleOutputName(name, version)), nil
	}
	if strings.HasSuffix(out, string(os.PathSeparator)) {
		return filepath.Join(out, modelCapsuleOutputName(name, version)), nil
	}
	if filepath.Ext(out) == "" {
		return filepath.Join(out, modelCapsuleOutputName(name, version)), nil
	}
	if !stringsHasSuffixFold(out, ".zmc") {
		return "", fmt.Errorf("model capsule output must end with .zmc")
	}
	return filepath.Abs(out)
}

func buildModelVerificationReceipt(capsulePath string, readResult modelCapsuleReadResult, signerFingerprint string) modelVerificationReceipt {
	now := time.Now().UTC().Format(time.RFC3339)
	manifest := readResult.Manifest
	artifactSHA := ""
	if len(manifest.Artifacts) > 0 {
		artifactSHA = manifest.Artifacts[0].SHA256
	}
	return modelVerificationReceipt{
		SchemaVersion: "zt-model-verification-receipt-v1",
		ReceiptID:     buildReceiptID(readResult.Info.CapsuleSHA256, now),
		VerifiedAt:    now,
		Model: modelVerificationReceiptModel{
			ModelID:   manifest.Model.ModelID,
			CapsuleID: manifest.CapsuleID,
			Name:      manifest.Model.Name,
			Version:   manifest.Model.Version,
			Format:    manifest.Model.Format,
			TenantID:  manifest.Distribution.TenantID,
			ClientID:  manifest.Distribution.ClientID,
		},
		Artifact: modelVerificationReceiptArtifact{
			Path:             capsulePath,
			CapsuleSHA256:    readResult.Info.CapsuleSHA256,
			ArtifactSHA256:   artifactSHA,
			ManifestSHA256:   readResult.Info.ManifestSHA256,
			SecurePackSHA256: readResult.Info.PayloadSHA256,
		},
		Verification: modelVerificationResult{
			ManifestValid:         true,
			PolicyValid:           true,
			PayloadSignatureValid: true,
			TamperDetected:        false,
			PolicyResult:          "pass",
			SignerFingerprint:     signerFingerprint,
			ShieldTier:            "audit_only",
		},
		Tooling: receiptTooling{
			ZTVersion:         ztVersion,
			SecurePackVersion: resolveSecurePackVersion(),
		},
	}
}

func writeModelVerificationReceipt(path string, receipt modelVerificationReceipt) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(receipt); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func emitModelInventoryResponse(resp modelInventoryResponse, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(resp)
	}
	if resp.Error != "" {
		fmt.Printf("[MODEL] inventory unavailable: %s\n", resp.Error)
		return nil
	}
	fmt.Printf("[MODEL] inventory tenant=%s total=%d\n", resp.TenantID, resp.Total)
	for _, item := range resp.Items {
		fmt.Printf("%s %s %s %s %s\n", item.ModelID, item.Name, item.Version, item.Format, item.Status)
	}
	return nil
}

func emitModelStatusResponse(resp modelStatusResponse, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(resp)
	}
	if resp.Error != "" {
		fmt.Printf("[MODEL] status attention required: %s\n", resp.Error)
	}
	fmt.Printf("[MODEL] tenant=%s models=%d capsules=%d shield=%s local_sor=%s\n", resp.TenantID, resp.Metrics.TotalModels, resp.Metrics.TotalCapsules, resp.ShieldTier, resp.LocalSOR)
	return nil
}

func resolveModelTenantScope(repoRoot, explicit string) string {
	if v := strings.TrimSpace(explicit); v != "" {
		return v
	}
	if v := strings.TrimSpace(resolveDashboardTenantScope(repoRoot)); v != "" {
		return v
	}
	return "local-default"
}

func printModelUsage() {
	fmt.Println(cliModelUsage)
	fmt.Println("")
	fmt.Println("Commands:")
	fmt.Printf("  %s\n", cliModelPackSignature)
	fmt.Printf("  %s\n", cliModelVerifySignature)
	fmt.Printf("  %s\n", cliModelRunSignature)
	fmt.Printf("  %s\n", cliModelPermitIssueSignature)
	fmt.Printf("  %s\n", cliModelInventorySignature)
	fmt.Printf("  %s\n", cliModelStatusSignature)
}

func reorderInterspersedFlags(args []string, valueFlags map[string]bool) ([]string, error) {
	flags := make([]string, 0, len(args))
	positionals := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := strings.TrimSpace(args[i])
		if arg == "--" {
			positionals = append(positionals, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			positionals = append(positionals, args[i])
			continue
		}
		flags = append(flags, args[i])
		name := strings.TrimLeft(arg, "-")
		if eq := strings.Index(name, "="); eq >= 0 {
			continue
		}
		if valueFlags[name] {
			if i+1 >= len(args) {
				return nil, fmt.Errorf("flag needs an argument: --%s", name)
			}
			i++
			flags = append(flags, args[i])
		}
	}
	return append(flags, positionals...), nil
}
