package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	modelCapsuleManifestSchemaV1 = "zt-model-capsule-v1"
	modelPolicySchemaV1          = "zt-model-policy-v1"
	modelArtifactKindWeight      = "weight"
	defaultModelPolicyProfile    = trustProfileConfidential
	defaultOfflineLeaseSeconds   = 86400
	defaultModelRuntimeName      = "llama.cpp"
)

var modelCapsuleIDSafeRE = regexp.MustCompile(`[^A-Za-z0-9_.-]+`)
var defaultModelAllowedRuntimes = []string{defaultModelRuntimeName}

type modelCapsuleManifestV1 struct {
	SchemaVersion string                    `json:"schema_version"`
	CapsuleID     string                    `json:"capsule_id"`
	Model         modelManifestModel        `json:"model"`
	Artifacts     []modelManifestArtifact   `json:"artifacts"`
	Policy        modelPolicyV1             `json:"policy"`
	Provenance    modelManifestProvenance   `json:"provenance"`
	Distribution  modelManifestDistribution `json:"distribution"`
}

type modelManifestModel struct {
	ModelID           string `json:"model_id"`
	Name              string `json:"name"`
	Version           string `json:"version"`
	Format            string `json:"format"`
	BaseModel         string `json:"base_model,omitempty"`
	Quantization      string `json:"quantization,omitempty"`
	DeclaredSizeBytes int64  `json:"declared_size_bytes"`
}

type modelManifestArtifact struct {
	Path        string `json:"path"`
	Kind        string `json:"kind"`
	SHA256      string `json:"sha256"`
	SizeBytes   int64  `json:"size_bytes"`
	ContentType string `json:"content_type,omitempty"`
}

type modelPolicyV1 struct {
	SchemaVersion       string                       `json:"schema_version,omitempty"`
	Profile             string                       `json:"profile"`
	AllowedRuntimes     []string                     `json:"allowed_runtimes"`
	RuntimeBinaryHashes []string                     `json:"runtime_binary_hashes,omitempty"`
	OfflineLeaseSeconds int                          `json:"offline_lease_seconds"`
	RequireKernelShield bool                         `json:"require_kernel_shield"`
	RequireAttestation  bool                         `json:"require_attestation"`
	Formats             *modelPolicyFormatRules      `json:"formats,omitempty"`
	Scan                *modelPolicyScanRequirements `json:"scan,omitempty"`
	EgressPolicyID      string                       `json:"egress_policy_id,omitempty"`
}

type modelPolicyFormatRules struct {
	Allow []string `json:"allow,omitempty"`
	Warn  []string `json:"warn,omitempty"`
	Deny  []string `json:"deny,omitempty"`
}

type modelPolicyScanRequirements struct {
	DenySecretPatterns      bool `json:"deny_secret_patterns"`
	DenyPickleSerialization bool `json:"deny_pickle_serialization"`
	RequireSignedProvenance bool `json:"require_signed_provenance"`
}

type modelManifestProvenance struct {
	SLSAProvenanceSHA256 string `json:"slsa_provenance_sha256,omitempty"`
	OMSSignatureSHA256   string `json:"oms_signature_sha256,omitempty"`
	BuildID              string `json:"build_id,omitempty"`
	SourceRef            string `json:"source_ref,omitempty"`
	SecurePackSHA256     string `json:"secure_pack_sha256,omitempty"`
}

type modelManifestDistribution struct {
	TenantID    string `json:"tenant_id"`
	ClientID    string `json:"client_id"`
	WatermarkID string `json:"watermark_id,omitempty"`
	CreatedAt   string `json:"created_at"`
}

type buildModelManifestInput struct {
	ModelPath          string
	Name               string
	Version            string
	Format             string
	ClientID           string
	TenantID           string
	Profile            string
	Runtimes           []string
	RepoRoot           string
	CreatedAt          time.Time
	BaseModel          string
	Quantization       string
	SLSAProvenancePath string
	OMSSignaturePath   string
}

func buildModelCapsuleManifest(input buildModelManifestInput) (modelCapsuleManifestV1, error) {
	modelPath := strings.TrimSpace(input.ModelPath)
	if modelPath == "" {
		return modelCapsuleManifestV1{}, fmt.Errorf("model path is required")
	}
	info, err := os.Stat(modelPath)
	if err != nil {
		return modelCapsuleManifestV1{}, err
	}
	if !info.Mode().IsRegular() {
		return modelCapsuleManifestV1{}, fmt.Errorf("model path must be a regular file: %s", modelPath)
	}

	name := strings.TrimSpace(input.Name)
	if name == "" {
		return modelCapsuleManifestV1{}, fmt.Errorf("model name is required")
	}
	version := strings.TrimSpace(input.Version)
	if version == "" {
		return modelCapsuleManifestV1{}, fmt.Errorf("model version is required")
	}
	format := normalizeModelFormat(input.Format)
	if format == "" {
		format = inferModelFormatFromPath(modelPath)
	}
	if format == "" {
		return modelCapsuleManifestV1{}, fmt.Errorf("model format is required")
	}
	if err := validateModelFormat(format); err != nil {
		return modelCapsuleManifestV1{}, err
	}
	artifactName := filepath.Base(modelPath)
	if isReservedModelArtifactName(artifactName) {
		return modelCapsuleManifestV1{}, fmt.Errorf("model artifact filename %q is reserved for capsule metadata", artifactName)
	}

	profile := strings.TrimSpace(input.Profile)
	if profile == "" {
		profile = defaultModelPolicyProfile
	}
	profile, err = validateTrustProfile(profile)
	if err != nil {
		return modelCapsuleManifestV1{}, err
	}

	createdAt := input.CreatedAt.UTC()
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	tenantID := strings.TrimSpace(input.TenantID)
	if tenantID == "" {
		tenantID = "local-default"
	}
	clientID := strings.TrimSpace(input.ClientID)
	if clientID == "" {
		return modelCapsuleManifestV1{}, fmt.Errorf("client id is required")
	}

	artifactSHA, err := fileSHA256Hex(modelPath)
	if err != nil {
		return modelCapsuleManifestV1{}, err
	}
	modelID := prefixedDigestID("mdl", name, version, format, artifactSHA)
	capsuleID := prefixedDigestID("zmc", modelID, tenantID, clientID, createdAt.Format(time.RFC3339Nano))
	policy, err := buildModelPolicyForManifest(input.RepoRoot, profile, input.Runtimes)
	if err != nil {
		return modelCapsuleManifestV1{}, err
	}
	provenance, err := buildModelManifestProvenance(input, policy)
	if err != nil {
		return modelCapsuleManifestV1{}, err
	}

	manifest := modelCapsuleManifestV1{
		SchemaVersion: modelCapsuleManifestSchemaV1,
		CapsuleID:     capsuleID,
		Model: modelManifestModel{
			ModelID:           modelID,
			Name:              name,
			Version:           version,
			Format:            format,
			BaseModel:         strings.TrimSpace(input.BaseModel),
			Quantization:      strings.TrimSpace(input.Quantization),
			DeclaredSizeBytes: info.Size(),
		},
		Artifacts: []modelManifestArtifact{
			{
				Path:        artifactName,
				Kind:        modelArtifactKindWeight,
				SHA256:      artifactSHA,
				SizeBytes:   info.Size(),
				ContentType: modelContentType(format),
			},
		},
		Policy:     policy,
		Provenance: provenance,
		Distribution: modelManifestDistribution{
			TenantID:  tenantID,
			ClientID:  clientID,
			CreatedAt: createdAt.Format(time.RFC3339),
		},
	}
	if err := validateModelCapsuleManifest(manifest); err != nil {
		return modelCapsuleManifestV1{}, err
	}
	return manifest, nil
}

func buildModelPolicyForManifest(repoRoot, profile string, requestedRuntimes []string) (modelPolicyV1, error) {
	if strings.TrimSpace(repoRoot) == "" {
		return modelPolicyV1{
			SchemaVersion:       modelPolicySchemaV1,
			Profile:             profile,
			AllowedRuntimes:     normalizeModelRuntimes(requestedRuntimes),
			OfflineLeaseSeconds: defaultOfflineLeaseSeconds,
			RequireKernelShield: false,
			RequireAttestation:  false,
		}, nil
	}
	policyPath, err := resolveModelPolicyPath(repoRoot, profile)
	if err != nil {
		return modelPolicyV1{}, err
	}
	policy, err := loadModelPolicy(policyPath, profile)
	if err != nil {
		return modelPolicyV1{}, err
	}
	requested := normalizeModelRuntimeInputs(requestedRuntimes)
	if len(requested) > 0 {
		selected := make([]string, 0, len(requested))
		for _, runtimeName := range requested {
			canonical, ok := modelPolicyCanonicalRuntime(policy, runtimeName)
			if !ok {
				return modelPolicyV1{}, fmt.Errorf("runtime %q is not allowed by model policy %s", runtimeName, policyPath)
			}
			selected = append(selected, canonical)
		}
		policy.AllowedRuntimes = normalizeModelRuntimeInputs(selected)
	}
	if err := validateModelPolicy(policy); err != nil {
		return modelPolicyV1{}, fmt.Errorf("model policy %s: %w", policyPath, err)
	}
	return policy, nil
}

func resolveModelPolicyPath(repoRoot, profile string) (string, error) {
	profile, err := validateTrustProfile(profile)
	if err != nil {
		return "", err
	}
	var path string
	if profile == trustProfileInternal {
		path = filepath.Join(repoRoot, "policy", "model_policy.toml")
	} else {
		path = filepath.Join(repoRoot, "policy", "profiles", profile, "model_policy.toml")
	}
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("profile %q model policy file is missing: %s", profile, path)
		}
		return "", err
	}
	return path, nil
}

func loadModelPolicy(policyFile, expectedProfile string) (modelPolicyV1, error) {
	expectedProfile, err := validateTrustProfile(expectedProfile)
	if err != nil {
		return modelPolicyV1{}, err
	}
	f, err := os.Open(policyFile)
	if err != nil {
		return modelPolicyV1{}, err
	}
	defer f.Close()

	policy := modelPolicyV1{SchemaVersion: modelPolicySchemaV1, Profile: expectedProfile}
	sc := bufio.NewScanner(f)
	current := ""
	arrBuf := []string{}
	inArray := false
	section := ""
	lineNo := 0
	applyArray := func(key string, items []string) {
		switch key {
		case "allowed_runtimes":
			policy.AllowedRuntimes = normalizeModelRuntimeInputs(items)
		case "runtime_binary_hashes":
			policy.RuntimeBinaryHashes = normalizeStringList(items)
		case "formats.allow":
			if policy.Formats == nil {
				policy.Formats = &modelPolicyFormatRules{}
			}
			policy.Formats.Allow = normalizeModelFormats(items)
		case "formats.warn":
			if policy.Formats == nil {
				policy.Formats = &modelPolicyFormatRules{}
			}
			policy.Formats.Warn = normalizeModelFormats(items)
		case "formats.deny":
			if policy.Formats == nil {
				policy.Formats = &modelPolicyFormatRules{}
			}
			policy.Formats.Deny = normalizeModelFormats(items)
		}
	}
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		if inArray {
			arrBuf = append(arrBuf, line)
			if strings.Contains(line, "]") {
				inArray = false
				items, err := parseArrayItems(strings.Join(arrBuf, " "))
				if err != nil {
					return modelPolicyV1{}, fmt.Errorf("parse %s at line %d: %w", current, lineNo, err)
				}
				applyArray(current, items)
				current = ""
				arrBuf = nil
			}
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
			continue
		}
		if section == "scan" && strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			if policy.Scan == nil {
				policy.Scan = &modelPolicyScanRequirements{}
			}
			switch key {
			case "deny_secret_patterns":
				b, err := parseBoolValue(val)
				if err != nil {
					return modelPolicyV1{}, fmt.Errorf("parse scan.deny_secret_patterns at line %d: %w", lineNo, err)
				}
				policy.Scan.DenySecretPatterns = b
			case "deny_pickle_serialization":
				b, err := parseBoolValue(val)
				if err != nil {
					return modelPolicyV1{}, fmt.Errorf("parse scan.deny_pickle_serialization at line %d: %w", lineNo, err)
				}
				policy.Scan.DenyPickleSerialization = b
			case "require_signed_provenance":
				b, err := parseBoolValue(val)
				if err != nil {
					return modelPolicyV1{}, fmt.Errorf("parse scan.require_signed_provenance at line %d: %w", lineNo, err)
				}
				policy.Scan.RequireSignedProvenance = b
			}
			continue
		}
		if section == "formats" && strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			switch key {
			case "allow", "warn", "deny":
				arrayKey := "formats." + key
				if strings.Contains(val, "[") && strings.Contains(val, "]") {
					items, err := parseArrayItems(val)
					if err != nil {
						return modelPolicyV1{}, fmt.Errorf("parse formats.%s at line %d: %w", key, lineNo, err)
					}
					applyArray(arrayKey, items)
				} else if strings.Contains(val, "[") {
					inArray = true
					current = arrayKey
					arrBuf = []string{val}
				}
			}
			continue
		}
		if section != "" || !strings.Contains(line, "=") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		switch key {
		case "profile":
			policy.Profile = parseStringValue(val)
		case "allowed_runtimes", "runtime_binary_hashes":
			if strings.Contains(val, "[") && strings.Contains(val, "]") {
				items, err := parseArrayItems(val)
				if err != nil {
					return modelPolicyV1{}, fmt.Errorf("parse %s at line %d: %w", key, lineNo, err)
				}
				applyArray(key, items)
			} else if strings.Contains(val, "[") {
				inArray = true
				current = key
				arrBuf = []string{val}
			}
		case "offline_lease_seconds":
			n, err := parseInt64Value(val)
			if err != nil {
				return modelPolicyV1{}, fmt.Errorf("parse offline_lease_seconds at line %d: %w", lineNo, err)
			}
			policy.OfflineLeaseSeconds = int(n)
		case "require_kernel_shield":
			b, err := parseBoolValue(val)
			if err != nil {
				return modelPolicyV1{}, fmt.Errorf("parse require_kernel_shield at line %d: %w", lineNo, err)
			}
			policy.RequireKernelShield = b
		case "require_attestation":
			b, err := parseBoolValue(val)
			if err != nil {
				return modelPolicyV1{}, fmt.Errorf("parse require_attestation at line %d: %w", lineNo, err)
			}
			policy.RequireAttestation = b
		case "egress_policy_id":
			policy.EgressPolicyID = parseStringValue(val)
		}
	}
	if err := sc.Err(); err != nil {
		return modelPolicyV1{}, err
	}
	if normalizeTrustProfile(policy.Profile) != expectedProfile {
		return modelPolicyV1{}, fmt.Errorf("model policy profile %q does not match requested profile %q", policy.Profile, expectedProfile)
	}
	policy.Profile = expectedProfile
	if err := validateModelPolicy(policy); err != nil {
		return modelPolicyV1{}, err
	}
	return policy, nil
}

func validateModelCapsuleManifest(m modelCapsuleManifestV1) error {
	if strings.TrimSpace(m.SchemaVersion) != modelCapsuleManifestSchemaV1 {
		return fmt.Errorf("invalid model capsule manifest schema_version: %q", m.SchemaVersion)
	}
	if !strings.HasPrefix(strings.TrimSpace(m.CapsuleID), "zmc_") {
		return fmt.Errorf("capsule_id must start with zmc_")
	}
	if !strings.HasPrefix(strings.TrimSpace(m.Model.ModelID), "mdl_") {
		return fmt.Errorf("model.model_id must start with mdl_")
	}
	if strings.TrimSpace(m.Model.Name) == "" {
		return fmt.Errorf("model.name is required")
	}
	if strings.TrimSpace(m.Model.Version) == "" {
		return fmt.Errorf("model.version is required")
	}
	if err := validateModelFormat(m.Model.Format); err != nil {
		return err
	}
	if m.Model.DeclaredSizeBytes <= 0 {
		return fmt.Errorf("model.declared_size_bytes must be positive")
	}
	if len(m.Artifacts) == 0 {
		return fmt.Errorf("artifacts must contain at least one item")
	}
	for i, a := range m.Artifacts {
		artifactPath := strings.TrimSpace(a.Path)
		if artifactPath == "" {
			return fmt.Errorf("artifacts[%d].path is required", i)
		}
		cleanPath := filepath.Clean(artifactPath)
		if filepath.IsAbs(artifactPath) || artifactPath != cleanPath || filepath.Base(cleanPath) != cleanPath || cleanPath == "." || cleanPath == ".." || isReservedModelArtifactName(cleanPath) {
			return fmt.Errorf("artifacts[%d].path must be a relative file name", i)
		}
		if strings.TrimSpace(a.Kind) == "" {
			return fmt.Errorf("artifacts[%d].kind is required", i)
		}
		if err := validateSHA256String(a.SHA256); err != nil {
			return fmt.Errorf("artifacts[%d].sha256: %w", i, err)
		}
		if a.SizeBytes <= 0 {
			return fmt.Errorf("artifacts[%d].size_bytes must be positive", i)
		}
	}
	if err := validateModelPolicy(m.Policy); err != nil {
		return err
	}
	if strings.TrimSpace(m.Distribution.TenantID) == "" {
		return fmt.Errorf("distribution.tenant_id is required")
	}
	if strings.TrimSpace(m.Distribution.ClientID) == "" {
		return fmt.Errorf("distribution.client_id is required")
	}
	if _, err := time.Parse(time.RFC3339, strings.TrimSpace(m.Distribution.CreatedAt)); err != nil {
		return fmt.Errorf("distribution.created_at must be RFC3339: %w", err)
	}
	if sha := strings.TrimSpace(m.Provenance.SecurePackSHA256); sha != "" {
		if err := validateSHA256String(sha); err != nil {
			return fmt.Errorf("provenance.secure_pack_sha256: %w", err)
		}
	}
	if err := validateModelPolicyProvenance(m.Policy, m.Provenance); err != nil {
		return err
	}
	return nil
}

func validateModelPolicy(p modelPolicyV1) error {
	if schema := strings.TrimSpace(p.SchemaVersion); schema != "" && schema != modelPolicySchemaV1 {
		return fmt.Errorf("invalid model policy schema_version: %q", p.SchemaVersion)
	}
	if _, err := validateTrustProfile(p.Profile); err != nil {
		return err
	}
	if len(p.AllowedRuntimes) == 0 {
		return fmt.Errorf("policy.allowed_runtimes must contain at least one runtime")
	}
	for i, runtime := range p.AllowedRuntimes {
		if strings.TrimSpace(runtime) == "" {
			return fmt.Errorf("policy.allowed_runtimes[%d] is empty", i)
		}
	}
	if p.OfflineLeaseSeconds <= 0 {
		return fmt.Errorf("policy.offline_lease_seconds must be positive")
	}
	for i, h := range p.RuntimeBinaryHashes {
		h = strings.TrimSpace(strings.TrimPrefix(h, "sha256:"))
		if err := validateSHA256String(h); err != nil {
			return fmt.Errorf("policy.runtime_binary_hashes[%d]: %w", i, err)
		}
	}
	if p.Formats != nil {
		if err := validateModelPolicyFormatList("policy.formats.allow", p.Formats.Allow); err != nil {
			return err
		}
		if err := validateModelPolicyFormatList("policy.formats.warn", p.Formats.Warn); err != nil {
			return err
		}
		if err := validateModelPolicyFormatList("policy.formats.deny", p.Formats.Deny); err != nil {
			return err
		}
	}
	return nil
}

func buildModelManifestProvenance(input buildModelManifestInput, policy modelPolicyV1) (modelManifestProvenance, error) {
	provenance := modelManifestProvenance{}
	if path := strings.TrimSpace(input.SLSAProvenancePath); path != "" {
		sha, err := hashRegularFileForModelProvenance(path, "slsa provenance")
		if err != nil {
			return modelManifestProvenance{}, err
		}
		provenance.SLSAProvenanceSHA256 = sha
	}
	if path := strings.TrimSpace(input.OMSSignaturePath); path != "" {
		sha, err := hashRegularFileForModelProvenance(path, "oms signature")
		if err != nil {
			return modelManifestProvenance{}, err
		}
		provenance.OMSSignatureSHA256 = sha
	}
	if err := validateModelPolicyProvenance(policy, provenance); err != nil {
		return modelManifestProvenance{}, err
	}
	return provenance, nil
}

func hashRegularFileForModelProvenance(path, label string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("%s file is required: %w", label, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s path must be a regular file: %s", label, path)
	}
	if info.Size() == 0 {
		return "", fmt.Errorf("%s file must not be empty: %s", label, path)
	}
	sha, err := fileSHA256Hex(path)
	if err != nil {
		return "", fmt.Errorf("%s sha256 failed: %w", label, err)
	}
	return sha, nil
}

func validateModelPolicyProvenance(policy modelPolicyV1, provenance modelManifestProvenance) error {
	if sha := strings.TrimSpace(provenance.SLSAProvenanceSHA256); sha != "" {
		if err := validateSHA256String(sha); err != nil {
			return fmt.Errorf("provenance.slsa_provenance_sha256: %w", err)
		}
	}
	if sha := strings.TrimSpace(provenance.OMSSignatureSHA256); sha != "" {
		if err := validateSHA256String(sha); err != nil {
			return fmt.Errorf("provenance.oms_signature_sha256: %w", err)
		}
	}
	if policy.Scan != nil && policy.Scan.RequireSignedProvenance {
		if strings.TrimSpace(provenance.SLSAProvenanceSHA256) == "" || strings.TrimSpace(provenance.OMSSignatureSHA256) == "" {
			return fmt.Errorf("policy.scan.require_signed_provenance requires SLSA provenance and OMS signature")
		}
	}
	return nil
}

func normalizeModelRuntimes(raw []string) []string {
	out := normalizeModelRuntimeInputs(raw)
	if len(out) == 0 {
		return defaultModelRuntimes()
	}
	return out
}

func normalizeModelRuntimeInputs(raw []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		for _, part := range strings.Split(v, ",") {
			runtime := strings.TrimSpace(part)
			if runtime == "" {
				continue
			}
			key := strings.ToLower(runtime)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, runtime)
		}
	}
	sort.Strings(out)
	return out
}

func defaultModelRuntimes() []string {
	return append([]string(nil), defaultModelAllowedRuntimes...)
}

func normalizeModelFormat(format string) string {
	return strings.ToLower(strings.TrimPrefix(strings.TrimSpace(format), "."))
}

func normalizeModelFormats(formats []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(formats))
	for _, format := range formats {
		format = normalizeModelFormat(format)
		if format == "" {
			continue
		}
		if _, ok := seen[format]; ok {
			continue
		}
		seen[format] = struct{}{}
		out = append(out, format)
	}
	sort.Strings(out)
	return out
}

func inferModelFormatFromPath(path string) string {
	return normalizeModelFormat(filepath.Ext(path))
}

func validateModelPolicyFormatList(name string, formats []string) error {
	for i, format := range formats {
		if err := validateModelFormat(format); err != nil {
			return fmt.Errorf("%s[%d]: %w", name, i, err)
		}
	}
	return nil
}

func validateModelFormat(format string) error {
	switch normalizeModelFormat(format) {
	case "gguf", "safetensors", "pt", "pth", "bin", "onnx":
		return nil
	default:
		return fmt.Errorf("unsupported model format %q (expected gguf, safetensors, pt, pth, bin or onnx)", format)
	}
}

func modelContentType(format string) string {
	switch normalizeModelFormat(format) {
	case "gguf":
		return "application/x-gguf"
	case "safetensors":
		return "application/x-safetensors"
	case "onnx":
		return "application/onnx"
	case "pt", "pth", "bin":
		return "application/octet-stream"
	default:
		return "application/octet-stream"
	}
}

func fileSHA256Hex(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func prefixedDigestID(prefix string, parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		_, _ = io.WriteString(h, strings.TrimSpace(p))
		_, _ = io.WriteString(h, "\x00")
	}
	return prefix + "_" + hex.EncodeToString(h.Sum(nil))[:24]
}

func validateSHA256String(v string) error {
	v = strings.TrimSpace(strings.ToLower(v))
	if len(v) != 64 {
		return fmt.Errorf("must be 64 hex chars")
	}
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		default:
			return fmt.Errorf("must be hex")
		}
	}
	return nil
}

func isReservedModelArtifactName(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", ".", "..", modelCapsuleManifestName, modelCapsulePolicyName, "scan_result.json", modelCapsuleProvenanceDir, modelCapsuleSignaturesDir:
		return true
	default:
		return false
	}
}

func modelCapsuleOutputName(name, version string) string {
	base := strings.Trim(modelCapsuleIDSafeRE.ReplaceAllString(strings.TrimSpace(name)+"-"+strings.TrimSpace(version), "-"), "-")
	if base == "" {
		base = "model"
	}
	return base + ".zmc"
}

func marshalModelJSON(v any) ([]byte, error) {
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}
