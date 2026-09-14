package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

const (
	modelCapsuleManifestName       = "manifest.json"
	modelCapsulePolicyName         = "policy.json"
	modelCapsulePayloadName        = "payload.spkg.tgz"
	modelCapsuleAuditSeed          = "audit_seed.json"
	modelCapsuleProvenanceDir      = "provenance"
	modelCapsuleSignaturesDir      = "signatures"
	modelCapsuleSLSAProvenanceName = "slsa.provenance.json"
	modelCapsuleOMSSignatureName   = "oms.sig"
	modelCapsuleMaxJSONBytes       = 4 << 20
)

type modelCapsuleArchiveInfo struct {
	Path             string
	CapsuleSHA256    string
	ManifestSHA256   string
	PolicySHA256     string
	PayloadSHA256    string
	PayloadSizeBytes int64
}

type modelCapsuleReadResult struct {
	Info     modelCapsuleArchiveInfo
	Manifest modelCapsuleManifestV1
	Policy   modelPolicyV1
	Payload  string
}

func writeModelCapsuleArchive(outPath string, manifest modelCapsuleManifestV1, payloadPath string) (modelCapsuleArchiveInfo, error) {
	if err := validateModelCapsuleManifest(manifest); err != nil {
		return modelCapsuleArchiveInfo{}, err
	}
	payloadInfo, err := os.Stat(payloadPath)
	if err != nil {
		return modelCapsuleArchiveInfo{}, err
	}
	if !payloadInfo.Mode().IsRegular() {
		return modelCapsuleArchiveInfo{}, fmt.Errorf("payload must be a regular file: %s", payloadPath)
	}
	payloadSHA, err := fileSHA256Hex(payloadPath)
	if err != nil {
		return modelCapsuleArchiveInfo{}, err
	}
	if strings.TrimSpace(manifest.Provenance.SecurePackSHA256) != "" && manifest.Provenance.SecurePackSHA256 != payloadSHA {
		return modelCapsuleArchiveInfo{}, fmt.Errorf("manifest secure_pack_sha256 does not match payload")
	}
	manifest.Provenance.SecurePackSHA256 = payloadSHA

	manifestJSON, err := marshalModelJSON(manifest)
	if err != nil {
		return modelCapsuleArchiveInfo{}, err
	}
	policyJSON, err := marshalModelJSON(manifest.Policy)
	if err != nil {
		return modelCapsuleArchiveInfo{}, err
	}
	auditSeedJSON, err := marshalModelJSON(map[string]any{
		"schema_version": "zt-model-audit-seed-v1",
		"capsule_id":     manifest.CapsuleID,
		"model_id":       manifest.Model.ModelID,
		"created_at":     time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return modelCapsuleArchiveInfo{}, err
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		return modelCapsuleArchiveInfo{}, err
	}
	f, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return modelCapsuleArchiveInfo{}, err
	}
	writeOK := false
	defer func() {
		_ = f.Close()
		if !writeOK {
			_ = os.Remove(outPath)
		}
	}()

	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)
	if err := writeTarBytes(tw, modelCapsuleManifestName, manifestJSON, 0644); err != nil {
		_ = tw.Close()
		_ = gw.Close()
		return modelCapsuleArchiveInfo{}, err
	}
	if err := writeTarBytes(tw, modelCapsulePolicyName, policyJSON, 0644); err != nil {
		_ = tw.Close()
		_ = gw.Close()
		return modelCapsuleArchiveInfo{}, err
	}
	if err := writeTarFile(tw, modelCapsulePayloadName, payloadPath, 0400); err != nil {
		_ = tw.Close()
		_ = gw.Close()
		return modelCapsuleArchiveInfo{}, err
	}
	if err := writeTarBytes(tw, modelCapsuleAuditSeed, auditSeedJSON, 0644); err != nil {
		_ = tw.Close()
		_ = gw.Close()
		return modelCapsuleArchiveInfo{}, err
	}
	if err := tw.Close(); err != nil {
		_ = gw.Close()
		return modelCapsuleArchiveInfo{}, err
	}
	if err := gw.Close(); err != nil {
		return modelCapsuleArchiveInfo{}, err
	}
	if err := f.Close(); err != nil {
		return modelCapsuleArchiveInfo{}, err
	}
	writeOK = true

	capsuleSHA, err := fileSHA256Hex(outPath)
	if err != nil {
		return modelCapsuleArchiveInfo{}, err
	}
	return modelCapsuleArchiveInfo{
		Path:             outPath,
		CapsuleSHA256:    capsuleSHA,
		ManifestSHA256:   sha256HexBytes(manifestJSON),
		PolicySHA256:     sha256HexBytes(policyJSON),
		PayloadSHA256:    payloadSHA,
		PayloadSizeBytes: payloadInfo.Size(),
	}, nil
}

func readModelCapsuleArchive(capsulePath, tempDir string) (modelCapsuleReadResult, error) {
	if strings.TrimSpace(tempDir) == "" {
		return modelCapsuleReadResult{}, fmt.Errorf("temp dir is required")
	}
	capsuleSHA, err := fileSHA256Hex(capsulePath)
	if err != nil {
		return modelCapsuleReadResult{}, err
	}
	f, err := os.Open(capsulePath)
	if err != nil {
		return modelCapsuleReadResult{}, err
	}
	defer f.Close()
	gr, err := gzip.NewReader(f)
	if err != nil {
		return modelCapsuleReadResult{}, fmt.Errorf("open zmc gzip: %w", err)
	}
	defer gr.Close()
	tr := tar.NewReader(gr)

	var manifestJSON, policyJSON []byte
	payloadPath := filepath.Join(tempDir, modelCapsulePayloadName)
	var payloadFound bool
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return modelCapsuleReadResult{}, fmt.Errorf("read zmc tar: %w", err)
		}
		name := cleanCapsuleEntryName(hdr.Name)
		if name == "" {
			return modelCapsuleReadResult{}, fmt.Errorf("unsafe capsule entry path: %q", hdr.Name)
		}
		if hdr.FileInfo().IsDir() {
			continue
		}
		switch name {
		case modelCapsuleManifestName:
			if manifestJSON != nil {
				return modelCapsuleReadResult{}, fmt.Errorf("duplicate manifest.json")
			}
			manifestJSON, err = readLimitedEntry(tr, modelCapsuleMaxJSONBytes)
			if err != nil {
				return modelCapsuleReadResult{}, fmt.Errorf("read manifest.json: %w", err)
			}
		case modelCapsulePolicyName:
			if policyJSON != nil {
				return modelCapsuleReadResult{}, fmt.Errorf("duplicate policy.json")
			}
			policyJSON, err = readLimitedEntry(tr, modelCapsuleMaxJSONBytes)
			if err != nil {
				return modelCapsuleReadResult{}, fmt.Errorf("read policy.json: %w", err)
			}
		case modelCapsulePayloadName:
			if payloadFound {
				return modelCapsuleReadResult{}, fmt.Errorf("duplicate payload.spkg.tgz")
			}
			if err := writeEntryToFile(tr, payloadPath, 0400); err != nil {
				return modelCapsuleReadResult{}, fmt.Errorf("extract payload.spkg.tgz: %w", err)
			}
			payloadFound = true
		default:
			if _, err := io.Copy(io.Discard, tr); err != nil {
				return modelCapsuleReadResult{}, fmt.Errorf("drain capsule entry %q: %w", hdr.Name, err)
			}
		}
	}
	if len(manifestJSON) == 0 {
		return modelCapsuleReadResult{}, fmt.Errorf("manifest.json missing from capsule")
	}
	if len(policyJSON) == 0 {
		return modelCapsuleReadResult{}, fmt.Errorf("policy.json missing from capsule")
	}
	if !payloadFound {
		return modelCapsuleReadResult{}, fmt.Errorf("payload.spkg.tgz missing from capsule")
	}

	var manifest modelCapsuleManifestV1
	if err := json.Unmarshal(manifestJSON, &manifest); err != nil {
		return modelCapsuleReadResult{}, fmt.Errorf("manifest.json invalid: %w", err)
	}
	if err := validateModelCapsuleManifest(manifest); err != nil {
		return modelCapsuleReadResult{}, err
	}
	var policy modelPolicyV1
	if err := json.Unmarshal(policyJSON, &policy); err != nil {
		return modelCapsuleReadResult{}, fmt.Errorf("policy.json invalid: %w", err)
	}
	if err := validateModelPolicy(policy); err != nil {
		return modelCapsuleReadResult{}, err
	}
	if !reflect.DeepEqual(policy, manifest.Policy) {
		return modelCapsuleReadResult{}, fmt.Errorf("policy.json does not match manifest policy")
	}

	payloadSHA, err := fileSHA256Hex(payloadPath)
	if err != nil {
		return modelCapsuleReadResult{}, err
	}
	if manifest.Provenance.SecurePackSHA256 != "" && manifest.Provenance.SecurePackSHA256 != payloadSHA {
		return modelCapsuleReadResult{}, fmt.Errorf("payload sha256 mismatch: manifest=%s actual=%s", manifest.Provenance.SecurePackSHA256, payloadSHA)
	}
	payloadInfo, err := os.Stat(payloadPath)
	if err != nil {
		return modelCapsuleReadResult{}, err
	}
	return modelCapsuleReadResult{
		Info: modelCapsuleArchiveInfo{
			Path:             capsulePath,
			CapsuleSHA256:    capsuleSHA,
			ManifestSHA256:   sha256HexBytes(manifestJSON),
			PolicySHA256:     sha256HexBytes(policyJSON),
			PayloadSHA256:    payloadSHA,
			PayloadSizeBytes: payloadInfo.Size(),
		},
		Manifest: manifest,
		Policy:   policy,
		Payload:  payloadPath,
	}, nil
}

func validateModelCapsuleSignedMetadata(readResult modelCapsuleReadResult, extractedRoot string) error {
	manifestPath, err := signedModelCapsuleMetadataPath(extractedRoot, modelCapsuleManifestName)
	if err != nil {
		return err
	}
	policyPath, err := signedModelCapsuleMetadataPath(extractedRoot, modelCapsulePolicyName)
	if err != nil {
		return err
	}

	var signedManifest modelCapsuleManifestV1
	if err := readModelJSONFile(manifestPath, &signedManifest); err != nil {
		return fmt.Errorf("signed manifest invalid: %w", err)
	}
	if err := validateModelCapsuleManifestForSignedPayload(signedManifest); err != nil {
		return err
	}
	var signedPolicy modelPolicyV1
	if err := readModelJSONFile(policyPath, &signedPolicy); err != nil {
		return fmt.Errorf("signed policy invalid: %w", err)
	}
	if err := validateModelPolicy(signedPolicy); err != nil {
		return err
	}
	if !reflect.DeepEqual(signedPolicy, signedManifest.Policy) {
		return fmt.Errorf("signed policy.json does not match signed manifest policy")
	}
	if !modelManifestEqualIgnoringPayloadSHA(readResult.Manifest, signedManifest) {
		return fmt.Errorf("signed manifest does not match capsule manifest")
	}
	if !reflect.DeepEqual(readResult.Manifest.Policy, signedPolicy) {
		return fmt.Errorf("signed policy does not match capsule policy")
	}
	if err := validateModelCapsuleSignedArtifacts(signedManifest, extractedRoot); err != nil {
		return err
	}
	if err := validateModelCapsuleSignedProvenance(signedManifest, extractedRoot); err != nil {
		return err
	}
	return nil
}

func validateModelCapsuleSignedArtifacts(manifest modelCapsuleManifestV1, extractedRoot string) error {
	for i, artifact := range manifest.Artifacts {
		artifactPath := strings.TrimSpace(artifact.Path)
		path, err := signedModelCapsuleMetadataPath(extractedRoot, artifactPath)
		if err != nil {
			return fmt.Errorf("signed artifact[%d] %q is missing: %w", i, artifactPath, err)
		}
		actualSHA, err := fileSHA256Hex(path)
		if err != nil {
			return fmt.Errorf("signed artifact[%d] %q sha256 failed: %w", i, artifactPath, err)
		}
		expectedSHA := strings.ToLower(strings.TrimSpace(artifact.SHA256))
		if actualSHA != expectedSHA {
			return fmt.Errorf("signed artifact[%d] %q sha256 mismatch: manifest=%s actual=%s", i, artifactPath, expectedSHA, actualSHA)
		}
	}
	return nil
}

func validateModelCapsuleSignedProvenance(manifest modelCapsuleManifestV1, extractedRoot string) error {
	if manifest.Policy.Scan == nil || !manifest.Policy.Scan.RequireSignedProvenance {
		return nil
	}
	if err := validateModelCapsuleSignedProvenanceFile(
		extractedRoot,
		filepath.Join(modelCapsuleProvenanceDir, modelCapsuleSLSAProvenanceName),
		strings.TrimSpace(manifest.Provenance.SLSAProvenanceSHA256),
		"slsa provenance",
	); err != nil {
		return err
	}
	return validateModelCapsuleSignedProvenanceFile(
		extractedRoot,
		filepath.Join(modelCapsuleSignaturesDir, modelCapsuleOMSSignatureName),
		strings.TrimSpace(manifest.Provenance.OMSSignatureSHA256),
		"oms signature",
	)
}

func validateModelCapsuleSignedProvenanceFile(extractedRoot, signedPath, expectedSHA, label string) error {
	if expectedSHA == "" {
		return fmt.Errorf("signed %s sha256 missing from manifest", label)
	}
	path, err := signedModelCapsuleMetadataPath(extractedRoot, signedPath)
	if err != nil {
		return fmt.Errorf("signed %s is missing: %w", label, err)
	}
	actualSHA, err := fileSHA256Hex(path)
	if err != nil {
		return fmt.Errorf("signed %s sha256 failed: %w", label, err)
	}
	if actualSHA != expectedSHA {
		return fmt.Errorf("signed %s sha256 mismatch: manifest=%s actual=%s", label, expectedSHA, actualSHA)
	}
	return nil
}

func validateModelCapsuleManifestForSignedPayload(manifest modelCapsuleManifestV1) error {
	signed := manifest
	if strings.TrimSpace(signed.Provenance.SecurePackSHA256) == "" {
		signed.Provenance.SecurePackSHA256 = strings.Repeat("0", 64)
	}
	return validateModelCapsuleManifest(signed)
}

func modelManifestEqualIgnoringPayloadSHA(a, b modelCapsuleManifestV1) bool {
	a.Provenance.SecurePackSHA256 = ""
	b.Provenance.SecurePackSHA256 = ""
	return reflect.DeepEqual(a, b)
}

func signedModelCapsuleMetadataPath(root, name string) (string, error) {
	for _, candidate := range []string{
		filepath.Join(root, "docs", name),
		filepath.Join(root, name),
	} {
		info, err := os.Lstat(candidate)
		if err == nil {
			if !info.Mode().IsRegular() {
				return "", fmt.Errorf("signed %s is not a regular file", name)
			}
			return candidate, nil
		}
		if !os.IsNotExist(err) {
			return "", err
		}
	}
	return "", fmt.Errorf("signed %s missing from payload", name)
}

func readModelJSONFile(path string, dst any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := readLimitedEntry(f, modelCapsuleMaxJSONBytes)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, dst)
}

func writeTarBytes(tw *tar.Writer, name string, b []byte, mode int64) error {
	if err := tw.WriteHeader(&tar.Header{
		Name:     name,
		Mode:     mode,
		Size:     int64(len(b)),
		Typeflag: tar.TypeReg,
	}); err != nil {
		return err
	}
	_, err := tw.Write(b)
	return err
}

func writeTarFile(tw *tar.Writer, name, src string, mode int64) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("not a regular file: %s", src)
	}
	if err := tw.WriteHeader(&tar.Header{
		Name:     name,
		Mode:     mode,
		Size:     info.Size(),
		Typeflag: tar.TypeReg,
	}); err != nil {
		return err
	}
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(tw, f)
	return err
}

func readLimitedEntry(r io.Reader, limit int64) ([]byte, error) {
	var lr io.LimitedReader
	lr.R = r
	lr.N = limit + 1
	b, err := io.ReadAll(&lr)
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("entry exceeds %d bytes", limit)
	}
	return b, nil
}

func writeEntryToFile(r io.Reader, path string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	out, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, r); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

func cleanCapsuleEntryName(raw string) string {
	name := filepath.Clean(strings.TrimSpace(raw))
	if name == "." || name == "" || filepath.IsAbs(name) {
		return ""
	}
	if strings.HasPrefix(name, "..") || strings.Contains(name, string(filepath.Separator)+".."+string(filepath.Separator)) {
		return ""
	}
	return filepath.ToSlash(name)
}

func sha256HexReader(r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
