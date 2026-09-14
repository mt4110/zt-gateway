package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	runtimePermitSchemaV1             = "zt-runtime-permit-v1"
	runtimePermitShieldTierAuditOnly  = "audit_only"
	runtimePermitShieldTierKernelMode = "kernel_shield"
)

type runtimePermitV1 struct {
	SchemaVersion string                 `json:"schema_version"`
	PermitID      string                 `json:"permit_id"`
	TenantID      string                 `json:"tenant_id"`
	ModelID       string                 `json:"model_id"`
	CapsuleID     string                 `json:"capsule_id"`
	DeviceID      string                 `json:"device_id"`
	Runtime       runtimePermitRuntime   `json:"runtime"`
	Policy        runtimePermitPolicy    `json:"policy"`
	Validity      runtimePermitValidity  `json:"validity"`
	Signature     runtimePermitSignature `json:"signature"`
}

type runtimePermitRuntime struct {
	Name         string `json:"name"`
	BinarySHA256 string `json:"binary_sha256,omitempty"`
	AllowedUID   int    `json:"allowed_uid,omitempty"`
}

type runtimePermitPolicy struct {
	Profile             string `json:"profile"`
	ShieldMinTier       string `json:"shield_min_tier"`
	EgressPolicyID      string `json:"egress_policy_id,omitempty"`
	OfflineLeaseSeconds int    `json:"offline_lease_seconds"`
}

type runtimePermitValidity struct {
	NotBefore string `json:"not_before"`
	ExpiresAt string `json:"expires_at"`
}

type runtimePermitSignature struct {
	Alg    string `json:"alg"`
	KeyID  string `json:"key_id,omitempty"`
	SigB64 string `json:"sig_b64"`
}

func newRuntimePermitForManifest(manifest modelCapsuleManifestV1, deviceID, runtimeName, runtimeBinarySHA256 string, now time.Time, ttl time.Duration) (runtimePermitV1, error) {
	if err := validateModelCapsuleManifest(manifest); err != nil {
		return runtimePermitV1{}, err
	}
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return runtimePermitV1{}, fmt.Errorf("device_id is required")
	}
	runtimeName = strings.TrimSpace(runtimeName)
	if runtimeName == "" {
		return runtimePermitV1{}, fmt.Errorf("runtime name is required")
	}
	canonicalRuntimeName, ok := modelPolicyCanonicalRuntime(manifest.Policy, runtimeName)
	if !ok {
		return runtimePermitV1{}, fmt.Errorf("runtime %q is not allowed by model policy", runtimeName)
	}
	runtimeName = canonicalRuntimeName
	runtimeBinarySHA256 = normalizeRuntimeSHA256(runtimeBinarySHA256)
	if runtimeBinarySHA256 != "" {
		if err := validateSHA256String(runtimeBinarySHA256); err != nil {
			return runtimePermitV1{}, fmt.Errorf("runtime binary_sha256: %w", err)
		}
	}
	if len(manifest.Policy.RuntimeBinaryHashes) > 0 {
		if runtimeBinarySHA256 == "" {
			return runtimePermitV1{}, fmt.Errorf("runtime binary_sha256 is required by model policy")
		}
		if !modelPolicyAllowsRuntimeSHA(manifest.Policy, runtimeBinarySHA256) {
			return runtimePermitV1{}, fmt.Errorf("runtime binary_sha256 is not allowed by model policy")
		}
	}
	if err := validateRuntimeAttestationPolicyForManifest(manifest); err != nil {
		return runtimePermitV1{}, err
	}
	if ttl <= 0 {
		return runtimePermitV1{}, fmt.Errorf("permit ttl must be positive")
	}
	if manifest.Policy.OfflineLeaseSeconds > 0 {
		maxTTL := time.Duration(manifest.Policy.OfflineLeaseSeconds) * time.Second
		if ttl > maxTTL {
			ttl = maxTTL
		}
	}
	now = now.UTC()
	return runtimePermitV1{
		SchemaVersion: runtimePermitSchemaV1,
		PermitID:      prefixedDigestID("permit", manifest.CapsuleID, deviceID, runtimeName, now.Format(time.RFC3339Nano)),
		TenantID:      manifest.Distribution.TenantID,
		ModelID:       manifest.Model.ModelID,
		CapsuleID:     manifest.CapsuleID,
		DeviceID:      deviceID,
		Runtime: runtimePermitRuntime{
			Name:         runtimeName,
			BinarySHA256: runtimeBinarySHA256,
		},
		Policy: runtimePermitPolicy{
			Profile:             manifest.Policy.Profile,
			ShieldMinTier:       modelPolicyRuntimePermitShieldTier(manifest.Policy),
			EgressPolicyID:      manifest.Policy.EgressPolicyID,
			OfflineLeaseSeconds: manifest.Policy.OfflineLeaseSeconds,
		},
		Validity: runtimePermitValidity{
			NotBefore: now.Format(time.RFC3339),
			ExpiresAt: now.Add(ttl).UTC().Format(time.RFC3339),
		},
		Signature: runtimePermitSignature{
			Alg: "Ed25519",
		},
	}, nil
}

func signRuntimePermit(permit runtimePermitV1, keyID string, priv ed25519.PrivateKey) (runtimePermitV1, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return runtimePermitV1{}, fmt.Errorf("invalid Ed25519 private key length")
	}
	permit.Signature.Alg = "Ed25519"
	permit.Signature.KeyID = strings.TrimSpace(keyID)
	permit.Signature.SigB64 = ""
	signingBytes, err := runtimePermitSigningBytes(permit)
	if err != nil {
		return runtimePermitV1{}, err
	}
	permit.Signature.SigB64 = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, signingBytes))
	return permit, nil
}

func validateRuntimePermitForManifest(permit runtimePermitV1, manifest modelCapsuleManifestV1, expectedDeviceID, expectedRuntimeName string, now time.Time, pub ed25519.PublicKey) error {
	if err := validateRuntimePermitShape(permit); err != nil {
		return err
	}
	if err := validateModelCapsuleManifest(manifest); err != nil {
		return err
	}
	if strings.TrimSpace(permit.TenantID) != strings.TrimSpace(manifest.Distribution.TenantID) {
		return fmt.Errorf("runtime permit tenant mismatch")
	}
	if strings.TrimSpace(permit.ModelID) != strings.TrimSpace(manifest.Model.ModelID) {
		return fmt.Errorf("runtime permit model mismatch")
	}
	if strings.TrimSpace(permit.CapsuleID) != strings.TrimSpace(manifest.CapsuleID) {
		return fmt.Errorf("runtime permit capsule mismatch")
	}
	if strings.TrimSpace(expectedDeviceID) == "" {
		return fmt.Errorf("expected device_id is required")
	}
	if strings.TrimSpace(permit.DeviceID) != strings.TrimSpace(expectedDeviceID) {
		return fmt.Errorf("runtime permit device mismatch")
	}
	if strings.TrimSpace(expectedRuntimeName) == "" {
		return fmt.Errorf("expected runtime name is required")
	}
	permitRuntimeName := canonicalRuntimeNameForPermitValidation(manifest.Policy, permit.Runtime.Name)
	expectedRuntimeName = canonicalRuntimeNameForPermitValidation(manifest.Policy, expectedRuntimeName)
	if permitRuntimeName != expectedRuntimeName {
		return fmt.Errorf("runtime permit runtime mismatch")
	}
	if err := validateRuntimePermitPolicyForManifest(permit, manifest); err != nil {
		return err
	}
	notBefore, expiresAt, err := parseRuntimePermitValidity(permit)
	if err != nil {
		return err
	}
	if err := validateRuntimePermitLeasePolicyForManifest(permit, manifest, notBefore, expiresAt); err != nil {
		return err
	}
	now = now.UTC()
	if now.Before(notBefore) {
		return fmt.Errorf("runtime permit is not yet valid")
	}
	if !now.Before(expiresAt) {
		return fmt.Errorf("runtime permit expired")
	}
	if err := verifyRuntimePermitSignature(permit, pub); err != nil {
		return err
	}
	return nil
}

func canonicalRuntimeNameForPermitValidation(policy modelPolicyV1, runtimeName string) string {
	if canonical, ok := modelPolicyCanonicalRuntime(policy, runtimeName); ok {
		return canonical
	}
	return strings.ToLower(strings.TrimSpace(runtimeName))
}

func validateRuntimePermitPolicyForManifest(permit runtimePermitV1, manifest modelCapsuleManifestV1) error {
	runtimeName := strings.TrimSpace(permit.Runtime.Name)
	if !modelPolicyAllowsRuntime(manifest.Policy, runtimeName) {
		return fmt.Errorf("runtime permit runtime %q is not allowed by model policy", runtimeName)
	}
	if manifest.Policy.RequireKernelShield && strings.TrimSpace(permit.Policy.ShieldMinTier) != runtimePermitShieldTierKernelMode {
		return fmt.Errorf("runtime permit shield_min_tier does not satisfy kernel shield policy")
	}
	if err := validateRuntimeAttestationPolicyForManifest(manifest); err != nil {
		return err
	}
	if len(manifest.Policy.RuntimeBinaryHashes) == 0 {
		return nil
	}
	runtimeSHA := normalizeRuntimeSHA256(permit.Runtime.BinarySHA256)
	if runtimeSHA == "" {
		return fmt.Errorf("runtime permit binary_sha256 is required by model policy")
	}
	if !modelPolicyAllowsRuntimeSHA(manifest.Policy, runtimeSHA) {
		return fmt.Errorf("runtime permit binary_sha256 is not allowed by model policy")
	}
	return nil
}

func validateRuntimeAttestationPolicyForManifest(manifest modelCapsuleManifestV1) error {
	if manifest.Policy.RequireAttestation {
		return fmt.Errorf("runtime permit cannot satisfy model attestation policy: attestation is unavailable")
	}
	return nil
}

func modelPolicyRuntimePermitShieldTier(policy modelPolicyV1) string {
	if policy.RequireKernelShield {
		return runtimePermitShieldTierKernelMode
	}
	return runtimePermitShieldTierAuditOnly
}

func validateRuntimePermitLeasePolicyForManifest(permit runtimePermitV1, manifest modelCapsuleManifestV1, notBefore, expiresAt time.Time) error {
	maxLease := time.Duration(manifest.Policy.OfflineLeaseSeconds) * time.Second
	if maxLease <= 0 {
		return fmt.Errorf("policy.offline_lease_seconds must be positive")
	}
	if permit.Policy.OfflineLeaseSeconds > manifest.Policy.OfflineLeaseSeconds {
		return fmt.Errorf("runtime permit offline lease exceeds capsule policy")
	}
	if expiresAt.Sub(notBefore) > maxLease {
		return fmt.Errorf("runtime permit validity exceeds capsule offline lease policy")
	}
	return nil
}

func modelPolicyAllowsRuntime(policy modelPolicyV1, runtimeName string) bool {
	_, ok := modelPolicyCanonicalRuntime(policy, runtimeName)
	return ok
}

func modelPolicyCanonicalRuntime(policy modelPolicyV1, runtimeName string) (string, bool) {
	runtimeName = strings.TrimSpace(runtimeName)
	if runtimeName == "" {
		return "", false
	}
	for _, allowed := range policy.AllowedRuntimes {
		canonical := strings.TrimSpace(allowed)
		if canonical != "" && strings.EqualFold(canonical, runtimeName) {
			return canonical, true
		}
	}
	return "", false
}

func modelPolicyAllowsRuntimeSHA(policy modelPolicyV1, runtimeSHA string) bool {
	runtimeSHA = normalizeRuntimeSHA256(runtimeSHA)
	if runtimeSHA == "" {
		return false
	}
	for _, allowed := range policy.RuntimeBinaryHashes {
		if normalizeRuntimeSHA256(allowed) == runtimeSHA {
			return true
		}
	}
	return false
}

func normalizeRuntimeSHA256(v string) string {
	return strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(v), "sha256:")))
}

func validateRuntimePermitShape(permit runtimePermitV1) error {
	if strings.TrimSpace(permit.SchemaVersion) != runtimePermitSchemaV1 {
		return fmt.Errorf("invalid runtime permit schema_version: %q", permit.SchemaVersion)
	}
	if !strings.HasPrefix(strings.TrimSpace(permit.PermitID), "permit_") {
		return fmt.Errorf("permit_id must start with permit_")
	}
	if strings.TrimSpace(permit.TenantID) == "" {
		return fmt.Errorf("tenant_id is required")
	}
	if !strings.HasPrefix(strings.TrimSpace(permit.ModelID), "mdl_") {
		return fmt.Errorf("model_id must start with mdl_")
	}
	if !strings.HasPrefix(strings.TrimSpace(permit.CapsuleID), "zmc_") {
		return fmt.Errorf("capsule_id must start with zmc_")
	}
	if strings.TrimSpace(permit.DeviceID) == "" {
		return fmt.Errorf("device_id is required")
	}
	if strings.TrimSpace(permit.Runtime.Name) == "" {
		return fmt.Errorf("runtime.name is required")
	}
	if sha := strings.TrimSpace(strings.TrimPrefix(permit.Runtime.BinarySHA256, "sha256:")); sha != "" {
		if err := validateSHA256String(sha); err != nil {
			return fmt.Errorf("runtime.binary_sha256: %w", err)
		}
	}
	if _, err := validateTrustProfile(permit.Policy.Profile); err != nil {
		return err
	}
	if strings.TrimSpace(permit.Policy.ShieldMinTier) == "" {
		return fmt.Errorf("policy.shield_min_tier is required")
	}
	if permit.Policy.OfflineLeaseSeconds <= 0 {
		return fmt.Errorf("policy.offline_lease_seconds must be positive")
	}
	if _, _, err := parseRuntimePermitValidity(permit); err != nil {
		return err
	}
	if permit.Signature.Alg != "Ed25519" {
		return fmt.Errorf("runtime permit signature alg must be Ed25519")
	}
	if strings.TrimSpace(permit.Signature.SigB64) == "" {
		return fmt.Errorf("runtime permit signature is required")
	}
	return nil
}

func parseRuntimePermitValidity(permit runtimePermitV1) (time.Time, time.Time, error) {
	notBefore, err := time.Parse(time.RFC3339, strings.TrimSpace(permit.Validity.NotBefore))
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("validity.not_before must be RFC3339: %w", err)
	}
	expiresAt, err := time.Parse(time.RFC3339, strings.TrimSpace(permit.Validity.ExpiresAt))
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("validity.expires_at must be RFC3339: %w", err)
	}
	if !expiresAt.After(notBefore) {
		return time.Time{}, time.Time{}, fmt.Errorf("validity.expires_at must be after not_before")
	}
	return notBefore.UTC(), expiresAt.UTC(), nil
}

func verifyRuntimePermitSignature(permit runtimePermitV1, pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid Ed25519 public key length")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(permit.Signature.SigB64))
	if err != nil {
		return fmt.Errorf("runtime permit signature is invalid base64: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("invalid runtime permit signature length")
	}
	unsigned := permit
	unsigned.Signature.SigB64 = ""
	signingBytes, err := runtimePermitSigningBytes(unsigned)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, signingBytes, sig) {
		return fmt.Errorf("runtime permit signature mismatch")
	}
	return nil
}

func runtimePermitSigningBytes(permit runtimePermitV1) ([]byte, error) {
	permit.Signature.SigB64 = ""
	return json.Marshal(permit)
}
