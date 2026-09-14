package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	cpRuntimePermitPrivateKeyEnv = "ZT_CP_RUNTIME_PERMIT_ED25519_PRIV_B64"
	cpRuntimePermitKeyIDEnv      = "ZT_CP_RUNTIME_PERMIT_KEY_ID"
	cpRuntimePermitShieldAudit   = "audit_only"
	cpRuntimePermitShieldKernel  = "kernel_shield"
)

type cpRuntimePermit struct {
	SchemaVersion string                   `json:"schema_version"`
	PermitID      string                   `json:"permit_id"`
	TenantID      string                   `json:"tenant_id"`
	ModelID       string                   `json:"model_id"`
	CapsuleID     string                   `json:"capsule_id"`
	DeviceID      string                   `json:"device_id"`
	Runtime       cpRuntimePermitRuntime   `json:"runtime"`
	Policy        cpRuntimePermitPolicy    `json:"policy"`
	Validity      cpRuntimePermitValidity  `json:"validity"`
	Signature     cpRuntimePermitSignature `json:"signature"`
}

type cpRuntimePermitRuntime struct {
	Name         string `json:"name"`
	BinarySHA256 string `json:"binary_sha256,omitempty"`
	AllowedUID   int    `json:"allowed_uid,omitempty"`
}

type cpRuntimePermitPolicy struct {
	Profile             string `json:"profile"`
	ShieldMinTier       string `json:"shield_min_tier"`
	EgressPolicyID      string `json:"egress_policy_id,omitempty"`
	OfflineLeaseSeconds int    `json:"offline_lease_seconds"`
}

type cpRuntimePermitValidity struct {
	NotBefore string `json:"not_before"`
	ExpiresAt string `json:"expires_at"`
}

type cpRuntimePermitSignature struct {
	Alg    string `json:"alg"`
	KeyID  string `json:"key_id,omitempty"`
	SigB64 string `json:"sig_b64"`
}

func buildCPRuntimePermit(payload map[string]any, tenantID, modelID, capsuleID, deviceID, runtimeName string, now time.Time, ttlSeconds, offlineLeaseSeconds int) cpRuntimePermit {
	profile := firstModelString(payload, "profile", "policy.profile")
	if profile == "" {
		profile = "internal"
	}
	shieldMinTier := firstModelString(payload, "shield_min_tier", "policy.shield_min_tier")
	if requireKernelShield, _ := firstModelBool(payload, "require_kernel_shield", "policy.require_kernel_shield"); requireKernelShield {
		shieldMinTier = cpRuntimePermitShieldKernel
	}
	if shieldMinTier == "" {
		shieldMinTier = cpRuntimePermitShieldAudit
	}
	permitID := "permit_" + sha256Hex([]byte(strings.Join([]string{
		modelID,
		capsuleID,
		deviceID,
		runtimeName,
		now.Format(time.RFC3339Nano),
	}, "\x00")))[:24]
	return cpRuntimePermit{
		SchemaVersion: "zt-runtime-permit-v1",
		PermitID:      permitID,
		TenantID:      tenantID,
		ModelID:       modelID,
		CapsuleID:     capsuleID,
		DeviceID:      deviceID,
		Runtime: cpRuntimePermitRuntime{
			Name:         runtimeName,
			BinarySHA256: firstModelString(payload, "runtime_binary_sha256", "runtime.binary_sha256"),
			AllowedUID:   positiveIntFromPayload(payload, "allowed_uid", 0),
		},
		Policy: cpRuntimePermitPolicy{
			Profile:             profile,
			ShieldMinTier:       shieldMinTier,
			EgressPolicyID:      firstModelString(payload, "egress_policy_id", "policy.egress_policy_id"),
			OfflineLeaseSeconds: offlineLeaseSeconds,
		},
		Validity: cpRuntimePermitValidity{
			NotBefore: now.Format(time.RFC3339),
			ExpiresAt: now.Add(time.Duration(ttlSeconds) * time.Second).Format(time.RFC3339),
		},
		Signature: cpRuntimePermitSignature{
			Alg: "Ed25519",
		},
	}
}

func signCPRuntimePermit(permit *cpRuntimePermit, keyID string, priv ed25519.PrivateKey) error {
	if permit == nil {
		return fmt.Errorf("nil permit")
	}
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid private key length")
	}
	permit.Signature.Alg = "Ed25519"
	permit.Signature.KeyID = keyID
	permit.Signature.SigB64 = ""
	signingBytes, err := cpRuntimePermitSigningBytes(*permit)
	if err != nil {
		return err
	}
	permit.Signature.SigB64 = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, signingBytes))
	return nil
}

func cpRuntimePermitSigningBytes(permit cpRuntimePermit) ([]byte, error) {
	permit.Signature.SigB64 = ""
	return json.Marshal(permit)
}

func loadCPRuntimePermitPrivateKey() (ed25519.PrivateKey, error) {
	raw := strings.TrimSpace(os.Getenv(cpRuntimePermitPrivateKeyEnv))
	if raw == "" {
		return nil, fmt.Errorf("runtime permit signer is not configured")
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	switch len(b) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(b), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(b), nil
	default:
		return nil, fmt.Errorf("invalid runtime permit signer length")
	}
}

func cpRuntimePermitKeyID() string {
	if v := strings.TrimSpace(os.Getenv(cpRuntimePermitKeyIDEnv)); v != "" {
		return v
	}
	return "cp-runtime-permit"
}
