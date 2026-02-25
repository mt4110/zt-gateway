package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const defaultPolicyBundleTTL = 7 * 24 * time.Hour

type policyBundleSigner struct {
	KeyID string
	Priv  ed25519.PrivateKey
	TTL   time.Duration
}

type policyBundle struct {
	ManifestID  string `json:"manifest_id"`
	Profile     string `json:"profile"`
	Version     string `json:"version"`
	SHA256      string `json:"sha256"`
	EffectiveAt string `json:"effective_at"`
	ExpiresAt   string `json:"expires_at"`
	KeyID       string `json:"key_id"`
	Signature   string `json:"signature"`
	ContentTOML string `json:"content_toml"`
}

type policyBundleSigningPayload struct {
	ManifestID  string `json:"manifest_id"`
	Profile     string `json:"profile"`
	Version     string `json:"version"`
	SHA256      string `json:"sha256"`
	EffectiveAt string `json:"effective_at"`
	ExpiresAt   string `json:"expires_at"`
	KeyID       string `json:"key_id"`
	ContentTOML string `json:"content_toml"`
}

func loadPolicyBundleSignerFromEnv() (*policyBundleSigner, error) {
	rawPriv := strings.TrimSpace(os.Getenv("ZT_CP_POLICY_SIGNING_ED25519_PRIV_B64"))
	if rawPriv == "" {
		return nil, nil
	}
	b, err := base64.StdEncoding.DecodeString(rawPriv)
	if err != nil {
		return nil, err
	}
	switch len(b) {
	case ed25519.SeedSize:
		b = ed25519.NewKeyFromSeed(b)
	case ed25519.PrivateKeySize:
	default:
		return nil, fmt.Errorf("expected %d-byte seed or %d-byte private key, got %d", ed25519.SeedSize, ed25519.PrivateKeySize, len(b))
	}
	keyID := strings.TrimSpace(os.Getenv("ZT_CP_POLICY_SIGNING_KEY_ID"))
	if keyID == "" {
		return nil, fmt.Errorf("ZT_CP_POLICY_SIGNING_KEY_ID is required")
	}
	ttl := defaultPolicyBundleTTL
	if rawTTL := strings.TrimSpace(os.Getenv("ZT_CP_POLICY_BUNDLE_TTL_HOURS")); rawTTL != "" {
		hours, err := strconv.Atoi(rawTTL)
		if err != nil || hours <= 0 {
			return nil, fmt.Errorf("ZT_CP_POLICY_BUNDLE_TTL_HOURS must be positive integer hours")
		}
		ttl = time.Duration(hours) * time.Hour
	}
	return &policyBundleSigner{
		KeyID: keyID,
		Priv:  ed25519.PrivateKey(b),
		TTL:   ttl,
	}, nil
}

func (s *policyBundleSigner) Sign(bundle policyBundle) (policyBundle, error) {
	if s == nil {
		return policyBundle{}, fmt.Errorf("policy signer is nil")
	}
	bundle.KeyID = strings.TrimSpace(s.KeyID)
	if bundle.KeyID == "" {
		return policyBundle{}, fmt.Errorf("policy signer key_id is empty")
	}
	signingBytes, err := policyBundleSigningBytes(bundle)
	if err != nil {
		return policyBundle{}, err
	}
	bundle.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(s.Priv, signingBytes))
	return bundle, nil
}

func policyBundleSigningBytes(bundle policyBundle) ([]byte, error) {
	payload := policyBundleSigningPayload{
		ManifestID:  strings.TrimSpace(bundle.ManifestID),
		Profile:     strings.TrimSpace(bundle.Profile),
		Version:     strings.TrimSpace(bundle.Version),
		SHA256:      strings.TrimSpace(bundle.SHA256),
		EffectiveAt: strings.TrimSpace(bundle.EffectiveAt),
		ExpiresAt:   strings.TrimSpace(bundle.ExpiresAt),
		KeyID:       strings.TrimSpace(bundle.KeyID),
		ContentTOML: bundle.ContentTOML,
	}
	return json.Marshal(payload)
}

func normalizePolicyProfile(raw string) (string, error) {
	profile := strings.ToLower(strings.TrimSpace(raw))
	if profile == "" {
		return "internal", nil
	}
	for _, r := range profile {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			continue
		}
		return "", fmt.Errorf("invalid profile")
	}
	return profile, nil
}

func policyPathForProfile(policyDir, fileName, profile string) string {
	if profile == "" || profile == "internal" {
		return filepath.Join(policyDir, fileName)
	}
	return filepath.Join(policyDir, "profiles", profile, fileName)
}

func policyManifestID(fileName, profile, version, contentSHA string) string {
	kind := strings.TrimSpace(strings.TrimSuffix(fileName, ".toml"))
	if kind == "" {
		kind = "policy"
	}
	profile = strings.TrimSpace(profile)
	if profile == "" {
		profile = "internal"
	}
	version = sanitizeManifestToken(version)
	if version == "" {
		version = "unknown"
	}
	shortSHA := strings.TrimSpace(contentSHA)
	if len(shortSHA) > 16 {
		shortSHA = shortSHA[:16]
	}
	if shortSHA == "" {
		shortSHA = "0000000000000000"
	}
	return fmt.Sprintf("pmf_%s_%s_%s_%s", kind, profile, version, shortSHA)
}

func sanitizeManifestToken(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	if v == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			continue
		}
		if r == '-' || r == '_' {
			b.WriteRune(r)
			continue
		}
		b.WriteRune('_')
	}
	return b.String()
}

func policyExpiresAtRFC3339(info os.FileInfo, ttl time.Duration) string {
	effective := time.Now().UTC()
	if info != nil {
		effective = info.ModTime().UTC()
	}
	if ttl <= 0 {
		ttl = defaultPolicyBundleTTL
	}
	return effective.Add(ttl).Format(time.RFC3339)
}
