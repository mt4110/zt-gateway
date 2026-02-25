package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	defaultPolicyBundleTTL           = 7 * 24 * time.Hour
	defaultPolicySigningKeyFileRel   = "keys/policy_signing_ed25519.seed.b64"
	defaultPolicyKeyIDPrefix         = "cp-policy-ed25519"
	defaultPolicyKeyIDFingerprintLen = 16
)

type policyBundleSigner struct {
	KeyID string
	Priv  ed25519.PrivateKey
	TTL   time.Duration
}

type policyBundle struct {
	ManifestID        string `json:"manifest_id"`
	Profile           string `json:"profile"`
	Version           string `json:"version"`
	SHA256            string `json:"sha256"`
	EffectiveAt       string `json:"effective_at"`
	ExpiresAt         string `json:"expires_at"`
	KeyID             string `json:"key_id"`
	Signature         string `json:"signature"`
	ContentTOML       string `json:"content_toml"`
	MinGatewayVersion string `json:"min_gateway_version"`
	DuplicateRule     string `json:"duplicate_rule"`
}

type policyBundleSigningPayload struct {
	ManifestID        string `json:"manifest_id"`
	Profile           string `json:"profile"`
	Version           string `json:"version"`
	SHA256            string `json:"sha256"`
	EffectiveAt       string `json:"effective_at"`
	ExpiresAt         string `json:"expires_at"`
	KeyID             string `json:"key_id"`
	ContentTOML       string `json:"content_toml"`
	MinGatewayVersion string `json:"min_gateway_version"`
	DuplicateRule     string `json:"duplicate_rule"`
}

func loadPolicyBundleSigner(dataDir string) (*policyBundleSigner, error) {
	ttl, err := loadPolicyBundleTTL()
	if err != nil {
		return nil, err
	}

	priv, err := loadPolicyBundlePrivateKeyWithFallback(dataDir)
	if err != nil {
		return nil, err
	}
	keyID := resolvePolicySigningKeyID(priv.Public().(ed25519.PublicKey))
	return &policyBundleSigner{
		KeyID: keyID,
		Priv:  priv,
		TTL:   ttl,
	}, nil
}

func loadPolicyBundleTTL() (time.Duration, error) {
	ttl := defaultPolicyBundleTTL
	if rawTTL := strings.TrimSpace(os.Getenv("ZT_CP_POLICY_BUNDLE_TTL_HOURS")); rawTTL != "" {
		hours, err := strconv.Atoi(rawTTL)
		if err != nil || hours <= 0 {
			return 0, fmt.Errorf("ZT_CP_POLICY_BUNDLE_TTL_HOURS must be positive integer hours")
		}
		ttl = time.Duration(hours) * time.Hour
	}
	return ttl, nil
}

func loadPolicyBundlePrivateKeyWithFallback(dataDir string) (ed25519.PrivateKey, error) {
	if rawPriv := strings.TrimSpace(os.Getenv("ZT_CP_POLICY_SIGNING_ED25519_PRIV_B64")); rawPriv != "" {
		return decodePolicyPrivateKeyB64(rawPriv)
	}
	keyPath, err := resolvePolicySigningKeyFilePath(dataDir)
	if err != nil {
		return nil, err
	}
	return loadOrCreatePolicyPrivateKeyFile(keyPath)
}

func resolvePolicySigningKeyFilePath(dataDir string) (string, error) {
	keyPath := strings.TrimSpace(os.Getenv("ZT_CP_POLICY_SIGNING_KEY_FILE"))
	if keyPath == "" {
		if strings.TrimSpace(dataDir) == "" {
			return "", fmt.Errorf("dataDir is empty")
		}
		return filepath.Join(dataDir, defaultPolicySigningKeyFileRel), nil
	}
	if filepath.IsAbs(keyPath) {
		return keyPath, nil
	}
	if strings.TrimSpace(dataDir) == "" {
		return "", fmt.Errorf("relative ZT_CP_POLICY_SIGNING_KEY_FILE requires dataDir")
	}
	return filepath.Join(dataDir, keyPath), nil
}

func loadOrCreatePolicyPrivateKeyFile(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		return decodePolicyPrivateKeyB64(strings.TrimSpace(string(b)))
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	encodedSeed := base64.StdEncoding.EncodeToString(seed) + "\n"
	if err := os.WriteFile(path, []byte(encodedSeed), 0o600); err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func decodePolicyPrivateKeyB64(raw string) (ed25519.PrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}
	switch len(b) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(b), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(b), nil
	default:
		return nil, fmt.Errorf("expected %d-byte seed or %d-byte private key, got %d", ed25519.SeedSize, ed25519.PrivateKeySize, len(b))
	}
}

func resolvePolicySigningKeyID(pub ed25519.PublicKey) string {
	if keyID := strings.TrimSpace(os.Getenv("ZT_CP_POLICY_SIGNING_KEY_ID")); keyID != "" {
		return keyID
	}
	hash := sha256.Sum256(pub)
	fp := hex.EncodeToString(hash[:])
	if len(fp) > defaultPolicyKeyIDFingerprintLen {
		fp = fp[:defaultPolicyKeyIDFingerprintLen]
	}
	return defaultPolicyKeyIDPrefix + "-" + fp
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
		ManifestID:        strings.TrimSpace(bundle.ManifestID),
		Profile:           strings.TrimSpace(bundle.Profile),
		Version:           strings.TrimSpace(bundle.Version),
		SHA256:            strings.TrimSpace(bundle.SHA256),
		EffectiveAt:       strings.TrimSpace(bundle.EffectiveAt),
		ExpiresAt:         strings.TrimSpace(bundle.ExpiresAt),
		KeyID:             strings.TrimSpace(bundle.KeyID),
		ContentTOML:       bundle.ContentTOML,
		MinGatewayVersion: strings.TrimSpace(bundle.MinGatewayVersion),
		DuplicateRule:     strings.TrimSpace(bundle.DuplicateRule),
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

func minimumGatewayVersion() string {
	if v := strings.TrimSpace(os.Getenv("ZT_CP_POLICY_MIN_GATEWAY_VERSION")); v != "" {
		return v
	}
	return "v0.5f"
}
