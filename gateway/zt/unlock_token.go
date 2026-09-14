package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	unlockTokenSchemaVersion = "v1"
	unlockTokenScopeRootPin  = "secure_pack_root_pin"
	unlockTokenMinApprovals  = 2

	unlockTokenPathEnv      = "ZT_BREAKGLASS_TOKEN_FILE"
	unlockTrustedSignersEnv = "ZT_BREAKGLASS_TRUSTED_SIGNERS"
	unlockAllowEmbeddedEnv  = "ZT_BREAKGLASS_ALLOW_EMBEDDED_SIGNERS"
)

type unlockToken struct {
	SchemaVersion string                `json:"schema_version"`
	Scope         string                `json:"scope"`
	Reason        string                `json:"reason"`
	IssuedAt      string                `json:"issued_at"`
	ExpiresAt     string                `json:"expires_at"`
	AllowRootPins []string              `json:"allow_root_fingerprints"`
	Approvals     []unlockTokenApproval `json:"approvals"`
}

type unlockTokenApproval struct {
	SignerID      string `json:"signer_id"`
	SignerPubKey  string `json:"signer_pubkey_b64"`
	Signature     string `json:"signature_b64"`
	SignedAt      string `json:"signed_at"`
	SignatureType string `json:"signature_type,omitempty"`
}

type unlockTokenVerification struct {
	Path               string   `json:"path"`
	Present            bool     `json:"present"`
	Active             bool     `json:"active"`
	Reason             string   `json:"reason,omitempty"`
	TrustedSource      string   `json:"trusted_source,omitempty"`
	ValidApprovals     int      `json:"valid_approvals"`
	RequiredApprovals  int      `json:"required_approvals"`
	SignerIDs          []string `json:"signer_ids,omitempty"`
	AllowRootPins      []string `json:"allow_root_fingerprints,omitempty"`
	ExpiresAt          string   `json:"expires_at,omitempty"`
	TrustedConfigured  bool     `json:"trusted_configured"`
	TrustedSignerCount int      `json:"trusted_signer_count"`
	Badge              string   `json:"badge,omitempty"`
}

func defaultUnlockTokenPath(repoRoot string) string {
	return filepath.Join(repoRoot, ".zt-spool", "unlock-token.json")
}

func resolveUnlockTokenPath(repoRoot string) string {
	if p := strings.TrimSpace(os.Getenv(unlockTokenPathEnv)); p != "" {
		if abs, err := filepath.Abs(p); err == nil {
			return abs
		}
		return p
	}
	return defaultUnlockTokenPath(repoRoot)
}

func splitUnlockSignerList(raw string) []string {
	return strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r'
	})
}

func loadUnlockTrustedSignersFromEnv() (map[string]ed25519.PublicKey, string, error) {
	raw := strings.TrimSpace(os.Getenv(unlockTrustedSignersEnv))
	if raw == "" {
		return nil, "none", nil
	}
	tokens := splitUnlockSignerList(raw)
	out := make(map[string]ed25519.PublicKey, len(tokens))
	for _, token := range tokens {
		id, keyRaw, err := splitSignerSpec(token)
		if err != nil {
			return nil, "env", fmt.Errorf("%s entry %q: %w", unlockTrustedSignersEnv, token, err)
		}
		pub, err := decodeUnlockPublicKeyB64(keyRaw)
		if err != nil {
			return nil, "env", fmt.Errorf("%s signer %q: %w", unlockTrustedSignersEnv, id, err)
		}
		out[id] = pub
	}
	return out, "env", nil
}

func splitSignerSpec(raw string) (string, string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", fmt.Errorf("empty signer")
	}
	parts := strings.SplitN(raw, ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("expected <signer_id>:<value>")
	}
	id := strings.TrimSpace(parts[0])
	val := strings.TrimSpace(parts[1])
	if id == "" || val == "" {
		return "", "", fmt.Errorf("expected non-empty <signer_id>:<value>")
	}
	return id, val, nil
}

func parseUnlockPrivateKeyB64(raw string) (ed25519.PrivateKey, error) {
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

func decodeUnlockPublicKeyB64(raw string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("expected %d-byte public key, got %d", ed25519.PublicKeySize, len(b))
	}
	return ed25519.PublicKey(b), nil
}

func writeUnlockTokenFile(path string, tok unlockToken) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("empty unlock token path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(tok, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o600)
}

func readUnlockTokenFile(path string) (unlockToken, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return unlockToken{}, err
	}
	var tok unlockToken
	if err := json.Unmarshal(data, &tok); err != nil {
		return unlockToken{}, err
	}
	return tok, nil
}

func canonicalUnlockToken(tok unlockToken) (unlockToken, error) {
	c := unlockToken{
		SchemaVersion: strings.TrimSpace(tok.SchemaVersion),
		Scope:         strings.TrimSpace(tok.Scope),
		Reason:        strings.TrimSpace(tok.Reason),
		IssuedAt:      strings.TrimSpace(tok.IssuedAt),
		ExpiresAt:     strings.TrimSpace(tok.ExpiresAt),
	}
	if c.SchemaVersion == "" {
		c.SchemaVersion = unlockTokenSchemaVersion
	}
	if c.Scope == "" {
		c.Scope = unlockTokenScopeRootPin
	}
	for _, pin := range tok.AllowRootPins {
		fp, err := normalizePGPFingerprint(pin)
		if err != nil {
			return unlockToken{}, fmt.Errorf("allow_root_fingerprints: %w", err)
		}
		c.AllowRootPins = append(c.AllowRootPins, fp)
	}
	c.AllowRootPins = dedupeStrings(c.AllowRootPins)
	sort.Strings(c.AllowRootPins)
	return c, nil
}

func unlockPayloadHash(tok unlockToken) (string, error) {
	canonical, err := canonicalUnlockToken(tok)
	if err != nil {
		return "", err
	}
	payload := struct {
		SchemaVersion string   `json:"schema_version"`
		Scope         string   `json:"scope"`
		Reason        string   `json:"reason"`
		IssuedAt      string   `json:"issued_at"`
		ExpiresAt     string   `json:"expires_at"`
		AllowRootPins []string `json:"allow_root_fingerprints"`
	}{
		SchemaVersion: canonical.SchemaVersion,
		Scope:         canonical.Scope,
		Reason:        canonical.Reason,
		IssuedAt:      canonical.IssuedAt,
		ExpiresAt:     canonical.ExpiresAt,
		AllowRootPins: canonical.AllowRootPins,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func unlockSigningMessage(payloadHash, signerID string) []byte {
	return []byte("zt-unlock-token-v1:" + strings.TrimSpace(payloadHash) + ":" + strings.TrimSpace(signerID))
}

func verifyUnlockToken(tok unlockToken, now time.Time, trusted map[string]ed25519.PublicKey, trustedSource string) (unlockTokenVerification, error) {
	v := unlockTokenVerification{
		RequiredApprovals: unlockTokenMinApprovals,
		TrustedSource:     trustedSource,
		TrustedConfigured: len(trusted) > 0,
		TrustedSignerCount: func() int {
			return len(trusted)
		}(),
	}

	canonical, err := canonicalUnlockToken(tok)
	if err != nil {
		v.Reason = err.Error()
		return v, err
	}
	if canonical.SchemaVersion != unlockTokenSchemaVersion {
		err := fmt.Errorf("unsupported schema_version %q", canonical.SchemaVersion)
		v.Reason = err.Error()
		return v, err
	}
	if canonical.Scope != unlockTokenScopeRootPin {
		err := fmt.Errorf("unsupported scope %q", canonical.Scope)
		v.Reason = err.Error()
		return v, err
	}
	if canonical.Reason == "" {
		err := fmt.Errorf("reason is required")
		v.Reason = err.Error()
		return v, err
	}
	if len(canonical.AllowRootPins) == 0 {
		err := fmt.Errorf("allow_root_fingerprints is empty")
		v.Reason = err.Error()
		return v, err
	}
	if len(trusted) == 0 && !envBool(unlockAllowEmbeddedEnv) {
		err := fmt.Errorf("trusted_signers_not_configured")
		v.Reason = err.Error()
		return v, err
	}

	issuedAt, err := time.Parse(time.RFC3339, canonical.IssuedAt)
	if err != nil {
		v.Reason = "issued_at_invalid"
		return v, fmt.Errorf("issued_at_invalid")
	}
	expiresAt, err := time.Parse(time.RFC3339, canonical.ExpiresAt)
	if err != nil {
		v.Reason = "expires_at_invalid"
		return v, fmt.Errorf("expires_at_invalid")
	}
	if !expiresAt.After(issuedAt) {
		v.Reason = "expires_at_must_be_after_issued_at"
		return v, fmt.Errorf("expires_at_must_be_after_issued_at")
	}
	now = now.UTC()
	if now.After(expiresAt) {
		v.Reason = "token_expired"
		v.ExpiresAt = expiresAt.UTC().Format(time.RFC3339)
		return v, fmt.Errorf("token_expired")
	}

	payloadHash, err := unlockPayloadHash(tok)
	if err != nil {
		v.Reason = err.Error()
		return v, err
	}
	seen := map[string]struct{}{}
	signerIDs := make([]string, 0, len(tok.Approvals))
	valid := 0
	for _, approval := range tok.Approvals {
		signerID := strings.TrimSpace(approval.SignerID)
		if signerID == "" {
			continue
		}
		if _, dup := seen[signerID]; dup {
			continue
		}

		var pub ed25519.PublicKey
		if len(trusted) > 0 {
			trustedPub, ok := trusted[signerID]
			if !ok {
				continue
			}
			pubFromToken, err := decodeUnlockPublicKeyB64(approval.SignerPubKey)
			if err != nil {
				continue
			}
			if base64.StdEncoding.EncodeToString(pubFromToken) != base64.StdEncoding.EncodeToString(trustedPub) {
				continue
			}
			pub = trustedPub
		} else {
			pubFromToken, err := decodeUnlockPublicKeyB64(approval.SignerPubKey)
			if err != nil {
				continue
			}
			pub = pubFromToken
		}

		sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(approval.Signature))
		if err != nil {
			continue
		}
		msg := unlockSigningMessage(payloadHash, signerID)
		if !ed25519.Verify(pub, msg, sig) {
			continue
		}
		seen[signerID] = struct{}{}
		signerIDs = append(signerIDs, signerID)
		valid++
	}
	sort.Strings(signerIDs)

	v.ValidApprovals = valid
	v.SignerIDs = signerIDs
	v.AllowRootPins = canonical.AllowRootPins
	v.ExpiresAt = expiresAt.UTC().Format(time.RFC3339)
	if valid < unlockTokenMinApprovals {
		v.Reason = "insufficient_valid_approvals"
		return v, fmt.Errorf("insufficient_valid_approvals")
	}

	v.Active = true
	v.Reason = "active"
	return v, nil
}

func loadUnlockRootPinOverrides(repoRoot string, now time.Time) (unlockTokenVerification, error) {
	path := resolveUnlockTokenPath(repoRoot)
	v := unlockTokenVerification{
		Path:              path,
		RequiredApprovals: unlockTokenMinApprovals,
	}
	tok, err := readUnlockTokenFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			v.Present = false
			v.Reason = "token_not_found"
			return finalizeUnlockTokenVerification(v), nil
		}
		v.Present = true
		v.Reason = err.Error()
		return finalizeUnlockTokenVerification(v), err
	}
	v.Present = true

	trusted, source, trustedErr := loadUnlockTrustedSignersFromEnv()
	if trustedErr != nil {
		v.Reason = trustedErr.Error()
		return finalizeUnlockTokenVerification(v), trustedErr
	}
	verified, verifyErr := verifyUnlockToken(tok, now, trusted, source)
	verified.Path = path
	verified.Present = true
	if verifyErr != nil {
		return finalizeUnlockTokenVerification(verified), verifyErr
	}
	return finalizeUnlockTokenVerification(verified), nil
}

func mergeRootPinsWithUnlockToken(repoRoot string, basePins []string, source string, now time.Time) ([]string, string, *unlockTokenVerification) {
	merged := append([]string(nil), basePins...)
	v, err := loadUnlockRootPinOverrides(repoRoot, now)
	if err != nil {
		return merged, source, &v
	}
	if v.Active && len(v.AllowRootPins) > 0 {
		merged = dedupeStrings(append(merged, v.AllowRootPins...))
		sort.Strings(merged)
		if strings.TrimSpace(source) == "" || source == "none" {
			source = "unlock-token"
		} else {
			source += "+unlock-token"
		}
	}
	return merged, source, &v
}

func finalizeUnlockTokenVerification(v unlockTokenVerification) unlockTokenVerification {
	v.Badge = resolveUnlockBadge(v)
	return v
}

func resolveUnlockBadge(v unlockTokenVerification) string {
	if !v.Present {
		return "none"
	}
	if v.Active {
		return "active"
	}
	switch strings.TrimSpace(v.Reason) {
	case "token_expired":
		return "expired"
	case "insufficient_valid_approvals":
		return "pending"
	}
	if v.ValidApprovals > 0 && v.ValidApprovals < v.RequiredApprovals {
		return "pending"
	}
	return "inactive"
}
