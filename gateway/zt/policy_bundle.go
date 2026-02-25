package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	policyErrorCodeVerifyFailed = "policy_verify_failed"
	policyErrorCodeStale        = "policy_stale"
)

type signedPolicyBundle struct {
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

type policyBundleVerifyError struct {
	ErrorCode string
	Reason    string
}

func (e *policyBundleVerifyError) Error() string {
	if e == nil {
		return ""
	}
	reason := strings.TrimSpace(e.Reason)
	if reason == "" {
		reason = "verification failed"
	}
	return fmt.Sprintf("%s: %s", strings.TrimSpace(e.ErrorCode), reason)
}

func isPolicyBundleFailClosedError(err error) bool {
	var e *policyBundleVerifyError
	return errors.As(err, &e)
}

func decodeAndVerifySignedPolicyBundle(body []byte, verifyAt time.Time, trustedKeys map[string]ed25519.PublicKey) (signedPolicyBundle, error) {
	var bundle signedPolicyBundle
	if err := json.Unmarshal(body, &bundle); err != nil {
		return signedPolicyBundle{}, &policyBundleVerifyError{ErrorCode: policyErrorCodeVerifyFailed, Reason: "invalid_json"}
	}
	if err := verifySignedPolicyBundle(bundle, verifyAt, trustedKeys); err != nil {
		return signedPolicyBundle{}, err
	}
	return bundle, nil
}

func verifySignedPolicyBundle(bundle signedPolicyBundle, verifyAt time.Time, trustedKeys map[string]ed25519.PublicKey) error {
	if verifyAt.IsZero() {
		verifyAt = time.Now().UTC()
	} else {
		verifyAt = verifyAt.UTC()
	}
	if err := validateSignedPolicyBundleFields(bundle); err != nil {
		return &policyBundleVerifyError{ErrorCode: policyErrorCodeVerifyFailed, Reason: err.Error()}
	}
	effectiveAt, err := time.Parse(time.RFC3339, strings.TrimSpace(bundle.EffectiveAt))
	if err != nil {
		return &policyBundleVerifyError{ErrorCode: policyErrorCodeVerifyFailed, Reason: "effective_at_invalid"}
	}
	expiresAt, err := time.Parse(time.RFC3339, strings.TrimSpace(bundle.ExpiresAt))
	if err != nil {
		return &policyBundleVerifyError{ErrorCode: policyErrorCodeVerifyFailed, Reason: "expires_at_invalid"}
	}
	if verifyAt.Before(effectiveAt) {
		return &policyBundleVerifyError{ErrorCode: policyErrorCodeStale, Reason: "policy_not_effective"}
	}
	if verifyAt.After(expiresAt) {
		return &policyBundleVerifyError{ErrorCode: policyErrorCodeStale, Reason: "policy_expired"}
	}
	pub, ok := trustedKeys[strings.TrimSpace(bundle.KeyID)]
	if !ok || len(pub) != ed25519.PublicKeySize {
		return &policyBundleVerifyError{ErrorCode: policyErrorCodeVerifyFailed, Reason: "policy_key_not_trusted"}
	}
	wantSHA := sha256HexBytes([]byte(bundle.ContentTOML))
	if !strings.EqualFold(strings.TrimSpace(bundle.SHA256), wantSHA) {
		return &policyBundleVerifyError{ErrorCode: policyErrorCodeVerifyFailed, Reason: "policy_sha256_mismatch"}
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(bundle.Signature))
	if err != nil {
		return &policyBundleVerifyError{ErrorCode: policyErrorCodeVerifyFailed, Reason: "policy_signature_decode_failed"}
	}
	signingBytes, err := policyBundleSigningBytes(bundle)
	if err != nil {
		return &policyBundleVerifyError{ErrorCode: policyErrorCodeVerifyFailed, Reason: "policy_signing_bytes_failed"}
	}
	if !ed25519.Verify(pub, signingBytes, sig) {
		return &policyBundleVerifyError{ErrorCode: policyErrorCodeVerifyFailed, Reason: "policy_signature_invalid"}
	}
	return nil
}

func validateSignedPolicyBundleFields(bundle signedPolicyBundle) error {
	required := map[string]string{
		"manifest_id":  bundle.ManifestID,
		"profile":      bundle.Profile,
		"version":      bundle.Version,
		"sha256":       bundle.SHA256,
		"effective_at": bundle.EffectiveAt,
		"expires_at":   bundle.ExpiresAt,
		"key_id":       bundle.KeyID,
		"signature":    bundle.Signature,
		"content_toml": bundle.ContentTOML,
	}
	for field, value := range required {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s_required", field)
		}
	}
	return nil
}

func policyBundleSigningBytes(bundle signedPolicyBundle) ([]byte, error) {
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
