package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

const summaryAuthorityDomain = "zt-summary-authority-v1."
const summaryReadPermission = "verification-event-summary:read"

type verificationSummaryEdgeConfig struct {
	transportSecret string
	authorityKey    []byte
}

// Opt-in dedicated origin mode; partial configurations never silently enable an
// unprotected endpoint. Secrets are independent, random 32-byte base64url values.
func loadVerificationSummaryEdgeConfig() (*verificationSummaryEdgeConfig, error) {
	mode := os.Getenv("ZT_CP_SUMMARY_EDGE_ONLY")
	transport := os.Getenv("ZT_CP_SUMMARY_EDGE_SECRET")
	key := os.Getenv("ZT_CP_SUMMARY_AUTHORITY_KEY")
	if mode == "" && transport == "" && key == "" {
		return nil, nil
	}
	t, e1 := base64.RawURLEncoding.DecodeString(transport)
	k, e2 := base64.RawURLEncoding.DecodeString(key)
	if mode != "1" || e1 != nil || e2 != nil || len(t) != 32 || len(k) != 32 ||
		base64.RawURLEncoding.EncodeToString(t) != transport || base64.RawURLEncoding.EncodeToString(k) != key || hmac.Equal(t, k) {
		return nil, errors.New("invalid summary edge configuration")
	}
	return &verificationSummaryEdgeConfig{transportSecret: transport, authorityKey: k}, nil
}

var summaryNoncePattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

func (cfg *verificationSummaryEdgeConfig) validRequest(r *http.Request) bool {
	if cfg == nil || len(cfg.authorityKey) != 32 || len(cfg.transportSecret) != 43 {
		return false
	}
	values := r.Header.Values("X-ZT-Edge-Secret")
	nonces := r.Header.Values("X-ZT-Read-Nonce")
	return len(values) == 1 && len(nonces) == 1 &&
		subtle.ConstantTimeCompare([]byte(values[0]), []byte(cfg.transportSecret)) == 1 &&
		summaryNoncePattern.MatchString(nonces[0])
}

type summaryAuthorityContext struct {
	Principal  string   `json:"principal"`
	Tenant     string   `json:"tenant"`
	Permission string   `json:"permission"`
	RecordIDs  []string `json:"record_ids"`
}

type summaryAuthorityProof struct {
	Version   int                     `json:"version"`
	Nonce     string                  `json:"nonce"`
	Path      string                  `json:"path"`
	ExpiresAt int64                   `json:"expires_at"`
	Context   summaryAuthorityContext `json:"context"`
}

// Called only after JWT authentication, tenant-constrained SQL lookup and row
// predicate checks. Context is never reconstructed from the serialized payload.
func (cfg *verificationSummaryEdgeConfig) proof(r *http.Request, auth controlPlaneAuthContext, authorizedID string) (string, error) {
	if !cfg.validRequest(r) || auth.Issuer == "" || len(auth.Issuer) > 2048 || !validSummaryPrincipal(auth.Subject) || !validSummaryPrincipal(auth.TenantID) || !verificationSummaryIDPattern.MatchString(authorizedID) {
		return "", errors.New("invalid summary authority")
	}
	// Namespace subjects by issuer so equal sub values from different issuers do
	// not accidentally share a disclosure budget. This hash is not anonymity.
	principal := sha256.Sum256([]byte(auth.Issuer + "\x00" + auth.Subject))
	p := summaryAuthorityProof{
		Version: 1, Nonce: r.Header.Get("X-ZT-Read-Nonce"), Path: r.URL.Path,
		ExpiresAt: time.Now().Add(30 * time.Second).Unix(),
		Context:   summaryAuthorityContext{hex.EncodeToString(principal[:]), auth.TenantID, summaryReadPermission, []string{authorizedID}},
	}
	body, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(body)
	mac := hmac.New(sha256.New, cfg.authorityKey)
	_, _ = mac.Write([]byte(summaryAuthorityDomain + payload))
	return payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (s *server) verificationSummaryEdgeHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if s.summaryEdge == nil {
			writeVerificationSummaryError(w, http.StatusServiceUnavailable)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/v1/verification-events/") {
			writeVerificationSummaryError(w, http.StatusNotFound)
			return
		}
		s.handleVerificationEventSummary(w, r)
	})
}
