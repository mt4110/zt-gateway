package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode"

	jwt "github.com/golang-jwt/jwt/v5"
)

const verificationSummaryDBTimeout = 3 * time.Second

var verificationSummaryIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type verificationEventSummary struct {
	SchemaVersion          int    `json:"schema_version"`
	IngestID               string `json:"ingest_id"`
	TenantID               string `json:"tenant_id"`
	Kind                   string `json:"kind"`
	ReceivedAt             string `json:"received_at"`
	ReportedResult         string `json:"reported_result"`
	ReportedPolicyDecision string `json:"reported_policy_decision"`
	EventSignatureVerified bool   `json:"event_signature_verified"`
}

func (s *server) handleVerificationEventSummary(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeVerificationSummaryError(w, http.StatusMethodNotAllowed)
		return
	}
	if s == nil || s.sso == nil || !s.sso.Enabled || s.db == nil {
		writeVerificationSummaryError(w, http.StatusServiceUnavailable)
		return
	}
	if r.URL.RawQuery != "" {
		writeVerificationSummaryError(w, http.StatusBadRequest)
		return
	}
	const prefix = "/v1/verification-events/"
	const suffix = "/summary"
	if !strings.HasPrefix(r.URL.Path, prefix) || !strings.HasSuffix(r.URL.Path, suffix) {
		writeVerificationSummaryError(w, http.StatusBadRequest)
		return
	}
	ingestID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, prefix), suffix)
	if strings.Contains(ingestID, "/") || !verificationSummaryIDPattern.MatchString(ingestID) {
		writeVerificationSummaryError(w, http.StatusBadRequest)
		return
	}

	authCtx, err := s.sso.authenticateBearerToken(r, false)
	if err != nil {
		var authErr *controlPlaneAuthError
		if errors.As(err, &authErr) && authErr.Status == http.StatusForbidden {
			writeVerificationSummaryError(w, http.StatusForbidden)
		} else {
			writeVerificationSummaryError(w, http.StatusUnauthorized)
		}
		return
	}
	// The shared verifier has already validated signature, alg, issuer policy, audience, exp
	// (when present), and nbf with 30 seconds of leeway. Inspect claims only after signature
	// verification to require exp and check iat here, since the shared verifier leaves iat optional.
	claims := jwt.MapClaims{}
	if _, _, err := new(jwt.Parser).ParseUnverified(extractBearerToken(r), claims); err != nil {
		writeVerificationSummaryError(w, http.StatusUnauthorized)
		return
	}
	expiry, expiryErr := claims.GetExpirationTime()
	issuedAt, issuedAtErr := claims.GetIssuedAt()
	issuer, issuerOK := claims["iss"].(string)
	subject, subjectOK := claims[s.sso.SubjectClaim].(string)
	tenantID, tenantOK := claims[s.sso.TenantClaim].(string)
	if expiryErr != nil || expiry == nil || issuedAtErr != nil || (issuedAt != nil && issuedAt.Time.After(time.Now().Add(30*time.Second))) || !issuerOK || strings.TrimSpace(issuer) != authCtx.Issuer ||
		!subjectOK || subject != authCtx.Subject || !validSummaryPrincipal(subject) ||
		!tenantOK || tenantID != authCtx.TenantID || !validSummaryPrincipal(tenantID) {
		writeVerificationSummaryError(w, http.StatusUnauthorized)
		return
	}
	if authCtx.Role != dashboardRoleViewer && authCtx.Role != dashboardRoleOperator && authCtx.Role != dashboardRoleAuditor && authCtx.Role != dashboardRoleAdmin {
		writeVerificationSummaryError(w, http.StatusForbidden)
		return
	}
	if r.URL.Path != prefix+ingestID+suffix {
		writeVerificationSummaryError(w, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), verificationSummaryDBTimeout)
	defer cancel()
	var row verificationEventSummary
	var receivedAt time.Time
	var rawResult, rawDecision string
	var envelopePresent, envelopeVerified bool
	err = s.db.QueryRowContext(ctx, `
select ingest_id, envelope_tenant_id, kind, received_at,
       coalesce(payload_json->>'result',''),
       coalesce(payload_json->'policy_decision'->>'decision',''),
       envelope_present, envelope_verified
from event_ingest
where ingest_id = $1 and kind = 'verify'
  and envelope_tenant_id = $2 and envelope_present = true and envelope_verified = true
limit 1
`, ingestID, authCtx.TenantID).Scan(
		&row.IngestID, &row.TenantID, &row.Kind, &receivedAt, &rawResult, &rawDecision,
		&envelopePresent, &envelopeVerified,
	)
	if errors.Is(err, sql.ErrNoRows) {
		writeVerificationSummaryError(w, http.StatusNotFound)
		return
	}
	if err != nil {
		writeVerificationSummaryError(w, http.StatusServiceUnavailable)
		return
	}
	// Re-check all security predicates against returned data before constructing a response.
	if row.IngestID != ingestID || row.TenantID != authCtx.TenantID || row.Kind != "verify" || !envelopePresent || !envelopeVerified || receivedAt.IsZero() {
		writeVerificationSummaryError(w, http.StatusServiceUnavailable)
		return
	}
	row.EventSignatureVerified = envelopeVerified
	if len(row.IngestID) > 128 || len(row.TenantID) > 128 || len(rawResult) > 128 || len(rawDecision) > 128 {
		writeVerificationSummaryError(w, http.StatusServiceUnavailable)
		return
	}
	row.SchemaVersion = 1
	row.ReceivedAt = receivedAt.UTC().Format(time.RFC3339)
	row.ReportedResult = normalizedSummaryResult(rawResult)
	row.ReportedPolicyDecision = normalizedSummaryDecision(rawDecision)
	encoded, err := json.Marshal(row)
	if err != nil || len(encoded)+1 > 4096 {
		writeVerificationSummaryError(w, http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(append(encoded, '\n'))
}

func validSummaryPrincipal(value string) bool {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func normalizedSummaryResult(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "verified", "failed", "warning":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "unknown"
	}
}

func normalizedSummaryDecision(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "allow", "deny", "degraded":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "unknown"
	}
}

func writeVerificationSummaryError(w http.ResponseWriter, status int) {
	code := "service_unavailable"
	switch status {
	case http.StatusBadRequest:
		code = "bad_request"
	case http.StatusUnauthorized:
		code = "unauthorized"
	case http.StatusForbidden:
		code = "forbidden"
	case http.StatusNotFound:
		code = "not_found"
	case http.StatusMethodNotAllowed:
		code = "method_not_allowed"
	}
	writeJSON(w, status, map[string]string{"error": code})
}
