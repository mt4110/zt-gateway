package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

func TestVerificationSummaryContract(t *testing.T) {
	t.Parallel()

	t.Run("returns fixed summary within JWT tenant", func(t *testing.T) {
		t.Parallel()
		srv, mock, cleanup := newDashboardContractServerWithSSO(t)
		defer cleanup()
		mock.ExpectQuery(`(?s)select ingest_id, envelope_tenant_id, kind, received_at.*where ingest_id = \$1 and kind = 'verify'.*envelope_tenant_id = \$2.*envelope_present = true and envelope_verified = true`).
			WithArgs("ing-a", "tenant-a").
			WillReturnRows(sqlmock.NewRows([]string{"ingest_id", "envelope_tenant_id", "kind", "received_at", "result", "decision", "present", "verified"}).
				AddRow("ing-a", "tenant-a", "verify", time.Date(2026, 10, 10, 0, 0, 0, 0, time.FixedZone("UTC+9", 9*60*60)), "verified", "allow", true, true))

		req := verificationSummaryRequest(t, "ing-a", map[string]any{"sub": "user-a", "tenant_id": "tenant-a", "role": "admin"})
		req.Header.Set("X-ZT-Tenant-ID", "tenant-b")
		req.Header.Set("X-ZT-Dashboard-Role", "viewer")
		rr := httptest.NewRecorder()
		srv.handleVerificationEventSummary(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
		}
		if rr.Header().Get("Cache-Control") != "no-store" || rr.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("security headers missing: %v", rr.Header())
		}
		var body map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if len(body) != 8 || body["tenant_id"] != "tenant-a" || body["received_at"] != "2026-10-09T15:00:00Z" || body["event_signature_verified"] != true {
			t.Fatalf("unexpected response: %#v", body)
		}
		for _, forbidden := range []string{"filename", "path", "payload", "reason", "key_id", "sha256", "sender"} {
			if _, exists := body[forbidden]; exists {
				t.Fatalf("sensitive field %q leaked: %#v", forbidden, body)
			}
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("missing tenant and cross tenant are same 404", func(t *testing.T) {
		t.Parallel()
		for _, id := range []string{"ing-missing", "ing-tenant-b"} {
			srv, mock, cleanup := newDashboardContractServerWithSSO(t)
			mock.ExpectQuery(regexp.QuoteMeta("select ingest_id, envelope_tenant_id, kind, received_at,")).
				WithArgs(id, "tenant-a").WillReturnRows(sqlmock.NewRows([]string{"ingest_id", "envelope_tenant_id", "kind", "received_at", "result", "decision", "present", "verified"}))
			req := verificationSummaryRequest(t, id, map[string]any{"sub": "user-a", "tenant_id": "tenant-a", "role": "admin"})
			rr := httptest.NewRecorder()
			srv.handleVerificationEventSummary(rr, req)
			if rr.Code != http.StatusNotFound || strings.TrimSpace(rr.Body.String()) != "{\n  \"error\": \"not_found\"\n}" {
				t.Fatalf("status/body = %d/%s", rr.Code, rr.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
			cleanup()
		}
	})

	t.Run("requires exp and SSO", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			name   string
			claims map[string]any
			token  bool
		}{
			{name: "exp missing", claims: map[string]any{"sub": "user-a", "tenant_id": "tenant-a"}, token: true},
			{name: "subject missing", claims: map[string]any{"tenant_id": "tenant-a"}, token: true},
			{name: "tenant missing", claims: map[string]any{"sub": "user-a"}, token: true},
			{name: "tenant invalid", claims: map[string]any{"sub": "user-a", "tenant_id": "tenant-a\x00bad"}, token: true},
			{name: "no token"},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				srv, mock, cleanup := newDashboardContractServerWithSSO(t)
				defer cleanup()
				req := httptest.NewRequest(http.MethodGet, "/v1/verification-events/ing-a/summary", nil)
				if tc.token {
					tc.claims["iss"] = "https://issuer.example"
					tc.claims["aud"] = "zt-cp"
					tc.claims["exp"] = time.Now().Add(time.Hour).Unix()
					if tc.name == "exp missing" {
						delete(tc.claims, "exp")
					}
					req.Header.Set("Authorization", "Bearer "+mustDashboardSSOToken(t, []byte("sso-secret"), tc.claims))
				}
				rr := httptest.NewRecorder()
				srv.handleVerificationEventSummary(rr, req)
				if rr.Code != http.StatusUnauthorized {
					t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
				}
				if err := mock.ExpectationsWereMet(); err != nil {
					t.Fatal(err)
				}
			})
		}
	})

	t.Run("rejects bad signature issuer audience and expiry", func(t *testing.T) {
		t.Parallel()
		cases := []struct {
			name   string
			claims map[string]any
			secret []byte
		}{
			{name: "signature", claims: map[string]any{"iss": "https://issuer.example", "aud": "zt-cp", "sub": "user-a", "tenant_id": "tenant-a", "exp": time.Now().Add(time.Hour).Unix()}, secret: []byte("wrong-secret")},
			{name: "issuer", claims: map[string]any{"iss": "https://untrusted.example", "aud": "zt-cp", "sub": "user-a", "tenant_id": "tenant-a", "exp": time.Now().Add(time.Hour).Unix()}, secret: []byte("sso-secret")},
			{name: "audience", claims: map[string]any{"iss": "https://issuer.example", "aud": "other", "sub": "user-a", "tenant_id": "tenant-a", "exp": time.Now().Add(time.Hour).Unix()}, secret: []byte("sso-secret")},
			{name: "expired", claims: map[string]any{"iss": "https://issuer.example", "aud": "zt-cp", "sub": "user-a", "tenant_id": "tenant-a", "exp": time.Now().Add(-time.Hour).Unix()}, secret: []byte("sso-secret")},
			{name: "future iat", claims: map[string]any{"iss": "https://issuer.example", "aud": "zt-cp", "sub": "user-a", "tenant_id": "tenant-a", "iat": time.Now().Add(time.Hour).Unix(), "exp": time.Now().Add(2 * time.Hour).Unix()}, secret: []byte("sso-secret")},
			{name: "non-string issuer", claims: map[string]any{"iss": []string{"https://issuer.example"}, "aud": "zt-cp", "sub": "user-a", "tenant_id": "tenant-a", "exp": time.Now().Add(time.Hour).Unix()}, secret: []byte("sso-secret")},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				srv, mock, cleanup := newDashboardContractServerWithSSO(t)
				defer cleanup()
				req := httptest.NewRequest(http.MethodGet, "/v1/verification-events/ing-a/summary", nil)
				req.Header.Set("Authorization", "Bearer "+mustDashboardSSOToken(t, tc.secret, tc.claims))
				req.Header.Set("X-API-Key", "api-key-must-not-authenticate")
				rr := httptest.NewRecorder()
				srv.handleVerificationEventSummary(rr, req)
				if rr.Code != http.StatusUnauthorized {
					t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
				}
				if err := mock.ExpectationsWereMet(); err != nil {
					t.Fatal(err)
				}
			})
		}
	})

	t.Run("rejects inconsistent row and unavailable database", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			name              string
			id, tenant, kind  string
			present, verified bool
		}{
			{name: "wrong ID", id: "ing-other", tenant: "tenant-a", kind: "verify", present: true, verified: true},
			{name: "wrong tenant", id: "ing-a", tenant: "tenant-b", kind: "verify", present: true, verified: true},
			{name: "wrong kind", id: "ing-a", tenant: "tenant-a", kind: "scan", present: true, verified: true},
			{name: "not signed", id: "ing-a", tenant: "tenant-a", kind: "verify", present: false, verified: true},
			{name: "unverified", id: "ing-a", tenant: "tenant-a", kind: "verify", present: true, verified: false},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				srv, mock, cleanup := newDashboardContractServerWithSSO(t)
				defer cleanup()
				mock.ExpectQuery(`(?s)select ingest_id, envelope_tenant_id, kind, received_at`).
					WithArgs("ing-a", "tenant-a").WillReturnRows(sqlmock.NewRows([]string{"ingest_id", "envelope_tenant_id", "kind", "received_at", "result", "decision", "present", "verified"}).
					AddRow(tc.id, tc.tenant, tc.kind, time.Now().UTC(), "verified", "allow", tc.present, tc.verified))
				req := verificationSummaryRequest(t, "ing-a", map[string]any{"sub": "user-a", "tenant_id": "tenant-a"})
				rr := httptest.NewRecorder()
				srv.handleVerificationEventSummary(rr, req)
				if rr.Code != http.StatusServiceUnavailable || strings.Contains(rr.Body.String(), "ing-other") || strings.Contains(rr.Body.String(), "tenant-b") {
					t.Fatalf("status/body=%d/%s", rr.Code, rr.Body.String())
				}
				if err := mock.ExpectationsWereMet(); err != nil {
					t.Fatal(err)
				}
			})
		}
	})

	t.Run("rejects query, malformed id, method and DB errors without data", func(t *testing.T) {
		t.Parallel()
		cases := []struct {
			method string
			path   string
			status int
			allow  string
		}{
			{method: http.MethodGet, path: "/v1/verification-events/bad%20id/summary", status: http.StatusBadRequest},
			{method: http.MethodGet, path: "/v1/verification-events/ing-a/summary?tenant_id=tenant-b", status: http.StatusBadRequest},
			{method: http.MethodPost, path: "/v1/verification-events/ing-a/summary", status: http.StatusMethodNotAllowed, allow: "GET"},
		}
		for _, tc := range cases {
			srv, mock, cleanup := newDashboardContractServerWithSSO(t)
			defer cleanup()
			req := verificationSummaryRequest(t, "ing-a", map[string]any{"sub": "user-a", "tenant_id": "tenant-a"})
			req.Method, req.URL = tc.method, mustParseSummaryURL(t, tc.path)
			rr := httptest.NewRecorder()
			srv.handleVerificationEventSummary(rr, req)
			if rr.Code != tc.status || rr.Header().Get("Allow") != tc.allow || strings.Contains(rr.Body.String(), "tenant-a") {
				t.Fatalf("status/header/body = %d/%q/%s", rr.Code, rr.Header().Get("Allow"), rr.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		}
		srv, mock, cleanup := newDashboardContractServerWithSSO(t)
		defer cleanup()
		mock.ExpectQuery(regexp.QuoteMeta("select ingest_id, envelope_tenant_id, kind, received_at,")).
			WithArgs("ing-a", "tenant-a").WillReturnError(errors.New("private database error"))
		req := verificationSummaryRequest(t, "ing-a", map[string]any{"sub": "user-a", "tenant_id": "tenant-a"})
		rr := httptest.NewRecorder()
		srv.handleVerificationEventSummary(rr, req)
		if rr.Code != http.StatusServiceUnavailable || strings.Contains(rr.Body.String(), "private database error") {
			t.Fatalf("status/body=%d/%s", rr.Code, rr.Body.String())
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestVerificationSummaryNormalizesReportedValues(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ input, want string }{
		{"verified", "verified"}, {"failed", "failed"}, {"warning", "warning"}, {"mystery", "unknown"}, {"", "unknown"},
	} {
		if got := normalizedSummaryResult(tc.input); got != tc.want {
			t.Errorf("result %q = %q, want %q", tc.input, got, tc.want)
		}
	}
	for _, tc := range []struct{ input, want string }{
		{"allow", "allow"}, {"deny", "deny"}, {"degraded", "degraded"}, {"mystery", "unknown"}, {"", "unknown"},
	} {
		if got := normalizedSummaryDecision(tc.input); got != tc.want {
			t.Errorf("decision %q = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestVerificationSummaryCanceledRequestFailsClosed(t *testing.T) {
	srv, mock, cleanup := newDashboardContractServerWithSSO(t)
	defer cleanup()
	req := verificationSummaryRequest(t, "ing-a", map[string]any{"sub": "user-a", "tenant_id": "tenant-a"})
	ctx, cancel := context.WithCancel(req.Context())
	cancel()
	rr := httptest.NewRecorder()
	srv.handleVerificationEventSummary(rr, req.WithContext(ctx))
	if rr.Code != http.StatusServiceUnavailable || strings.TrimSpace(rr.Body.String()) != "{\n  \"error\": \"service_unavailable\"\n}" {
		t.Fatalf("status/body=%d/%s", rr.Code, rr.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestVerificationSummaryDBTimeoutFailsClosed(t *testing.T) {
	srv, mock, cleanup := newDashboardContractServerWithSSO(t)
	defer cleanup()
	mock.ExpectQuery(`(?s)select ingest_id, envelope_tenant_id, kind, received_at`).
		WithArgs("ing-a", "tenant-a").WillDelayFor(verificationSummaryDBTimeout + time.Second).
		WillReturnRows(sqlmock.NewRows([]string{"ingest_id", "envelope_tenant_id", "kind", "received_at", "result", "decision", "present", "verified"}).
			AddRow("ing-a", "tenant-a", "verify", time.Now().UTC(), "verified", "allow", true, true))
	req := verificationSummaryRequest(t, "ing-a", map[string]any{"sub": "user-a", "tenant_id": "tenant-a"})
	rr := httptest.NewRecorder()
	srv.handleVerificationEventSummary(rr, req)
	if rr.Code != http.StatusServiceUnavailable || strings.Contains(rr.Body.String(), "ing-a") {
		t.Fatalf("status/body=%d/%s", rr.Code, rr.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestVerificationSummaryIngestThenReadMockDB(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	srv := &server{
		dataDir: t.TempDir(), db: db, eventKeyRegistryEnabled: true,
		eventKeyRegistry: map[string]eventKeyRegistryEntry{"key-a": {KeyID: "key-a", TenantID: "tenant-a", Alg: "Ed25519", Enabled: boolPtrSummary(true), publicKey: pub}},
		sso:              &controlPlaneSSOConfig{Enabled: true, Issuer: "https://issuer.example", Audience: "zt-cp", RoleClaim: "role", TenantClaim: "tenant_id", SubjectClaim: "sub", HS256Secret: []byte("sso-secret")},
	}
	payload := json.RawMessage(`{"event_id":"evt-summary","result":"failed","policy_decision":{"decision":"deny"},"file_name":"secret.txt","private_path":"/private/secret.txt","reason":"private explanation"}`)
	env := signedEventEnvelope{EnvelopeVersion: "zt-event-envelope-v1", Alg: "Ed25519", KeyID: "key-a", CreatedAt: time.Now().UTC().Format(time.RFC3339), Endpoint: "/v1/events/verify", PayloadSHA256: sha256Hex(payload), Payload: payload}
	signingBytes, err := envelopeSigningBytes(env)
	if err != nil {
		t.Fatal(err)
	}
	env.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, signingBytes))
	body, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectQuery(regexp.QuoteMeta("select key_id, coalesce(tenant_id,''), coalesce(alg,''), public_key_b64, enabled, coalesce(updated_by,''), coalesce(update_reason,'')\nfrom event_signing_keys\nwhere key_id = $1")).
		WithArgs("key-a").WillReturnRows(sqlmock.NewRows([]string{"key_id", "tenant_id", "alg", "public_key_b64", "enabled", "updated_by", "update_reason"}).
		AddRow("key-a", "tenant-a", "Ed25519", base64.StdEncoding.EncodeToString(pub), true, "", ""))
	mock.ExpectExec(`(?s)insert into event_ingest`).WillReturnResult(sqlmock.NewResult(0, 1))
	ingestReq := httptest.NewRequest(http.MethodPost, "/v1/events/verify", strings.NewReader(string(body)))
	ingestRR := httptest.NewRecorder()
	srv.handleEventIngest("verify")(ingestRR, ingestReq)
	if ingestRR.Code != http.StatusAccepted {
		t.Fatalf("ingest status=%d body=%s", ingestRR.Code, ingestRR.Body.String())
	}
	var accepted map[string]any
	if err := json.Unmarshal(ingestRR.Body.Bytes(), &accepted); err != nil {
		t.Fatal(err)
	}
	ingestID, _ := accepted["ingest_id"].(string)
	if ingestID == "" {
		t.Fatal("ingest response has no ingest_id")
	}
	mock.ExpectQuery(`(?s)select ingest_id, envelope_tenant_id, kind, received_at.*where ingest_id = \$1 and kind = 'verify'.*envelope_tenant_id = \$2.*envelope_present = true and envelope_verified = true`).
		WithArgs(ingestID, "tenant-a").WillReturnRows(sqlmock.NewRows([]string{"ingest_id", "envelope_tenant_id", "kind", "received_at", "result", "decision", "present", "verified"}).
		AddRow(ingestID, "tenant-a", "verify", time.Now().UTC(), "failed", "deny", true, true))
	readReq := verificationSummaryRequest(t, ingestID, map[string]any{"sub": "user-a", "tenant_id": "tenant-a", "role": "viewer"})
	readRR := httptest.NewRecorder()
	srv.handleVerificationEventSummary(readRR, readReq)
	if readRR.Code != http.StatusOK || !strings.Contains(readRR.Body.String(), `"reported_result":"failed"`) || !strings.Contains(readRR.Body.String(), `"reported_policy_decision":"deny"`) {
		t.Fatalf("summary status/body=%d/%s", readRR.Code, readRR.Body.String())
	}
	for _, secret := range []string{"secret.txt", "/private/secret.txt", "private explanation"} {
		if strings.Contains(readRR.Body.String(), secret) {
			t.Fatalf("payload leaked %q", secret)
		}
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func verificationSummaryRequest(t *testing.T, id string, claims map[string]any) *http.Request {
	t.Helper()
	claims["iss"], claims["aud"], claims["exp"] = "https://issuer.example", "zt-cp", time.Now().Add(time.Hour).Unix()
	req := httptest.NewRequest(http.MethodGet, "/v1/verification-events/"+id+"/summary", nil)
	req.Header.Set("Authorization", "Bearer "+mustDashboardSSOToken(t, []byte("sso-secret"), claims))
	return req
}

func mustParseSummaryURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func boolPtrSummary(value bool) *bool { return &value }
