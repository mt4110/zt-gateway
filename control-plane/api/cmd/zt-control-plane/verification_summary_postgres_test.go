package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// This test is opt-in and must only point at a disposable, isolated PostgreSQL database.
// It creates schema objects and synthetic rows; it intentionally does not delete rows.
func TestVerificationSummaryPostgresIngestToRead(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("ZT_CP_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set ZT_CP_TEST_POSTGRES_DSN to a disposable isolated PostgreSQL database")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open isolated PostgreSQL: %v", err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("connect isolated PostgreSQL: %v", err)
	}
	if err := ensurePostgresSchema(ctx, db); err != nil {
		t.Fatalf("ensure schema: %v", err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID := newID("testkey")
	if _, err := db.ExecContext(ctx, `insert into event_signing_keys (key_id, tenant_id, alg, public_key_b64, enabled, source) values ($1,$2,'Ed25519',$3,true,'synthetic-test')`, keyID, "tenant_integration_a", base64.StdEncoding.EncodeToString(pub)); err != nil {
		t.Fatalf("insert synthetic signing key: %v", err)
	}

	payload := json.RawMessage(`{"event_id":"evt_postgres_summary","result":"failed","policy_decision":{"decision":"degraded"},"file_name":"synthetic-secret.txt","path":"/tmp/synthetic-secret.txt","reason":"synthetic private detail"}`)
	env := signedEventEnvelope{
		EnvelopeVersion: "zt-event-envelope-v1", Alg: "Ed25519", KeyID: keyID,
		CreatedAt: time.Now().UTC().Format(time.RFC3339), Endpoint: "/v1/events/verify",
		PayloadSHA256: sha256Hex(payload), Payload: payload,
	}
	signingBytes, err := envelopeSigningBytes(env)
	if err != nil {
		t.Fatal(err)
	}
	env.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, signingBytes))
	eventBody, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}

	srv := &server{
		dataDir: t.TempDir(), db: db, eventKeyRegistryEnabled: true,
		sso: &controlPlaneSSOConfig{
			Enabled: true, Issuer: "https://integration-issuer.example", Audience: "zt-cp-integration",
			RoleClaim: "role", TenantClaim: "tenant_id", SubjectClaim: "sub",
			AdminRoles: map[string]struct{}{dashboardRoleAdmin: {}}, HS256Secret: []byte("ephemeral-synthetic-jwt-secret"),
		},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/events/verify", srv.handleEventIngest("verify"))
	mux.HandleFunc("/v1/verification-events/", srv.handleVerificationEventSummary)

	ingestReq := httptest.NewRequest(http.MethodPost, "/v1/events/verify", strings.NewReader(string(eventBody)))
	ingestResp := httptest.NewRecorder()
	mux.ServeHTTP(ingestResp, ingestReq)
	if ingestResp.Code != http.StatusAccepted {
		t.Fatalf("signed ingest status=%d body=%s", ingestResp.Code, ingestResp.Body.String())
	}
	var accepted struct {
		IngestID string `json:"ingest_id"`
	}
	if err := json.Unmarshal(ingestResp.Body.Bytes(), &accepted); err != nil || accepted.IngestID == "" {
		t.Fatalf("invalid ingest response: id=%q err=%v body=%s", accepted.IngestID, err, ingestResp.Body.String())
	}

	read := func(tenant, role string) *httptest.ResponseRecorder {
		t.Helper()
		token := mustDashboardSSOToken(t, srv.sso.HS256Secret, map[string]any{
			"iss": srv.sso.Issuer, "aud": srv.sso.Audience, "exp": time.Now().Add(time.Hour).Unix(),
			"sub": "integration-user", "tenant_id": tenant, "role": role,
		})
		req := httptest.NewRequest(http.MethodGet, "/v1/verification-events/"+accepted.IngestID+"/summary", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp := httptest.NewRecorder()
		mux.ServeHTTP(resp, req)
		return resp
	}

	good := read("tenant_integration_a", dashboardRoleViewer)
	if good.Code != http.StatusOK {
		t.Fatalf("same-tenant summary status=%d body=%s", good.Code, good.Body.String())
	}
	var summary map[string]any
	if err := json.Unmarshal(good.Body.Bytes(), &summary); err != nil {
		t.Fatalf("decode summary: %v", err)
	}
	if len(summary) != 8 || summary["ingest_id"] != accepted.IngestID || summary["tenant_id"] != "tenant_integration_a" || summary["reported_result"] != "failed" || summary["reported_policy_decision"] != "degraded" || summary["event_signature_verified"] != true {
		t.Fatalf("unexpected summary: %#v", summary)
	}
	for _, secret := range []string{"synthetic-secret.txt", "/tmp/synthetic-secret.txt", "synthetic private detail"} {
		if strings.Contains(good.Body.String(), secret) {
			t.Fatalf("sensitive payload value %q escaped: %s", secret, good.Body.String())
		}
	}

	for _, role := range []string{dashboardRoleViewer, dashboardRoleAdmin} {
		crossTenant := read("tenant_integration_b", role)
		if crossTenant.Code != http.StatusNotFound || strings.TrimSpace(crossTenant.Body.String()) != "{\n  \"error\": \"not_found\"\n}" {
			t.Fatalf("cross-tenant %s status/body=%d/%s", role, crossTenant.Code, crossTenant.Body.String())
		}
	}
}
