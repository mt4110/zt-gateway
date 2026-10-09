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
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Cross-repository opt-in fixture. Uses the real signed ingest handler and real
// PostgreSQL, then exposes only the production edge handler on loopback HTTP.
// Private config/readiness artifacts remain local; no response/token is logged.
func TestVerificationSummaryEdgeFixture(t *testing.T) {
	file := os.Getenv("ZT_CP_SUMMARY_EDGE_TEST_CONFIG")
	if file == "" {
		t.Skip("opt-in LeakFence integration fixture")
	}
	var cfg struct{ DSN, TransportSecret, AuthorityKey, JWTSecret, Directory, SyntheticSubject string }
	bytes, err := os.ReadFile(file)
	if err != nil {
		t.Fatal("read fixture config")
	}
	if json.Unmarshal(bytes, &cfg) != nil {
		t.Fatal("invalid fixture config")
	}
	if cfg.SyntheticSubject != "" && (!strings.HasPrefix(cfg.SyntheticSubject, "synthetic-") || !verificationSummaryIDPattern.MatchString(cfg.SyntheticSubject)) {
		t.Fatal("additional fixture subject must be an explicit synthetic identifier")
	}
	u, err := url.Parse(cfg.DSN)
	if err != nil || u.Hostname() != "127.0.0.1" || !strings.HasPrefix(u.Path, "/leakfence_validation_") {
		t.Fatal("fixture requires isolated localhost validation database")
	}
	t.Setenv("ZT_CP_SUMMARY_EDGE_ONLY", "1")
	t.Setenv("ZT_CP_SUMMARY_EDGE_SECRET", cfg.TransportSecret)
	t.Setenv("ZT_CP_SUMMARY_AUTHORITY_KEY", cfg.AuthorityKey)
	edge, err := loadVerificationSummaryEdgeConfig()
	if err != nil {
		t.Fatal("invalid edge config")
	}
	db, err := sql.Open("pgx", cfg.DSN)
	if err != nil {
		t.Fatal("open fixture DB")
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := ensurePostgresSchema(ctx, db); err != nil {
		t.Fatal("create fixture schema")
	}
	srv := &server{dataDir: filepath.Join(cfg.Directory, "origin-data"), db: db, summaryEdge: edge, eventKeyRegistryEnabled: true,
		sso: &controlPlaneSSOConfig{Enabled: true, Issuer: "https://zt-validation.invalid", Audience: "zt-validation", SubjectClaim: "sub", TenantClaim: "tenant_id", RoleClaim: "role", AdminRoles: map[string]struct{}{"admin": {}}, HS256Secret: []byte(cfg.JWTSecret)}}
	if err := os.MkdirAll(filepath.Join(srv.dataDir, "events"), 0700); err != nil {
		t.Fatal("create fixture spool")
	}
	ids := []string{}
	tokens := []string{}
	for _, tenant := range []string{"synthetic-zt-a", "synthetic-zt-b"} {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal("fixture key generation")
		}
		keyID := newID("fixturekey")
		if _, err := db.ExecContext(ctx, `insert into event_signing_keys (key_id,tenant_id,alg,public_key_b64,enabled,source) values ($1,$2,'Ed25519',$3,true,'synthetic-test')`, keyID, tenant, base64.StdEncoding.EncodeToString(pub)); err != nil {
			t.Fatal("insert fixture key")
		}
		payload, _ := json.Marshal(map[string]any{"event_id": newID("fixtureevent"), "result": "failed", "policy_decision": map[string]string{"decision": "degraded"}, "file_name": "SYNTHETIC_PRIVATE_FILENAME", "reason": "SYNTHETIC_PRIVATE_REASON"})
		env := signedEventEnvelope{EnvelopeVersion: "zt-event-envelope-v1", Alg: "Ed25519", KeyID: keyID, CreatedAt: time.Now().UTC().Format(time.RFC3339), Endpoint: "/v1/events/verify", PayloadSHA256: sha256Hex(payload), Payload: payload}
		message, err := envelopeSigningBytes(env)
		if err != nil {
			t.Fatal("fixture envelope")
		}
		env.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, message))
		body, _ := json.Marshal(env)
		rr := httptest.NewRecorder()
		srv.handleEventIngest("verify")(rr, httptest.NewRequest(http.MethodPost, env.Endpoint, strings.NewReader(string(body))))
		var accepted struct {
			IngestID string `json:"ingest_id"`
		}
		if rr.Code != 202 || json.Unmarshal(rr.Body.Bytes(), &accepted) != nil || accepted.IngestID == "" {
			t.Fatal("signed fixture ingest failed")
		}
		ids = append(ids, accepted.IngestID)
		subject := "synthetic-user"
		if tenant == "synthetic-zt-a" && cfg.SyntheticSubject != "" {
			subject = cfg.SyntheticSubject
		}
		tokens = append(tokens, mustDashboardSSOToken(t, srv.sso.HS256Secret, map[string]any{"iss": srv.sso.Issuer, "aud": srv.sso.Audience, "exp": time.Now().Add(10 * time.Minute).Unix(), "sub": subject, "tenant_id": tenant, "role": "admin"}))
	}
	production := srv.verificationSummaryEdgeHandler()
	var savedProof string
	var proofMu sync.Mutex
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rr := httptest.NewRecorder()
		production.ServeHTTP(rr, r)
		// Faults are selected only through a local fixture file, never an HTTP
		// parameter/header. No injection mechanism exists in the production mux.
		faultBytes, _ := os.ReadFile(filepath.Join(cfg.Directory, "fault"))
		fault := strings.TrimSpace(string(faultBytes))
		if rr.Code == 200 {
			proofMu.Lock()
			if savedProof == "" {
				savedProof = rr.Header().Get("X-ZT-Read-Authority")
			}
			if fault == "replay" {
				rr.Header().Set("X-ZT-Read-Authority", savedProof)
			}
			proofMu.Unlock()
			if fault == "missing-proof" {
				rr.Header().Del("X-ZT-Read-Authority")
			}
			if fault == "mac" {
				rr.Header().Set("X-ZT-Read-Authority", "invalid.invalid")
			}
			if fault == "failure" {
				writeVerificationSummaryError(w, 503)
				return
			}
			if fault == "tenant" || fault == "id" || fault == "field" || fault == "nested" {
				var body map[string]any
				if json.Unmarshal(rr.Body.Bytes(), &body) != nil {
					writeVerificationSummaryError(w, 503)
					return
				}
				switch fault {
				case "tenant":
					if body["tenant_id"] == "synthetic-zt-a" {
						body["tenant_id"] = "synthetic-zt-b"
					} else {
						body["tenant_id"] = "synthetic-zt-a"
					}
				case "id":
					if body["ingest_id"] == ids[0] {
						body["ingest_id"] = ids[1]
					} else {
						body["ingest_id"] = ids[0]
					}
				case "field":
					body["secret"] = "SYNTHETIC_PRIVATE_FIELD"
				case "nested":
					body["reported_result"] = map[string]string{"secret": "SYNTHETIC_PRIVATE_FIELD"}
				}
				replacement, _ := json.Marshal(body)
				rr.Body.Reset()
				_, _ = rr.Body.Write(replacement)
			}
		}
		for k, values := range rr.Header() {
			for _, value := range values {
				w.Header().Add(k, value)
			}
		}
		w.WriteHeader(rr.Code)
		_, _ = w.Write(rr.Body.Bytes())
	}))
	defer origin.Close()
	ready, _ := json.Marshal(map[string]any{"origin": origin.URL, "ids": ids, "tokens": tokens})
	if err := os.WriteFile(filepath.Join(cfg.Directory, "ready.json"), ready, 0600); err != nil {
		t.Fatal("write fixture readiness")
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.After(20 * time.Minute)
	for {
		select {
		case <-ticker.C:
			if _, err := os.Stat(filepath.Join(cfg.Directory, "stop")); err == nil {
				return
			}
		case <-deadline:
			t.Fatal("fixture deadline elapsed")
		}
	}
}
