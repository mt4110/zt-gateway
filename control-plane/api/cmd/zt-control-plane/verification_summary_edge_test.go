package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

func testSummaryEdgeConfig() *verificationSummaryEdgeConfig {
	return &verificationSummaryEdgeConfig{transportSecret: base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("t", 32))), authorityKey: []byte(strings.Repeat("k", 32))}
}

func TestVerificationSummaryEdgeOrigin(t *testing.T) {
	srv, mock, cleanup := newDashboardContractServerWithSSO(t)
	defer cleanup()
	srv.summaryEdge = testSummaryEdgeConfig()
	handler := srv.verificationSummaryEdgeHandler()
	for _, path := range []string{"/v1/dashboard/drilldown", "/healthz", "/v1/events/verify", "/v1/admin/event-keys"} {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, httptest.NewRequest("GET", path, nil))
		if rr.Code != 404 {
			t.Fatalf("unexpected public route: %s %d", path, rr.Code)
		}
	}
	for _, secret := range []string{"", "client-forged"} {
		r := verificationSummaryRequest(t, "ing-a", map[string]any{"sub": "user-a", "tenant_id": "tenant-a"})
		r.Header.Set("X-ZT-Edge-Secret", secret)
		r.Header.Set("X-ZT-Read-Nonce", strings.Repeat("a", 32))
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, r)
		if rr.Code != 401 || rr.Header().Get("X-ZT-Read-Authority") != "" {
			t.Fatalf("direct access returned %d", rr.Code)
		}
	}
	mock.ExpectQuery(`(?s)select ingest_id, envelope_tenant_id, kind, received_at`).WithArgs("ing-a", "tenant-a").
		WillReturnRows(sqlmock.NewRows([]string{"id", "tenant", "kind", "time", "result", "decision", "present", "verified"}).AddRow("ing-a", "tenant-a", "verify", time.Now(), "failed", "deny", true, true))
	r := verificationSummaryRequest(t, "ing-a", map[string]any{"sub": "user-a", "tenant_id": "tenant-a"})
	r.Header.Set("X-ZT-Edge-Secret", srv.summaryEdge.transportSecret)
	r.Header.Set("X-ZT-Read-Nonce", strings.Repeat("a", 32))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, r)
	if rr.Code != 200 {
		t.Fatalf("edge access returned %d", rr.Code)
	}
	parts := strings.Split(rr.Header().Get("X-ZT-Read-Authority"), ".")
	if len(parts) != 2 {
		t.Fatal("missing authority proof")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, srv.summaryEdge.authorityKey)
	_, _ = mac.Write([]byte(summaryAuthorityDomain + parts[0]))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		t.Fatal("invalid proof MAC")
	}
	bytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var p summaryAuthorityProof
	if err := json.Unmarshal(bytes, &p); err != nil {
		t.Fatal(err)
	}
	if p.Context.Tenant != "tenant-a" || len(p.Context.RecordIDs) != 1 || p.Context.RecordIDs[0] != "ing-a" || p.Nonce != r.Header.Get("X-ZT-Read-Nonce") || p.Path != r.URL.Path || p.Context.Permission != summaryReadPermission || len(p.Context.Principal) != 64 {
		t.Fatalf("invalid authority: %#v", p)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestVerificationSummaryEdgeConfig(t *testing.T) {
	cfg := testSummaryEdgeConfig()
	for _, tc := range []struct {
		mode, transport, key string
		allowed              bool
	}{
		{allowed: true},
		{mode: "1"},
		{transport: cfg.transportSecret},
		{mode: "1", transport: cfg.transportSecret, key: cfg.transportSecret},
		{mode: "1", transport: cfg.transportSecret, key: base64.RawURLEncoding.EncodeToString(cfg.authorityKey), allowed: true},
	} {
		t.Setenv("ZT_CP_SUMMARY_EDGE_ONLY", tc.mode)
		t.Setenv("ZT_CP_SUMMARY_EDGE_SECRET", tc.transport)
		t.Setenv("ZT_CP_SUMMARY_AUTHORITY_KEY", tc.key)
		_, err := loadVerificationSummaryEdgeConfig()
		if (err == nil) != tc.allowed {
			t.Fatalf("unexpected configuration result: %v", err)
		}
	}
}
