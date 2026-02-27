package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	jwt "github.com/golang-jwt/jwt/v5"
)

func TestDashboardActivityAuthzContract(t *testing.T) {
	t.Parallel()

	t.Run("tenant_scope_required_when_authenticated", func(t *testing.T) {
		t.Parallel()
		srv, mock, cleanup := newDashboardContractServer(t, "secret")
		defer cleanup()

		req := httptest.NewRequest(http.MethodGet, "/v1/dashboard/activity", nil)
		req.Header.Set("X-API-Key", "secret")
		rr := httptest.NewRecorder()
		srv.handleDashboardActivity(rr, req)
		assertDashboardStatusAndError(t, rr, http.StatusForbidden, "tenant_scope_required")
		assertDashboardNoDBLeak(t, mock)
	})

	t.Run("tenant_scope_violation", func(t *testing.T) {
		t.Parallel()
		srv, mock, cleanup := newDashboardContractServer(t, "secret")
		defer cleanup()

		req := httptest.NewRequest(http.MethodGet, "/v1/dashboard/activity?tenant_id=tenant-b", nil)
		req.Header.Set("X-API-Key", "secret")
		req.Header.Set("X-ZT-Tenant-ID", "tenant-a")
		rr := httptest.NewRecorder()
		srv.handleDashboardActivity(rr, req)
		assertDashboardStatusAndError(t, rr, http.StatusForbidden, "tenant_scope_violation")
		assertDashboardNoDBLeak(t, mock)
	})

	t.Run("sso_missing_tenant_claim_requires_scope", func(t *testing.T) {
		t.Parallel()
		srv, mock, cleanup := newDashboardContractServerWithSSO(t)
		defer cleanup()

		req := httptest.NewRequest(http.MethodGet, "/v1/dashboard/activity", nil)
		req.Header.Set("Authorization", "Bearer "+mustDashboardSSOToken(t, []byte("sso-secret"), map[string]any{
			"iss":  "https://issuer.example",
			"aud":  "zt-cp",
			"sub":  "user-1",
			"role": dashboardRoleOperator,
			"exp":  time.Now().Add(1 * time.Hour).Unix(),
		}))
		rr := httptest.NewRecorder()
		srv.handleDashboardActivity(rr, req)
		assertDashboardStatusAndError(t, rr, http.StatusForbidden, "tenant_scope_required")
		assertDashboardNoDBLeak(t, mock)
	})

	t.Run("sso_tenant_scope_violation", func(t *testing.T) {
		t.Parallel()
		srv, mock, cleanup := newDashboardContractServerWithSSO(t)
		defer cleanup()

		req := httptest.NewRequest(http.MethodGet, "/v1/dashboard/activity?tenant_id=tenant-b", nil)
		req.Header.Set("Authorization", "Bearer "+mustDashboardSSOToken(t, []byte("sso-secret"), map[string]any{
			"iss":       "https://issuer.example",
			"aud":       "zt-cp",
			"sub":       "user-1",
			"role":      dashboardRoleAuditor,
			"tenant_id": "tenant-a",
			"exp":       time.Now().Add(1 * time.Hour).Unix(),
		}))
		rr := httptest.NewRecorder()
		srv.handleDashboardActivity(rr, req)
		assertDashboardStatusAndError(t, rr, http.StatusForbidden, "tenant_scope_violation")
		assertDashboardNoDBLeak(t, mock)
	})
}

func TestDashboardActivityCSVExportContract(t *testing.T) {
	t.Parallel()

	srv, mock, cleanup := newDashboardContractServer(t, "secret")
	defer cleanup()

	mock.ExpectQuery(regexp.QuoteMeta("select count(*)::bigint\nfrom event_ingest\nwhere envelope_tenant_id = $1\n")).
		WithArgs("tenant-a").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	mock.ExpectQuery(`(?s)select ingest_id, kind, coalesce\(event_id,''\), coalesce\(envelope_tenant_id,''\), coalesce\(envelope_key_id,''\), envelope_present, envelope_verified, received_at`).
		WithArgs("tenant-a").
		WillReturnRows(sqlmock.NewRows([]string{
			"ingest_id", "kind", "event_id", "envelope_tenant_id", "envelope_key_id", "envelope_present", "envelope_verified", "received_at",
		}).AddRow("ing-1", "verify", "evt-1", "tenant-a", "key-1", true, true, time.Date(2026, time.February, 27, 1, 0, 0, 0, time.UTC)))

	mock.ExpectQuery(`(?s)select kind, count\(\*\)::bigint\s+from event_ingest`).
		WithArgs("tenant-a").
		WillReturnRows(sqlmock.NewRows([]string{"kind", "count"}).AddRow("verify", 1))

	req := httptest.NewRequest(http.MethodGet, "/v1/dashboard/activity?export=csv", nil)
	req.Header.Set("X-API-Key", "secret")
	req.Header.Set("X-ZT-Tenant-ID", "tenant-a")
	rr := httptest.NewRecorder()
	srv.handleDashboardActivity(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Fatalf("content-type = %q, want text/csv", ct)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "\"ingest_id\"") {
		t.Fatalf("csv header missing ingest_id: %s", body)
	}
	if !strings.Contains(body, "\"ing-1\"") {
		t.Fatalf("csv row missing ingest id: %s", body)
	}
	assertDashboardNoDBLeak(t, mock)
}

func TestDashboardActivityCSVExportContract_DropsCrossTenantRowsAtScale(t *testing.T) {
	t.Parallel()

	srv, mock, cleanup := newDashboardContractServer(t, "secret")
	defer cleanup()

	mock.ExpectQuery(regexp.QuoteMeta("select count(*)::bigint\nfrom event_ingest\nwhere envelope_tenant_id = $1\n")).
		WithArgs("tenant-a").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1005))

	rows := sqlmock.NewRows([]string{
		"ingest_id", "kind", "event_id", "envelope_tenant_id", "envelope_key_id", "envelope_present", "envelope_verified", "received_at",
	})
	baseTime := time.Date(2026, time.February, 27, 2, 0, 0, 0, time.UTC)
	for i := 0; i < 1000; i++ {
		rows.AddRow(
			fmt.Sprintf("ing-a-%04d", i),
			"verify",
			fmt.Sprintf("evt-a-%04d", i),
			"tenant-a",
			"key-a",
			true,
			true,
			baseTime.Add(time.Duration(i)*time.Second),
		)
	}
	for i := 0; i < 5; i++ {
		rows.AddRow(
			fmt.Sprintf("ing-b-%04d", i),
			"verify",
			fmt.Sprintf("evt-b-%04d", i),
			"tenant-b",
			"key-b",
			true,
			true,
			baseTime.Add(time.Duration(2000+i)*time.Second),
		)
	}
	mock.ExpectQuery(`(?s)select ingest_id, kind, coalesce\(event_id,''\), coalesce\(envelope_tenant_id,''\), coalesce\(envelope_key_id,''\), envelope_present, envelope_verified, received_at`).
		WithArgs("tenant-a").
		WillReturnRows(rows)

	mock.ExpectQuery(`(?s)select kind, count\(\*\)::bigint\s+from event_ingest`).
		WithArgs("tenant-a").
		WillReturnRows(sqlmock.NewRows([]string{"kind", "count"}).AddRow("verify", 1005))

	req := httptest.NewRequest(http.MethodGet, "/v1/dashboard/activity?export=csv", nil)
	req.Header.Set("X-API-Key", "secret")
	req.Header.Set("X-ZT-Tenant-ID", "tenant-a")
	rr := httptest.NewRecorder()
	srv.handleDashboardActivity(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rr.Code, rr.Body.String())
	}
	lines := strings.Split(strings.TrimSpace(rr.Body.String()), "\n")
	if len(lines) != 1001 { // header + 1000 tenant-a rows
		t.Fatalf("csv lines=%d, want 1001", len(lines))
	}
	for _, line := range lines {
		if strings.Contains(line, `"tenant-b"`) {
			t.Fatalf("cross-tenant leak detected in csv output")
		}
	}
	assertDashboardNoDBLeak(t, mock)
}

func TestDashboardTimeseriesAndDrilldownInputContract(t *testing.T) {
	t.Parallel()

	t.Run("timeseries_invalid_bucket", func(t *testing.T) {
		t.Parallel()
		srv, mock, cleanup := newDashboardContractServer(t, "")
		defer cleanup()

		req := httptest.NewRequest(http.MethodGet, "/v1/dashboard/timeseries?bucket_minutes=0", nil)
		rr := httptest.NewRecorder()
		srv.handleDashboardTimeseries(rr, req)
		assertDashboardStatusAndError(t, rr, http.StatusBadRequest, "invalid_bucket_minutes")
		assertDashboardNoDBLeak(t, mock)
	})

	t.Run("drilldown_event_id_required", func(t *testing.T) {
		t.Parallel()
		srv, mock, cleanup := newDashboardContractServer(t, "")
		defer cleanup()

		req := httptest.NewRequest(http.MethodGet, "/v1/dashboard/drilldown", nil)
		rr := httptest.NewRecorder()
		srv.handleDashboardDrilldown(rr, req)
		assertDashboardStatusAndError(t, rr, http.StatusBadRequest, "event_id_required")
		assertDashboardNoDBLeak(t, mock)
	})
}

func newDashboardContractServer(t *testing.T, apiKey string) (*server, sqlmock.Sqlmock, func()) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	srv := &server{db: db, apiKey: strings.TrimSpace(apiKey)}
	cleanup := func() {
		_ = db.Close()
	}
	return srv, mock, cleanup
}

func newDashboardContractServerWithSSO(t *testing.T) (*server, sqlmock.Sqlmock, func()) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	srv := &server{
		db: db,
		sso: &controlPlaneSSOConfig{
			Enabled:      true,
			Issuer:       "https://issuer.example",
			Audience:     "zt-cp",
			RoleClaim:    "role",
			TenantClaim:  "tenant_id",
			SubjectClaim: "sub",
			AdminRoles: map[string]struct{}{
				dashboardRoleAdmin: {},
			},
			HS256Secret: []byte("sso-secret"),
		},
	}
	cleanup := func() {
		_ = db.Close()
	}
	return srv, mock, cleanup
}

func mustDashboardSSOToken(t *testing.T, secret []byte, claims map[string]any) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
	raw, err := token.SignedString(secret)
	if err != nil {
		t.Fatalf("SignedString failed: %v", err)
	}
	return raw
}

func assertDashboardNoDBLeak(t *testing.T, mock sqlmock.Sqlmock) {
	t.Helper()
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("sql expectations: %v", err)
	}
}

func assertDashboardStatusAndError(t *testing.T, rr *httptest.ResponseRecorder, wantStatus int, wantError string) {
	t.Helper()
	if rr.Code != wantStatus {
		t.Fatalf("status = %d, want %d (body=%s)", rr.Code, wantStatus, rr.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json decode failed: %v, body=%s", err, rr.Body.String())
	}
	gotError, _ := resp["error"].(string)
	if strings.TrimSpace(gotError) != strings.TrimSpace(wantError) {
		t.Fatalf("error = %q, want %q", gotError, wantError)
	}
}
