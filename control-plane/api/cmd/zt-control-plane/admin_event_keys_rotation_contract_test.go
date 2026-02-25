package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"net/http"
	"regexp"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

func TestAdminEventKeysRotationStatusContract(t *testing.T) {
	t.Parallel()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	t.Run("replacement_key_id_required", func(t *testing.T) {
		t.Parallel()
		srv, mock, cleanup := newAdminEventKeysContractServer(t)
		defer cleanup()

		rr := performAdminEventKeysRequestContract(t, srv, http.MethodGet, "/v1/admin/event-keys/old/rotation-status", "", "")
		assertStatusAndErrorContract(t, rr, http.StatusBadRequest, "replacement_key_id_required")
		assertNoDBLeakContract(t, mock)
	})

	t.Run("method_not_allowed", func(t *testing.T) {
		t.Parallel()
		srv, mock, cleanup := newAdminEventKeysContractServer(t)
		defer cleanup()

		rr := performAdminEventKeysRequestContract(t, srv, http.MethodDelete, "/v1/admin/event-keys/old/rotation-status?replacement_key_id=new", "", "")
		assertStatusAndErrorContract(t, rr, http.StatusMethodNotAllowed, "method_not_allowed")
		assertNoDBLeakContract(t, mock)
	})

	t.Run("old_key_not_found", func(t *testing.T) {
		t.Parallel()
		srv, mock, cleanup := newAdminEventKeysContractServer(t)
		defer cleanup()

		expectEventKeyStateQueryContract(mock, "old").WillReturnError(sql.ErrNoRows)
		rr := performAdminEventKeysRequestContract(t, srv, http.MethodGet, "/v1/admin/event-keys/old/rotation-status?replacement_key_id=new", "", "")
		assertStatusAndErrorContract(t, rr, http.StatusNotFound, "event_key_not_found")
		assertNoDBLeakContract(t, mock)
	})

	t.Run("status_success", func(t *testing.T) {
		t.Parallel()
		srv, mock, cleanup := newAdminEventKeysContractServer(t)
		defer cleanup()

		now := time.Now().UTC()
		expectEventKeyStateRowContract(mock, "old", "tenant-a", pubB64, true, now.Add(-10*24*time.Hour), now.Add(-2*time.Hour))
		expectEventKeyStateRowContract(mock, "new", "tenant-a", pubB64, true, now.Add(-10*24*time.Hour), now.Add(-2*time.Hour))
		expectFirstSeenQueryContract(mock, "new", now.Add(-80*time.Hour))
		expectLastSeenQueryContract(mock, "old", now.Add(-26*time.Hour))

		rr := performAdminEventKeysRequestContract(t, srv, http.MethodGet, "/v1/admin/event-keys/old/rotation-status?replacement_key_id=new", "", "")
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body=%s", rr.Code, rr.Body.String())
		}
		resp := decodeJSONContract(t, rr)
		if got := resp["old_key_id"].(string); got != "old" {
			t.Fatalf("old_key_id = %q, want old", got)
		}
		if got := resp["replacement_key_id"].(string); got != "new" {
			t.Fatalf("replacement_key_id = %q, want new", got)
		}
		policy := resp["policy"].(map[string]any)
		if got := int(policy["coexistence_min_hours"].(float64)); got != 72 {
			t.Fatalf("coexistence_min_hours = %d, want 72", got)
		}
		checks := resp["checks"].(map[string]any)
		if got := checks["ready_disable"].(bool); !got {
			t.Fatalf("ready_disable = false, want true")
		}
		if got := checks["ready_delete"].(bool); got {
			t.Fatalf("ready_delete = true, want false")
		}
		assertNoDBLeakContract(t, mock)
	})
}

func TestAdminEventKeysRotationDeleteGuardsContract(t *testing.T) {
	t.Parallel()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	now := time.Now().UTC()

	makeRequest := func(t *testing.T, mock sqlmock.Sqlmock, oldEnabled, newEnabled bool, newFirstSeen, oldLastSeen, oldUpdatedAt time.Time, mode string) *httptestResponse {
		t.Helper()
		expectEventKeyStateRowContract(mock, "old", "tenant-a", pubB64, oldEnabled, now.Add(-20*24*time.Hour), oldUpdatedAt)
		expectEventKeyStateRowContract(mock, "new", "tenant-a", pubB64, newEnabled, now.Add(-20*24*time.Hour), now.Add(-2*time.Hour))
		expectFirstSeenQueryContract(mock, "new", newFirstSeen)
		expectLastSeenQueryContract(mock, "old", oldLastSeen)
		return &httptestResponse{target: "/v1/admin/event-keys/old?mode=" + mode + "&replacement_key_id=new"}
	}

	t.Run("replacement_not_enabled", func(t *testing.T) {
		t.Parallel()
		srv, mock, cleanup := newAdminEventKeysContractServer(t)
		defer cleanup()

		req := makeRequest(t, mock, true, false, now.Add(-80*time.Hour), now.Add(-26*time.Hour), now.Add(-2*time.Hour), "disable")
		rr := performAdminEventKeysRequestContract(t, srv, http.MethodDelete, req.target, "", "")
		assertStatusAndErrorContract(t, rr, http.StatusConflict, "rotation_replacement_key_not_enabled")
		assertNoDBLeakContract(t, mock)
	})

	t.Run("coexistence_not_elapsed", func(t *testing.T) {
		t.Parallel()
		srv, mock, cleanup := newAdminEventKeysContractServer(t)
		defer cleanup()

		req := makeRequest(t, mock, true, true, now.Add(-2*time.Hour), now.Add(-26*time.Hour), now.Add(-2*time.Hour), "disable")
		rr := performAdminEventKeysRequestContract(t, srv, http.MethodDelete, req.target, "", "")
		assertStatusAndErrorContract(t, rr, http.StatusConflict, "rotation_coexistence_period_not_elapsed")
		assertNoDBLeakContract(t, mock)
	})

	t.Run("switch_not_complete", func(t *testing.T) {
		t.Parallel()
		srv, mock, cleanup := newAdminEventKeysContractServer(t)
		defer cleanup()

		req := makeRequest(t, mock, true, true, now.Add(-80*time.Hour), now.Add(-1*time.Hour), now.Add(-2*time.Hour), "disable")
		rr := performAdminEventKeysRequestContract(t, srv, http.MethodDelete, req.target, "", "")
		assertStatusAndErrorContract(t, rr, http.StatusConflict, "rotation_switch_not_complete")
		assertNoDBLeakContract(t, mock)
	})

	t.Run("delete_requires_disabled", func(t *testing.T) {
		t.Parallel()
		srv, mock, cleanup := newAdminEventKeysContractServer(t)
		defer cleanup()

		req := makeRequest(t, mock, true, true, now.Add(-80*time.Hour), now.Add(-26*time.Hour), now.Add(-2*time.Hour), "delete")
		rr := performAdminEventKeysRequestContract(t, srv, http.MethodDelete, req.target, "", "")
		assertStatusAndErrorContract(t, rr, http.StatusConflict, "event_key_delete_requires_disabled")
		assertNoDBLeakContract(t, mock)
	})

	t.Run("delete_hold_not_elapsed", func(t *testing.T) {
		t.Parallel()
		srv, mock, cleanup := newAdminEventKeysContractServer(t)
		defer cleanup()

		req := makeRequest(t, mock, false, true, now.Add(-80*time.Hour), now.Add(-26*time.Hour), now.Add(-2*time.Hour), "delete")
		rr := performAdminEventKeysRequestContract(t, srv, http.MethodDelete, req.target, "", "")
		assertStatusAndErrorContract(t, rr, http.StatusConflict, "event_key_delete_hold_not_elapsed")
		assertNoDBLeakContract(t, mock)
	})
}

type httptestResponse struct {
	target string
}

func expectEventKeyStateQueryContract(mock sqlmock.Sqlmock, keyID string) *sqlmock.ExpectedQuery {
	return mock.ExpectQuery(regexp.QuoteMeta(`
select key_id, coalesce(tenant_id,''), coalesce(alg,''), public_key_b64, enabled, coalesce(source,''), created_at, updated_at, coalesce(updated_by,''), coalesce(update_reason,'')
from event_signing_keys
where key_id = $1
`)).WithArgs(keyID)
}

func expectEventKeyStateRowContract(mock sqlmock.Sqlmock, keyID, tenantID, publicKeyB64 string, enabled bool, createdAt, updatedAt time.Time) {
	expectEventKeyStateQueryContract(mock, keyID).WillReturnRows(sqlmock.NewRows([]string{
		"key_id", "tenant_id", "alg", "public_key_b64", "enabled", "source", "created_at", "updated_at", "updated_by", "update_reason",
	}).AddRow(keyID, tenantID, "Ed25519", publicKeyB64, enabled, "admin.api", createdAt, updatedAt, "ops", "rotation"))
}

func expectFirstSeenQueryContract(mock sqlmock.Sqlmock, keyID string, at time.Time) {
	mock.ExpectQuery(regexp.QuoteMeta(`
select min(received_at)
from event_ingest
where envelope_verified = true
  and envelope_key_id = $1
`)).WithArgs(keyID).WillReturnRows(sqlmock.NewRows([]string{"min"}).AddRow(at))
}

func expectLastSeenQueryContract(mock sqlmock.Sqlmock, keyID string, at time.Time) {
	mock.ExpectQuery(regexp.QuoteMeta(`
select max(received_at)
from event_ingest
where envelope_verified = true
  and envelope_key_id = $1
`)).WithArgs(keyID).WillReturnRows(sqlmock.NewRows([]string{"max"}).AddRow(at))
}
