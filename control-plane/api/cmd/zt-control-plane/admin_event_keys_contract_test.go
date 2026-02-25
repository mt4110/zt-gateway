package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

func TestAdminEventKeysRouteGuardsContract(t *testing.T) {
	t.Parallel()

	t.Run("missing_api_key", func(t *testing.T) {
		t.Parallel()
		srv := &server{apiKey: "secret", db: &sql.DB{}}
		rr := performAdminEventKeysRequestContract(t, srv, http.MethodGet, "/v1/admin/event-keys", "", "")
		assertStatusAndErrorContract(t, rr, http.StatusUnauthorized, "missing_api_key")
	})

	t.Run("invalid_api_key", func(t *testing.T) {
		t.Parallel()
		srv := &server{apiKey: "secret", db: &sql.DB{}}
		rr := performAdminEventKeysRequestContract(t, srv, http.MethodGet, "/v1/admin/event-keys", "", "bad")
		assertStatusAndErrorContract(t, rr, http.StatusUnauthorized, "invalid_api_key")
	})

	t.Run("postgres_not_configured", func(t *testing.T) {
		t.Parallel()
		srv := &server{}
		rr := performAdminEventKeysRequestContract(t, srv, http.MethodGet, "/v1/admin/event-keys", "", "")
		assertStatusAndErrorContract(t, rr, http.StatusServiceUnavailable, "postgres_not_configured")
	})

	t.Run("post_does_not_accept_path_key_id", func(t *testing.T) {
		t.Parallel()
		srv, mock, cleanup := newAdminEventKeysContractServer(t)
		defer cleanup()

		body := `{"key_id":"k1","public_key_b64":"abc"}`
		rr := performAdminEventKeysRequestContract(t, srv, http.MethodPost, "/v1/admin/event-keys/k1", body, "")
		assertStatusAndErrorContract(t, rr, http.StatusBadRequest, "post_does_not_accept_path_key_id")
		assertNoDBLeakContract(t, mock)
	})

	t.Run("history_method_not_allowed", func(t *testing.T) {
		t.Parallel()
		srv, mock, cleanup := newAdminEventKeysContractServer(t)
		defer cleanup()

		rr := performAdminEventKeysRequestContract(t, srv, http.MethodDelete, "/v1/admin/event-keys/k1/history", "", "")
		assertStatusAndErrorContract(t, rr, http.StatusMethodNotAllowed, "method_not_allowed")
		assertNoDBLeakContract(t, mock)
	})

	t.Run("unknown_nested_path_not_found", func(t *testing.T) {
		t.Parallel()
		srv, mock, cleanup := newAdminEventKeysContractServer(t)
		defer cleanup()

		rr := performAdminEventKeysRequestContract(t, srv, http.MethodGet, "/v1/admin/event-keys/k1/other", "", "")
		assertStatusAndErrorContract(t, rr, http.StatusNotFound, "not_found")
		assertNoDBLeakContract(t, mock)
	})

	t.Run("patch_without_key_id_requires_path_key", func(t *testing.T) {
		t.Parallel()
		srv, mock, cleanup := newAdminEventKeysContractServer(t)
		defer cleanup()

		rr := performAdminEventKeysRequestContract(t, srv, http.MethodPatch, "/v1/admin/event-keys", `{"enabled":false}`, "")
		assertStatusAndErrorContract(t, rr, http.StatusBadRequest, "key_id_required")
		assertNoDBLeakContract(t, mock)
	})

	t.Run("delete_without_key_id_requires_path_key", func(t *testing.T) {
		t.Parallel()
		srv, mock, cleanup := newAdminEventKeysContractServer(t)
		defer cleanup()

		rr := performAdminEventKeysRequestContract(t, srv, http.MethodDelete, "/v1/admin/event-keys", "", "")
		assertStatusAndErrorContract(t, rr, http.StatusBadRequest, "key_id_required")
		assertNoDBLeakContract(t, mock)
	})
}

func TestAdminEventKeysCRUDContract(t *testing.T) {
	t.Parallel()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	createdAt := time.Date(2026, time.February, 25, 10, 0, 0, 0, time.UTC)
	updatedAt := time.Date(2026, time.February, 25, 11, 0, 0, 0, time.UTC)

	t.Run("get_list_success", func(t *testing.T) {
		t.Parallel()
		srv, mock, cleanup := newAdminEventKeysContractServer(t)
		defer cleanup()

		rows := sqlmock.NewRows([]string{
			"key_id", "tenant_id", "alg", "public_key_b64", "enabled", "source", "created_at", "updated_at", "updated_by", "update_reason",
		}).AddRow("k1", "tenant-a", "Ed25519", pubB64, true, "admin.api", createdAt, updatedAt, "ops", "initial")
		mock.ExpectQuery(`(?s)from event_signing_keys\s+where \(\$1 = '' or tenant_id = \$1\)`).
			WithArgs("tenant-a").
			WillReturnRows(rows)

		rr := performAdminEventKeysRequestContract(t, srv, http.MethodGet, "/v1/admin/event-keys?tenant_id=tenant-a", "", "")
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body=%s", rr.Code, rr.Body.String())
		}
		resp := decodeJSONContract(t, rr)
		if got := int(resp["count"].(float64)); got != 1 {
			t.Fatalf("count = %d, want 1", got)
		}
		if got := resp["tenant_id"].(string); got != "tenant-a" {
			t.Fatalf("tenant_id = %q, want tenant-a", got)
		}
		items := resp["items"].([]any)
		if len(items) != 1 {
			t.Fatalf("len(items) = %d, want 1", len(items))
		}
		item := items[0].(map[string]any)
		if got := item["key_id"].(string); got != "k1" {
			t.Fatalf("item.key_id = %q, want k1", got)
		}
		assertNoDBLeakContract(t, mock)
	})

	t.Run("get_one_success", func(t *testing.T) {
		t.Parallel()
		srv, mock, cleanup := newAdminEventKeysContractServer(t)
		defer cleanup()

		rows := sqlmock.NewRows([]string{
			"key_id", "tenant_id", "alg", "public_key_b64", "enabled", "source", "created_at", "updated_at", "updated_by", "update_reason",
		}).AddRow("k1", "tenant-a", "Ed25519", pubB64, true, "admin.api", createdAt, updatedAt, "ops", "rotate")
		mock.ExpectQuery(`(?s)from event_signing_keys\s+where key_id = \$1`).
			WithArgs("k1").
			WillReturnRows(rows)

		rr := performAdminEventKeysRequestContract(t, srv, http.MethodGet, "/v1/admin/event-keys/k1", "", "")
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body=%s", rr.Code, rr.Body.String())
		}
		resp := decodeJSONContract(t, rr)
		item := resp["item"].(map[string]any)
		if got := item["source"].(string); got != "admin.api" {
			t.Fatalf("item.source = %q, want admin.api", got)
		}
		if got := item["created_at"].(string); got != createdAt.Format(time.RFC3339) {
			t.Fatalf("item.created_at = %q", got)
		}
		assertNoDBLeakContract(t, mock)
	})

	t.Run("get_one_not_found", func(t *testing.T) {
		t.Parallel()
		srv, mock, cleanup := newAdminEventKeysContractServer(t)
		defer cleanup()

		mock.ExpectQuery(`(?s)from event_signing_keys\s+where key_id = \$1`).
			WithArgs("missing").
			WillReturnError(sql.ErrNoRows)

		rr := performAdminEventKeysRequestContract(t, srv, http.MethodGet, "/v1/admin/event-keys/missing", "", "")
		assertStatusAndErrorContract(t, rr, http.StatusNotFound, "event_key_not_found")
		assertNoDBLeakContract(t, mock)
	})

	t.Run("post_invalid_json", func(t *testing.T) {
		t.Parallel()
		srv, mock, cleanup := newAdminEventKeysContractServer(t)
		defer cleanup()

		rr := performAdminEventKeysRequestContract(t, srv, http.MethodPost, "/v1/admin/event-keys", "{", "")
		assertStatusAndErrorContract(t, rr, http.StatusBadRequest, "invalid_json")
		assertNoDBLeakContract(t, mock)
	})

	t.Run("post_success", func(t *testing.T) {
		t.Parallel()
		srv, mock, cleanup := newAdminEventKeysContractServer(t)
		defer cleanup()

		mock.ExpectExec(`(?s)insert into event_signing_keys`).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectQuery(regexp.QuoteMeta(`
select key_id, coalesce(tenant_id,''), coalesce(alg,''), public_key_b64, enabled, coalesce(updated_by,''), coalesce(update_reason,'')
from event_signing_keys
where key_id = $1
`)).
			WithArgs("k1").
			WillReturnRows(sqlmock.NewRows([]string{
				"key_id", "tenant_id", "alg", "public_key_b64", "enabled", "updated_by", "update_reason",
			}).AddRow("k1", "tenant-a", "Ed25519", pubB64, true, "ops", "create"))
		mock.ExpectExec(`(?s)insert into event_signing_key_audit`).
			WillReturnResult(sqlmock.NewResult(0, 1))

		body := `{"key_id":"k1","tenant_id":"tenant-a","public_key_b64":"` + pubB64 + `","enabled":true,"updated_by":"ops","reason":"create"}`
		rr := performAdminEventKeysRequestContract(t, srv, http.MethodPost, "/v1/admin/event-keys", body, "")
		if rr.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201, body=%s", rr.Code, rr.Body.String())
		}
		resp := decodeJSONContract(t, rr)
		item := resp["item"].(map[string]any)
		if got := item["key_id"].(string); got != "k1" {
			t.Fatalf("item.key_id = %q, want k1", got)
		}
		assertNoDBLeakContract(t, mock)
	})

	t.Run("put_key_id_mismatch", func(t *testing.T) {
		t.Parallel()
		srv, mock, cleanup := newAdminEventKeysContractServer(t)
		defer cleanup()

		body := `{"key_id":"k2","public_key_b64":"` + pubB64 + `"}`
		rr := performAdminEventKeysRequestContract(t, srv, http.MethodPut, "/v1/admin/event-keys/k1", body, "")
		assertStatusAndErrorContract(t, rr, http.StatusBadRequest, "key_id_mismatch")
		assertNoDBLeakContract(t, mock)
	})

	t.Run("put_success", func(t *testing.T) {
		t.Parallel()
		srv, mock, cleanup := newAdminEventKeysContractServer(t)
		defer cleanup()

		mock.ExpectExec(`(?s)insert into event_signing_keys`).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectQuery(regexp.QuoteMeta(`
select key_id, coalesce(tenant_id,''), coalesce(alg,''), public_key_b64, enabled, coalesce(updated_by,''), coalesce(update_reason,'')
from event_signing_keys
where key_id = $1
`)).
			WithArgs("k1").
			WillReturnRows(sqlmock.NewRows([]string{
				"key_id", "tenant_id", "alg", "public_key_b64", "enabled", "updated_by", "update_reason",
			}).AddRow("k1", "tenant-a", "Ed25519", pubB64, true, "ops", "update"))
		mock.ExpectExec(`(?s)insert into event_signing_key_audit`).
			WillReturnResult(sqlmock.NewResult(0, 1))

		body := `{"tenant_id":"tenant-a","public_key_b64":"` + pubB64 + `","enabled":true,"updated_by":"ops","reason":"update"}`
		rr := performAdminEventKeysRequestContract(t, srv, http.MethodPut, "/v1/admin/event-keys/k1", body, "")
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body=%s", rr.Code, rr.Body.String())
		}
		assertNoDBLeakContract(t, mock)
	})

	t.Run("put_base_path_success_with_body_key_id", func(t *testing.T) {
		t.Parallel()
		srv, mock, cleanup := newAdminEventKeysContractServer(t)
		defer cleanup()

		mock.ExpectExec(`(?s)insert into event_signing_keys`).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectQuery(regexp.QuoteMeta(`
select key_id, coalesce(tenant_id,''), coalesce(alg,''), public_key_b64, enabled, coalesce(updated_by,''), coalesce(update_reason,'')
from event_signing_keys
where key_id = $1
`)).
			WithArgs("k-base").
			WillReturnRows(sqlmock.NewRows([]string{
				"key_id", "tenant_id", "alg", "public_key_b64", "enabled", "updated_by", "update_reason",
			}).AddRow("k-base", "tenant-a", "Ed25519", pubB64, true, "ops", "base-put"))
		mock.ExpectExec(`(?s)insert into event_signing_key_audit`).
			WillReturnResult(sqlmock.NewResult(0, 1))

		body := `{"key_id":"k-base","tenant_id":"tenant-a","public_key_b64":"` + pubB64 + `","enabled":true,"updated_by":"ops","reason":"base-put"}`
		rr := performAdminEventKeysRequestContract(t, srv, http.MethodPut, "/v1/admin/event-keys", body, "")
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body=%s", rr.Code, rr.Body.String())
		}
		resp := decodeJSONContract(t, rr)
		item := resp["item"].(map[string]any)
		if got := item["key_id"].(string); got != "k-base" {
			t.Fatalf("item.key_id = %q, want k-base", got)
		}
		assertNoDBLeakContract(t, mock)
	})

	t.Run("patch_requires_enabled", func(t *testing.T) {
		t.Parallel()
		srv, mock, cleanup := newAdminEventKeysContractServer(t)
		defer cleanup()

		rr := performAdminEventKeysRequestContract(t, srv, http.MethodPatch, "/v1/admin/event-keys/k1", `{}`, "")
		assertStatusAndErrorContract(t, rr, http.StatusBadRequest, "patch_requires_enabled")
		assertNoDBLeakContract(t, mock)
	})

	t.Run("patch_not_found", func(t *testing.T) {
		t.Parallel()
		srv, mock, cleanup := newAdminEventKeysContractServer(t)
		defer cleanup()

		mock.ExpectExec(`(?s)update event_signing_keys`).
			WillReturnResult(sqlmock.NewResult(0, 0))
		rr := performAdminEventKeysRequestContract(t, srv, http.MethodPatch, "/v1/admin/event-keys/k1", `{"enabled":false}`, "")
		assertStatusAndErrorContract(t, rr, http.StatusNotFound, "event_key_not_found")
		assertNoDBLeakContract(t, mock)
	})

	t.Run("patch_success", func(t *testing.T) {
		t.Parallel()
		srv, mock, cleanup := newAdminEventKeysContractServer(t)
		defer cleanup()

		mock.ExpectExec(`(?s)update event_signing_keys`).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectQuery(regexp.QuoteMeta(`select count(*)::bigint from event_signing_keys where enabled = true`)).
			WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
		mock.ExpectQuery(regexp.QuoteMeta(`
select key_id, coalesce(tenant_id,''), coalesce(alg,''), public_key_b64, enabled, coalesce(updated_by,''), coalesce(update_reason,'')
from event_signing_keys
where key_id = $1
`)).
			WithArgs("k1").
			WillReturnRows(sqlmock.NewRows([]string{
				"key_id", "tenant_id", "alg", "public_key_b64", "enabled", "updated_by", "update_reason",
			}).AddRow("k1", "tenant-a", "Ed25519", pubB64, false, "ops", "disable"))
		mock.ExpectExec(`(?s)insert into event_signing_key_audit`).
			WillReturnResult(sqlmock.NewResult(0, 1))

		rr := performAdminEventKeysRequestContract(t, srv, http.MethodPatch, "/v1/admin/event-keys/k1", `{"enabled":false,"updated_by":"ops","reason":"disable"}`, "")
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body=%s", rr.Code, rr.Body.String())
		}
		resp := decodeJSONContract(t, rr)
		item := resp["item"].(map[string]any)
		if got := item["enabled"].(bool); got {
			t.Fatalf("item.enabled = true, want false")
		}
		assertNoDBLeakContract(t, mock)
	})

	t.Run("delete_invalid_mode", func(t *testing.T) {
		t.Parallel()
		srv, mock, cleanup := newAdminEventKeysContractServer(t)
		defer cleanup()

		rr := performAdminEventKeysRequestContract(t, srv, http.MethodDelete, "/v1/admin/event-keys/k1?mode=drop", "", "")
		assertStatusAndErrorContract(t, rr, http.StatusBadRequest, "invalid_delete_mode")
		assertNoDBLeakContract(t, mock)
	})

	t.Run("delete_not_found", func(t *testing.T) {
		t.Parallel()
		srv, mock, cleanup := newAdminEventKeysContractServer(t)
		defer cleanup()

		mock.ExpectQuery(regexp.QuoteMeta(`
select key_id, coalesce(tenant_id,''), coalesce(alg,''), public_key_b64, enabled, coalesce(source,''), created_at, updated_at, coalesce(updated_by,''), coalesce(update_reason,'')
from event_signing_keys
where key_id = $1
`)).
			WithArgs("k1").
			WillReturnError(sql.ErrNoRows)
		rr := performAdminEventKeysRequestContract(t, srv, http.MethodDelete, "/v1/admin/event-keys/k1?replacement_key_id=k2", "", "")
		assertStatusAndErrorContract(t, rr, http.StatusNotFound, "event_key_not_found")
		assertNoDBLeakContract(t, mock)
	})

	t.Run("delete_disable_success", func(t *testing.T) {
		t.Parallel()
		srv, mock, cleanup := newAdminEventKeysContractServer(t)
		defer cleanup()

		now := time.Now().UTC()
		replacementFirstSeen := now.Add(-80 * time.Hour)
		oldLastSeen := now.Add(-25 * time.Hour)

		mock.ExpectQuery(regexp.QuoteMeta(`
select key_id, coalesce(tenant_id,''), coalesce(alg,''), public_key_b64, enabled, coalesce(source,''), created_at, updated_at, coalesce(updated_by,''), coalesce(update_reason,'')
from event_signing_keys
where key_id = $1
`)).
			WithArgs("k1").
			WillReturnRows(sqlmock.NewRows([]string{
				"key_id", "tenant_id", "alg", "public_key_b64", "enabled", "source", "created_at", "updated_at", "updated_by", "update_reason",
			}).AddRow("k1", "tenant-a", "Ed25519", pubB64, true, "admin.api", now.Add(-10*24*time.Hour), now.Add(-2*time.Hour), "ops", "disable"))
		mock.ExpectQuery(regexp.QuoteMeta(`
select key_id, coalesce(tenant_id,''), coalesce(alg,''), public_key_b64, enabled, coalesce(source,''), created_at, updated_at, coalesce(updated_by,''), coalesce(update_reason,'')
from event_signing_keys
where key_id = $1
`)).
			WithArgs("k2").
			WillReturnRows(sqlmock.NewRows([]string{
				"key_id", "tenant_id", "alg", "public_key_b64", "enabled", "source", "created_at", "updated_at", "updated_by", "update_reason",
			}).AddRow("k2", "tenant-a", "Ed25519", pubB64, true, "admin.api", now.Add(-10*24*time.Hour), now.Add(-2*time.Hour), "ops", "active"))
		mock.ExpectQuery(regexp.QuoteMeta(`
select min(received_at)
from event_ingest
where envelope_verified = true
  and envelope_key_id = $1
`)).
			WithArgs("k2").
			WillReturnRows(sqlmock.NewRows([]string{"min"}).AddRow(replacementFirstSeen))
		mock.ExpectQuery(regexp.QuoteMeta(`
select max(received_at)
from event_ingest
where envelope_verified = true
  and envelope_key_id = $1
`)).
			WithArgs("k1").
			WillReturnRows(sqlmock.NewRows([]string{"max"}).AddRow(oldLastSeen))

		mock.ExpectExec(`(?s)update event_signing_keys`).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectQuery(regexp.QuoteMeta(`select count(*)::bigint from event_signing_keys where enabled = true`)).
			WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
		mock.ExpectQuery(regexp.QuoteMeta(`
select key_id, coalesce(tenant_id,''), coalesce(alg,''), public_key_b64, enabled, coalesce(updated_by,''), coalesce(update_reason,'')
from event_signing_keys
where key_id = $1
`)).
			WithArgs("k1").
			WillReturnRows(sqlmock.NewRows([]string{
				"key_id", "tenant_id", "alg", "public_key_b64", "enabled", "updated_by", "update_reason",
			}).AddRow("k1", "tenant-a", "Ed25519", pubB64, false, "ops", "disable"))
		mock.ExpectExec(`(?s)insert into event_signing_key_audit`).
			WillReturnResult(sqlmock.NewResult(0, 1))

		rr := performAdminEventKeysRequestContract(t, srv, http.MethodDelete, "/v1/admin/event-keys/k1?mode=disable&replacement_key_id=k2&updated_by=ops&reason=disable", "", "")
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body=%s", rr.Code, rr.Body.String())
		}
		resp := decodeJSONContract(t, rr)
		if got := resp["mode"].(string); got != "disable" {
			t.Fatalf("mode = %q, want disable", got)
		}
		assertNoDBLeakContract(t, mock)
	})

	t.Run("delete_delete_success", func(t *testing.T) {
		t.Parallel()
		srv, mock, cleanup := newAdminEventKeysContractServer(t)
		defer cleanup()

		now := time.Now().UTC()
		replacementFirstSeen := now.Add(-90 * time.Hour)
		oldLastSeen := now.Add(-30 * time.Hour)
		oldDisabledAt := now.Add(-8 * 24 * time.Hour)

		mock.ExpectQuery(regexp.QuoteMeta(`
select key_id, coalesce(tenant_id,''), coalesce(alg,''), public_key_b64, enabled, coalesce(source,''), created_at, updated_at, coalesce(updated_by,''), coalesce(update_reason,'')
from event_signing_keys
where key_id = $1
`)).
			WithArgs("k1").
			WillReturnRows(sqlmock.NewRows([]string{
				"key_id", "tenant_id", "alg", "public_key_b64", "enabled", "source", "created_at", "updated_at", "updated_by", "update_reason",
			}).AddRow("k1", "tenant-a", "Ed25519", pubB64, false, "admin.api.patch", now.Add(-10*24*time.Hour), oldDisabledAt, "ops", "disabled"))
		mock.ExpectQuery(regexp.QuoteMeta(`
select key_id, coalesce(tenant_id,''), coalesce(alg,''), public_key_b64, enabled, coalesce(source,''), created_at, updated_at, coalesce(updated_by,''), coalesce(update_reason,'')
from event_signing_keys
where key_id = $1
`)).
			WithArgs("k2").
			WillReturnRows(sqlmock.NewRows([]string{
				"key_id", "tenant_id", "alg", "public_key_b64", "enabled", "source", "created_at", "updated_at", "updated_by", "update_reason",
			}).AddRow("k2", "tenant-a", "Ed25519", pubB64, true, "admin.api", now.Add(-10*24*time.Hour), now.Add(-2*time.Hour), "ops", "active"))
		mock.ExpectQuery(regexp.QuoteMeta(`
select min(received_at)
from event_ingest
where envelope_verified = true
  and envelope_key_id = $1
`)).
			WithArgs("k2").
			WillReturnRows(sqlmock.NewRows([]string{"min"}).AddRow(replacementFirstSeen))
		mock.ExpectQuery(regexp.QuoteMeta(`
select max(received_at)
from event_ingest
where envelope_verified = true
  and envelope_key_id = $1
`)).
			WithArgs("k1").
			WillReturnRows(sqlmock.NewRows([]string{"max"}).AddRow(oldLastSeen))
		mock.ExpectExec(`(?s)delete from event_signing_keys where key_id = \$1`).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectQuery(regexp.QuoteMeta(`select count(*)::bigint from event_signing_keys where enabled = true`)).
			WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
		mock.ExpectExec(`(?s)insert into event_signing_key_audit`).
			WillReturnResult(sqlmock.NewResult(0, 1))

		rr := performAdminEventKeysRequestContract(t, srv, http.MethodDelete, "/v1/admin/event-keys/k1?mode=delete&replacement_key_id=k2&updated_by=ops&reason=delete", "", "")
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body=%s", rr.Code, rr.Body.String())
		}
		resp := decodeJSONContract(t, rr)
		if got := resp["mode"].(string); got != "delete" {
			t.Fatalf("mode = %q, want delete", got)
		}
		assertNoDBLeakContract(t, mock)
	})
}

func TestAdminEventKeysHistoryContract(t *testing.T) {
	t.Parallel()

	t.Run("invalid_limit", func(t *testing.T) {
		t.Parallel()
		srv, mock, cleanup := newAdminEventKeysContractServer(t)
		defer cleanup()

		rr := performAdminEventKeysRequestContract(t, srv, http.MethodGet, "/v1/admin/event-keys/k1/history?limit=0", "", "")
		assertStatusAndErrorContract(t, rr, http.StatusBadRequest, "invalid_limit")
		assertNoDBLeakContract(t, mock)
	})

	t.Run("invalid_action", func(t *testing.T) {
		t.Parallel()
		srv, mock, cleanup := newAdminEventKeysContractServer(t)
		defer cleanup()

		rr := performAdminEventKeysRequestContract(t, srv, http.MethodGet, "/v1/admin/event-keys/k1/history?action=not_supported", "", "")
		assertStatusAndErrorContract(t, rr, http.StatusBadRequest, "invalid_action")
		assertNoDBLeakContract(t, mock)
	})

	t.Run("invalid_from", func(t *testing.T) {
		t.Parallel()
		srv, mock, cleanup := newAdminEventKeysContractServer(t)
		defer cleanup()

		rr := performAdminEventKeysRequestContract(t, srv, http.MethodGet, "/v1/admin/event-keys/k1/history?from=bad", "", "")
		assertStatusAndErrorContract(t, rr, http.StatusBadRequest, "invalid_from")
		assertNoDBLeakContract(t, mock)
	})

	t.Run("invalid_to", func(t *testing.T) {
		t.Parallel()
		srv, mock, cleanup := newAdminEventKeysContractServer(t)
		defer cleanup()

		rr := performAdminEventKeysRequestContract(t, srv, http.MethodGet, "/v1/admin/event-keys/k1/history?to=bad", "", "")
		assertStatusAndErrorContract(t, rr, http.StatusBadRequest, "invalid_to")
		assertNoDBLeakContract(t, mock)
	})

	t.Run("invalid_time_range", func(t *testing.T) {
		t.Parallel()
		srv, mock, cleanup := newAdminEventKeysContractServer(t)
		defer cleanup()

		rr := performAdminEventKeysRequestContract(t, srv, http.MethodGet, "/v1/admin/event-keys/k1/history?from=2026-02-25T00:00:00Z&to=2026-02-24T00:00:00Z", "", "")
		assertStatusAndErrorContract(t, rr, http.StatusBadRequest, "invalid_time_range")
		assertNoDBLeakContract(t, mock)
	})

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		srv, mock, cleanup := newAdminEventKeysContractServer(t)
		defer cleanup()

		rows := sqlmock.NewRows([]string{
			"audit_id", "key_id", "action", "tenant_id", "enabled", "source", "updated_by", "update_reason", "meta_json", "occurred_at",
		}).AddRow(
			int64(101), "k1", "admin_post", "tenant-a", true, "admin.api", "ops", "create", `{"method":"POST"}`, time.Date(2026, time.February, 25, 10, 0, 0, 0, time.UTC),
		).AddRow(
			int64(102), "k1", "admin_disable", "tenant-a", false, "admin.api.delete", "ops", "disable", `{"mode":"disable"}`, time.Date(2026, time.February, 25, 10, 30, 0, 0, time.UTC),
		)
		mock.ExpectQuery(`(?s)from event_signing_key_audit`).
			WillReturnRows(rows)

		target := "/v1/admin/event-keys/k1/history?limit=2&action=admin_post&action=admin_disable&from=2026-02-25T00:00:00Z&to=2026-02-25T23:59:59Z"
		rr := performAdminEventKeysRequestContract(t, srv, http.MethodGet, target, "", "")
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body=%s", rr.Code, rr.Body.String())
		}
		resp := decodeJSONContract(t, rr)
		if got := resp["key_id"].(string); got != "k1" {
			t.Fatalf("key_id = %q, want k1", got)
		}
		if got := int(resp["count"].(float64)); got != 2 {
			t.Fatalf("count = %d, want 2", got)
		}
		if got := int(resp["limit"].(float64)); got != 2 {
			t.Fatalf("limit = %d, want 2", got)
		}
		actions := resp["actions"].([]any)
		if got := actions[0].(string); got != "admin_post" {
			t.Fatalf("actions[0] = %q, want admin_post", got)
		}
		window := resp["window"].(map[string]any)
		if got := window["mode"].(string); got != "custom" {
			t.Fatalf("window.mode = %q, want custom", got)
		}
		items := resp["items"].([]any)
		if len(items) != 2 {
			t.Fatalf("len(items) = %d, want 2", len(items))
		}
		first := items[0].(map[string]any)
		if got := first["action"].(string); got != "admin_post" {
			t.Fatalf("first.action = %q, want admin_post", got)
		}
		assertNoDBLeakContract(t, mock)
	})
}

func performAdminEventKeysRequestContract(t *testing.T, srv *server, method, target, body, apiKey string) *httptest.ResponseRecorder {
	t.Helper()
	reader := strings.NewReader(body)
	req := httptest.NewRequest(method, target, reader)
	if strings.TrimSpace(apiKey) != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	rr := httptest.NewRecorder()
	srv.handleAdminEventKeys(rr, req)
	return rr
}

func decodeJSONContract(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var got map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("json.Unmarshal: %v, body=%s", err, rr.Body.String())
	}
	return got
}

func assertStatusAndErrorContract(t *testing.T, rr *httptest.ResponseRecorder, wantStatus int, wantError string) {
	t.Helper()
	if rr.Code != wantStatus {
		t.Fatalf("status = %d, want %d, body=%s", rr.Code, wantStatus, rr.Body.String())
	}
	resp := decodeJSONContract(t, rr)
	if got := resp["error"].(string); got != wantError {
		t.Fatalf("error = %q, want %q", got, wantError)
	}
}

func newAdminEventKeysContractServer(t *testing.T) (*server, sqlmock.Sqlmock, func()) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	srv := &server{db: db}
	cleanup := func() {
		_ = db.Close()
	}
	return srv, mock, cleanup
}

func assertNoDBLeakContract(t *testing.T, mock sqlmock.Sqlmock) {
	t.Helper()
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("sqlmock expectations: %v", err)
	}
}
