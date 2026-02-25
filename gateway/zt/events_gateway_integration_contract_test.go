package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGatewayEventSigningContract_KeyIDUnsetOmitsEnvelopeField(t *testing.T) {
	t.Setenv("ZT_EVENT_SIGNING_ED25519_PRIV_B64", eventSigningSeedContract())
	t.Setenv("ZT_EVENT_SIGNING_KEY_ID", "")

	signer, err := loadEventEnvelopeSignerFromEnv()
	if err != nil {
		t.Fatalf("loadEventEnvelopeSignerFromEnv: %v", err)
	}
	if signer == nil {
		t.Fatalf("signer is nil")
	}

	wrapped, err := signer.Wrap("/v1/events/scan", []byte(`{"event_id":"evt_contract_keyid_empty"}`))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	var env map[string]any
	if err := json.Unmarshal(wrapped, &env); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if _, ok := env["key_id"]; ok {
		t.Fatalf("envelope.key_id exists in JSON when env key_id is empty: %s", string(wrapped))
	}
}

func TestGatewayEventSigningContract_KeyIDSetIncludesEnvelopeField(t *testing.T) {
	t.Setenv("ZT_EVENT_SIGNING_ED25519_PRIV_B64", eventSigningSeedContract())
	t.Setenv("ZT_EVENT_SIGNING_KEY_ID", "k_contract")

	signer, err := loadEventEnvelopeSignerFromEnv()
	if err != nil {
		t.Fatalf("loadEventEnvelopeSignerFromEnv: %v", err)
	}
	if signer == nil {
		t.Fatalf("signer is nil")
	}

	wrapped, err := signer.Wrap("/v1/events/verify", []byte(`{"event_id":"evt_contract_keyid_set"}`))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	var env map[string]any
	if err := json.Unmarshal(wrapped, &env); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if got, _ := env["key_id"].(string); got != "k_contract" {
		t.Fatalf("envelope.key_id = %q, want k_contract", got)
	}
}

func TestGatewayEventSyncContract_FailClosedOnControlPlaneEnvelopeError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"envelope.key_id_required"}`))
	}))
	defer srv.Close()

	spool := newEventSpool(t.TempDir())
	spool.SetAutoSync(false)
	spool.SetControlPlaneURL(srv.URL)
	if err := spool.Enqueue("/v1/events/scan", map[string]any{"event_id": "evt_sync_fail_closed"}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	res, err := spool.Sync(true)
	if err == nil {
		t.Fatalf("Sync returned nil error, want fail-closed error")
	}
	if !isControlPlaneFailClosedSyncError(err) {
		t.Fatalf("Sync error should be fail-closed, got: %v", err)
	}
	if !strings.Contains(err.Error(), "envelope.key_id_required") {
		t.Fatalf("Sync error=%q, want envelope.key_id_required", err.Error())
	}
	if res.Remaining != 1 {
		t.Fatalf("Remaining = %d, want 1", res.Remaining)
	}
	if !strings.Contains(res.LastError, "envelope.key_id_required") {
		t.Fatalf("LastError = %q, want envelope.key_id_required", res.LastError)
	}

	pending, readErr := readQueuedEvents(spool.pendingPath())
	if readErr != nil {
		t.Fatalf("readQueuedEvents: %v", readErr)
	}
	if len(pending) != 1 {
		t.Fatalf("pending len = %d, want 1", len(pending))
	}
	if !strings.Contains(pending[0].LastError, "envelope.key_id_required") {
		t.Fatalf("pending[0].LastError = %q, want envelope.key_id_required", pending[0].LastError)
	}
	retryAt, parseErr := time.Parse(time.RFC3339Nano, pending[0].NextRetryAt)
	if parseErr != nil {
		t.Fatalf("NextRetryAt parse failed: %v", parseErr)
	}
	if retryAt.Before(time.Now().UTC().Add(23 * time.Hour)) {
		t.Fatalf("NextRetryAt = %s, want fail-closed backoff (~24h)", pending[0].NextRetryAt)
	}
}

func TestGatewayEventSyncContract_KeepRetryableOnServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"temporary_unavailable"}`))
	}))
	defer srv.Close()

	spool := newEventSpool(t.TempDir())
	spool.SetAutoSync(false)
	spool.SetControlPlaneURL(srv.URL)
	if err := spool.Enqueue("/v1/events/verify", map[string]any{"event_id": "evt_sync_retryable"}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	res, err := spool.Sync(true)
	if err != nil {
		t.Fatalf("Sync returned error for retryable 5xx: %v", err)
	}
	if res.Sent != 0 {
		t.Fatalf("Sent = %d, want 0", res.Sent)
	}
	if res.Remaining != 1 {
		t.Fatalf("Remaining = %d, want 1", res.Remaining)
	}
	if !strings.Contains(res.LastError, "http_503") {
		t.Fatalf("LastError = %q, want contains http_503", res.LastError)
	}

	pending, readErr := readQueuedEvents(spool.pendingPath())
	if readErr != nil {
		t.Fatalf("readQueuedEvents: %v", readErr)
	}
	if len(pending) != 1 {
		t.Fatalf("pending len = %d, want 1", len(pending))
	}
	if pending[0].Attempts != 1 {
		t.Fatalf("pending[0].Attempts = %d, want 1", pending[0].Attempts)
	}
	if !strings.Contains(pending[0].LastError, "http_503") {
		t.Fatalf("pending[0].LastError = %q, want contains http_503", pending[0].LastError)
	}
}

func eventSigningSeedContract() string {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	return base64.StdEncoding.EncodeToString(seed)
}
