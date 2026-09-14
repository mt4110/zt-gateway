package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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

func TestGatewayEventSyncContract_FailClosedSuppressesAutoRetryLoop(t *testing.T) {
	var postCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		postCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"envelope.key_id_required"}`))
	}))
	defer srv.Close()

	spool := newEventSpool(t.TempDir())
	spool.SetAutoSync(false)
	spool.SetControlPlaneURL(srv.URL)
	if err := spool.Enqueue("/v1/events/scan", map[string]any{"event_id": "evt_sync_no_busy_loop"}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	if _, err := spool.Sync(true); err == nil {
		t.Fatalf("Sync(force) returned nil, want fail-closed error")
	}
	for i := 0; i < 3; i++ {
		res, err := spool.Sync(false)
		if err != nil {
			t.Fatalf("Sync(non-force #%d) returned error: %v", i+1, err)
		}
		if res.Skipped != 1 {
			t.Fatalf("Sync(non-force #%d) skipped=%d, want 1", i+1, res.Skipped)
		}
	}
	if got := postCount.Load(); got != 1 {
		t.Fatalf("post count = %d, want 1 (no busy loop retries)", got)
	}

	pending, err := readQueuedEvents(spool.pendingPath())
	if err != nil {
		t.Fatalf("readQueuedEvents: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("pending len = %d, want 1", len(pending))
	}
	if pending[0].Attempts != 1 {
		t.Fatalf("pending[0].Attempts = %d, want 1", pending[0].Attempts)
	}
	if pending[0].ErrorClass != syncErrorClassFailClosed {
		t.Fatalf("pending[0].ErrorClass = %q, want %q", pending[0].ErrorClass, syncErrorClassFailClosed)
	}
	if pending[0].FirstFailedAt == "" || pending[0].LastFailedAt == "" {
		t.Fatalf("pending failure timestamps should be set: first=%q last=%q", pending[0].FirstFailedAt, pending[0].LastFailedAt)
	}
}

func TestGatewayEventSyncContract_FailClosedCanResendWithForceAfterRecovery(t *testing.T) {
	var failClosed atomic.Bool
	failClosed.Store(true)
	var postCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		postCount.Add(1)
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if failClosed.Load() {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"envelope.key_id_required"}`))
			return
		}
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":         "accepted",
			"endpoint":       r.URL.Path,
			"payload_sha256": canonicalEventPayloadSHA(body),
			"accepted_at":    time.Now().UTC().Format(time.RFC3339),
		})
	}))
	defer srv.Close()

	spool := newEventSpool(t.TempDir())
	spool.SetAutoSync(false)
	spool.SetControlPlaneURL(srv.URL)
	if err := spool.Enqueue("/v1/events/verify", map[string]any{"event_id": "evt_sync_force_recovery"}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	if _, err := spool.Sync(true); err == nil {
		t.Fatalf("Sync(force initial) returned nil, want fail-closed error")
	}
	failClosed.Store(false)

	resSkip, err := spool.Sync(false)
	if err != nil {
		t.Fatalf("Sync(non-force) returned error after recovery: %v", err)
	}
	if resSkip.Skipped != 1 {
		t.Fatalf("Sync(non-force) skipped=%d, want 1", resSkip.Skipped)
	}
	if got := postCount.Load(); got != 1 {
		t.Fatalf("post count after non-force = %d, want 1", got)
	}

	resForce, err := spool.Sync(true)
	if err != nil {
		t.Fatalf("Sync(force recovery) returned error: %v", err)
	}
	if resForce.Sent != 1 || resForce.Remaining != 0 {
		t.Fatalf("Sync(force recovery) sent=%d remaining=%d, want 1/0", resForce.Sent, resForce.Remaining)
	}
	if got := postCount.Load(); got != 2 {
		t.Fatalf("post count after force recovery = %d, want 2", got)
	}
}

func eventSigningSeedContract() string {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	return base64.StdEncoding.EncodeToString(seed)
}
