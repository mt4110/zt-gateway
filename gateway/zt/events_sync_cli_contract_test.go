package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSyncCLIJSONContract_FailClosedExitCodeAndEnvelopeError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"envelope.key_id_required"}`))
	}))
	defer srv.Close()

	spool := newEventSpool(t.TempDir())
	spool.SetAutoSync(false)
	spool.SetControlPlaneURL(srv.URL)
	if err := spool.Enqueue("/v1/events/scan", map[string]any{"event_id": "evt_sync_json_fail_closed"}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	prev := cpEvents
	cpEvents = spool
	defer func() { cpEvents = prev }()

	var out bytes.Buffer
	exitCode := runSyncEventsCommand(syncOptions{Force: true, JSON: true}, []string{"zt", "sync", "--force", "--json"}, &out)
	if exitCode != 1 {
		t.Fatalf("exit_code = %d, want 1", exitCode)
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal stdout: %v (stdout=%s)", err, out.String())
	}
	if got, _ := payload["ok"].(bool); got {
		t.Fatalf("ok = true, want false")
	}
	if got, _ := payload["error_class"].(string); got != syncErrorClassFailClosed {
		t.Fatalf("error_class = %q, want %q", got, syncErrorClassFailClosed)
	}
	if got, _ := payload["error_code"].(string); got != "envelope.key_id_required" {
		t.Fatalf("error_code = %q, want envelope.key_id_required", got)
	}
	if got, _ := payload["exit_code"].(float64); int(got) != 1 {
		t.Fatalf("payload.exit_code = %v, want 1", got)
	}
}

func TestSyncCLIJSONContract_Retryable5xxKeepsExitZero(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"temporary_unavailable"}`))
	}))
	defer srv.Close()

	spool := newEventSpool(t.TempDir())
	spool.SetAutoSync(false)
	spool.SetControlPlaneURL(srv.URL)
	if err := spool.Enqueue("/v1/events/verify", map[string]any{"event_id": "evt_sync_json_503"}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	prev := cpEvents
	cpEvents = spool
	defer func() { cpEvents = prev }()

	var out bytes.Buffer
	exitCode := runSyncEventsCommand(syncOptions{Force: true, JSON: true}, []string{"zt", "sync", "--force", "--json"}, &out)
	if exitCode != 0 {
		t.Fatalf("exit_code = %d, want 0", exitCode)
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal stdout: %v (stdout=%s)", err, out.String())
	}
	if got, _ := payload["error_class"].(string); got != syncErrorClassRetryable {
		t.Fatalf("error_class = %q, want %q", got, syncErrorClassRetryable)
	}
	if got, _ := payload["error_code"].(string); got != "http_503" {
		t.Fatalf("error_code = %q, want http_503", got)
	}
	if got, _ := payload["exit_code"].(float64); int(got) != 0 {
		t.Fatalf("payload.exit_code = %v, want 0", got)
	}
}

func TestSyncCLIJSONContract_RetryableTransportError(t *testing.T) {
	spool := newEventSpool(t.TempDir())
	spool.SetAutoSync(false)
	spool.SetControlPlaneURL("http://127.0.0.1:1")
	if err := spool.Enqueue("/v1/events/scan", map[string]any{"event_id": "evt_sync_json_transport"}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	prev := cpEvents
	cpEvents = spool
	defer func() { cpEvents = prev }()

	var out bytes.Buffer
	exitCode := runSyncEventsCommand(syncOptions{Force: true, JSON: true}, []string{"zt", "sync", "--force", "--json"}, &out)
	if exitCode != 0 {
		t.Fatalf("exit_code = %d, want 0", exitCode)
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal stdout: %v (stdout=%s)", err, out.String())
	}
	if got, _ := payload["error_class"].(string); got != syncErrorClassRetryable {
		t.Fatalf("error_class = %q, want %q", got, syncErrorClassRetryable)
	}
	if got, _ := payload["error_code"].(string); got != syncErrorCodeTransportFailed {
		t.Fatalf("error_code = %q, want %q", got, syncErrorCodeTransportFailed)
	}
}
