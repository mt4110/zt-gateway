package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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
	qfb, ok := payload["quick_fix_bundle"].(map[string]any)
	if !ok {
		t.Fatalf("quick_fix_bundle missing: %#v", payload["quick_fix_bundle"])
	}
	if got, _ := qfb["runbook"].(string); got == "" {
		t.Fatalf("quick_fix_bundle.runbook is empty")
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

func TestSyncCLIJSONContract_BacklogVisibilityContract(t *testing.T) {
	spool := newEventSpool(t.TempDir())
	spool.SetAutoSync(false)
	// keep pending events local only to test backlog projection fields.
	if err := spool.Enqueue("/v1/events/scan", map[string]any{"event_id": "evt_backlog_1"}); err != nil {
		t.Fatalf("Enqueue(1): %v", err)
	}
	if err := spool.Enqueue("/v1/events/verify", map[string]any{"event_id": "evt_backlog_2"}); err != nil {
		t.Fatalf("Enqueue(2): %v", err)
	}
	pending, err := readQueuedEvents(spool.pendingPath())
	if err != nil {
		t.Fatalf("readQueuedEvents: %v", err)
	}
	if len(pending) != 2 {
		t.Fatalf("pending len = %d, want 2", len(pending))
	}
	pending[0].EnqueuedAt = time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339Nano)
	pending[0].ErrorClass = syncErrorClassRetryable
	pending[0].NextRetryAt = time.Now().UTC().Add(5 * time.Minute).Format(time.RFC3339Nano)
	pending[1].ErrorClass = syncErrorClassFailClosed
	if err := rewriteQueuedEvents(spool.pendingPath(), pending); err != nil {
		t.Fatalf("rewriteQueuedEvents: %v", err)
	}

	prev := cpEvents
	cpEvents = spool
	defer func() { cpEvents = prev }()

	t.Setenv("ZT_SYNC_BACKLOG_SLO_SECONDS", "10")
	var out bytes.Buffer
	exitCode := runSyncEventsCommand(syncOptions{Force: false, JSON: true}, []string{"zt", "sync", "--json"}, &out)
	if exitCode != 0 {
		t.Fatalf("exit_code = %d, want 0", exitCode)
	}
	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal stdout: %v (stdout=%s)", err, out.String())
	}
	if got, _ := payload["pending_count"].(float64); int(got) != 2 {
		t.Fatalf("pending_count = %v, want 2", got)
	}
	if got, _ := payload["retryable_count"].(float64); int(got) != 1 {
		t.Fatalf("retryable_count = %v, want 1", got)
	}
	if got, _ := payload["fail_closed_count"].(float64); int(got) != 1 {
		t.Fatalf("fail_closed_count = %v, want 1", got)
	}
	if got, _ := payload["oldest_pending_age_seconds"].(float64); int(got) <= 0 {
		t.Fatalf("oldest_pending_age_seconds = %v, want >0", got)
	}
	if got, _ := payload["backlog_slo_seconds"].(float64); int64(got) != 10 {
		t.Fatalf("backlog_slo_seconds = %v, want 10", got)
	}
	if got, _ := payload["backlog_breached"].(bool); !got {
		t.Fatalf("backlog_breached = %v, want true", got)
	}
	if got, _ := payload["error_code"].(string); got != syncErrorCodeBacklogSLOBreached {
		t.Fatalf("error_code = %q, want %q", got, syncErrorCodeBacklogSLOBreached)
	}
	qfb, ok := payload["quick_fix_bundle"].(map[string]any)
	if !ok {
		t.Fatalf("quick_fix_bundle missing: %#v", payload["quick_fix_bundle"])
	}
	if got, _ := qfb["runbook_anchor"].(string); got != "#sync-backlog-slo-breached-v070" {
		t.Fatalf("runbook_anchor = %q, want #sync-backlog-slo-breached-v070", got)
	}
}

func TestSyncCLIJSONContract_BacklogSLODeterminismContract(t *testing.T) {
	spool := newEventSpool(t.TempDir())
	spool.SetAutoSync(false)
	if err := spool.Enqueue("/v1/events/scan", map[string]any{"event_id": "evt_backlog_slo_determinism"}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	pending, err := readQueuedEvents(spool.pendingPath())
	if err != nil {
		t.Fatalf("readQueuedEvents: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("pending len = %d, want 1", len(pending))
	}
	oldest := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
	pending[0].EnqueuedAt = oldest.Format(time.RFC3339Nano)
	if err := rewriteQueuedEvents(spool.pendingPath(), pending); err != nil {
		t.Fatalf("rewriteQueuedEvents: %v", err)
	}

	prev := cpEvents
	cpEvents = spool
	defer func() { cpEvents = prev }()

	t.Setenv("ZT_SYNC_BACKLOG_SLO_SECONDS", "60")
	var out bytes.Buffer
	exitCode := runSyncEventsCommand(syncOptions{JSON: true}, []string{"zt", "sync", "--json"}, &out)
	if exitCode != 0 {
		t.Fatalf("exit_code = %d, want 0", exitCode)
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal stdout: %v (stdout=%s)", err, out.String())
	}
	if got, _ := payload["backlog_slo_seconds"].(float64); int64(got) != 60 {
		t.Fatalf("backlog_slo_seconds = %v, want 60", got)
	}
	if got, _ := payload["backlog_breached"].(bool); !got {
		t.Fatalf("backlog_breached = %v, want true", got)
	}
	wantSince := oldest.Add(60 * time.Second).UTC().Format(time.RFC3339)
	if got, _ := payload["backlog_breached_since"].(string); got != wantSince {
		t.Fatalf("backlog_breached_since = %q, want %q", got, wantSince)
	}
}

func TestSyncCLIJSONContract_AckIntegrityMismatchContract(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"accepted","endpoint":"/v1/events/scan","payload_sha256":"wrong","accepted_at":"2026-02-25T00:00:00Z"}`))
	}))
	defer srv.Close()

	spool := newEventSpool(t.TempDir())
	spool.SetAutoSync(false)
	spool.SetControlPlaneURL(srv.URL)
	if err := spool.Enqueue("/v1/events/scan", map[string]any{"event_id": "evt_sync_ack_mismatch"}); err != nil {
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
	if got, _ := payload["error_class"].(string); got != syncErrorClassInternal {
		t.Fatalf("error_class = %q, want %q", got, syncErrorClassInternal)
	}
	if got, _ := payload["error_code"].(string); got != syncErrorCodeIngestAckMismatch {
		t.Fatalf("error_code = %q, want %q", got, syncErrorCodeIngestAckMismatch)
	}
	qfb, ok := payload["quick_fix_bundle"].(map[string]any)
	if !ok {
		t.Fatalf("quick_fix_bundle missing: %#v", payload["quick_fix_bundle"])
	}
	if got, _ := qfb["runbook_anchor"].(string); got != "#ingest-ack-mismatch-v070" {
		t.Fatalf("runbook_anchor = %q, want #ingest-ack-mismatch-v070", got)
	}
}
