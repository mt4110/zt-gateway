package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEventIngestIdempotencyContract_DuplicateAcceptedAndIdentified(t *testing.T) {
	srv := newIngestContractServer(t, nil, false, nil)
	handler := srv.handleEventIngest("scan")
	body := []byte(`{"event_id":"evt_dup_1","result":"allow","reason":"clean"}`)

	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, httptest.NewRequest(http.MethodPost, "/v1/events/scan", bytes.NewReader(body)))
	if rr1.Code != http.StatusAccepted {
		t.Fatalf("first status = %d, want 202 (body=%s)", rr1.Code, rr1.Body.String())
	}
	first := decodeJSONMapContract(t, rr1.Body.Bytes())
	if got, _ := first["duplicate"].(bool); got {
		t.Fatalf("first duplicate = true, want false")
	}
	ingestID1, _ := first["ingest_id"].(string)
	if strings.TrimSpace(ingestID1) == "" {
		t.Fatalf("first ingest_id is empty")
	}

	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, httptest.NewRequest(http.MethodPost, "/v1/events/scan", bytes.NewReader(body)))
	if rr2.Code != http.StatusAccepted {
		t.Fatalf("second status = %d, want 202 (body=%s)", rr2.Code, rr2.Body.String())
	}
	second := decodeJSONMapContract(t, rr2.Body.Bytes())
	if got, _ := second["duplicate"].(bool); !got {
		t.Fatalf("second duplicate = false, want true")
	}
	ingestID2, _ := second["ingest_id"].(string)
	if ingestID2 != ingestID1 {
		t.Fatalf("duplicate ingest_id = %q, want %q", ingestID2, ingestID1)
	}
	if got, _ := second["duplicate_rule"].(string); got != "event_id+payload_sha256" {
		t.Fatalf("duplicate_rule = %q, want event_id+payload_sha256", got)
	}

	eventsPath := filepath.Join(srv.dataDir, "events", "scan.jsonl")
	lines := readJSONLLineCountContract(t, eventsPath)
	if lines != 1 {
		t.Fatalf("stored events lines = %d, want 1", lines)
	}
}

func TestEventIngestIdempotencyContract_NonDuplicateOnPayloadChange(t *testing.T) {
	srv := newIngestContractServer(t, nil, false, nil)
	handler := srv.handleEventIngest("scan")
	bodyA := []byte(`{"event_id":"evt_dup_2","result":"allow","reason":"clean"}`)
	bodyB := []byte(`{"event_id":"evt_dup_2","result":"allow","reason":"updated"}`)

	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, httptest.NewRequest(http.MethodPost, "/v1/events/scan", bytes.NewReader(bodyA)))
	if rr1.Code != http.StatusAccepted {
		t.Fatalf("first status = %d, want 202 (body=%s)", rr1.Code, rr1.Body.String())
	}
	first := decodeJSONMapContract(t, rr1.Body.Bytes())
	ingestID1, _ := first["ingest_id"].(string)

	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, httptest.NewRequest(http.MethodPost, "/v1/events/scan", bytes.NewReader(bodyB)))
	if rr2.Code != http.StatusAccepted {
		t.Fatalf("second status = %d, want 202 (body=%s)", rr2.Code, rr2.Body.String())
	}
	second := decodeJSONMapContract(t, rr2.Body.Bytes())
	if got, _ := second["duplicate"].(bool); got {
		t.Fatalf("second duplicate = true, want false")
	}
	ingestID2, _ := second["ingest_id"].(string)
	if ingestID2 == ingestID1 {
		t.Fatalf("ingest_id should differ for non-duplicate payloads: %q", ingestID2)
	}

	eventsPath := filepath.Join(srv.dataDir, "events", "scan.jsonl")
	lines := readJSONLLineCountContract(t, eventsPath)
	if lines != 2 {
		t.Fatalf("stored events lines = %d, want 2", lines)
	}
}

func TestEventIngestIdempotencyContract_EventIDRequired(t *testing.T) {
	srv := newIngestContractServer(t, nil, false, nil)
	handler := srv.handleEventIngest("scan")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/events/scan", bytes.NewReader([]byte(`{"result":"allow"}`))))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body=%s)", rr.Code, rr.Body.String())
	}
	resp := decodeJSONMapContract(t, rr.Body.Bytes())
	if got, _ := resp["error"].(string); got != "event_id_required" {
		t.Fatalf("error = %q, want event_id_required", got)
	}
}

func decodeJSONMapContract(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("json.Unmarshal: %v (body=%s)", err, string(body))
	}
	return m
}

func readJSONLLineCountContract(t *testing.T, path string) int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("os.ReadFile(%s): %v", path, err)
	}
	trimmed := strings.TrimSpace(string(b))
	if trimmed == "" {
		return 0
	}
	return len(strings.Split(trimmed, "\n"))
}
