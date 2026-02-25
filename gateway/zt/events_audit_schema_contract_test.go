package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

type auditEventRecordContract struct {
	EventID          string `json:"event_id"`
	EventType        string `json:"event_type"`
	Timestamp        string `json:"timestamp"`
	Result           string `json:"result"`
	Endpoint         string `json:"endpoint"`
	PayloadSHA256    string `json:"payload_sha256"`
	ChainVersion     string `json:"chain_version"`
	PrevRecordSHA256 string `json:"prev_record_sha256"`
	RecordSHA256     string `json:"record_sha256"`
	SignatureAlg     string `json:"signature_alg"`
	SignatureKeyID   string `json:"signature_key_id"`
	Signature        string `json:"signature"`
}

func TestAuditEventsJSONL_SchemaContract(t *testing.T) {
	repoRoot := t.TempDir()
	spool := newEventSpool(repoRoot)
	spool.SetAutoSync(false)

	payload := map[string]any{
		"event_id": "evt_scan_schema_contract",
		"command":  "send",
		"result":   "allow",
	}
	if err := spool.appendAuditEvent("/v1/events/scan", payload); err != nil {
		t.Fatalf("appendAuditEvent: %v", err)
	}

	records := readAuditEventRecordsContract(t, spool.auditPath())
	if len(records) != 1 {
		t.Fatalf("records len = %d, want 1", len(records))
	}
	record := records[0]
	assertAuditRequiredFieldsContract(t, record)
	if record.EventID != "evt_scan_schema_contract" {
		t.Fatalf("event_id = %q, want evt_scan_schema_contract", record.EventID)
	}
	if record.EventType != "send" {
		t.Fatalf("event_type = %q, want send", record.EventType)
	}
	if record.Endpoint != "/v1/events/scan" {
		t.Fatalf("endpoint = %q, want /v1/events/scan", record.Endpoint)
	}
	if record.Result != "allow" {
		t.Fatalf("result = %q, want allow", record.Result)
	}
	if _, err := time.Parse(time.RFC3339Nano, record.Timestamp); err != nil {
		t.Fatalf("timestamp parse failed: %v", err)
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal(payload): %v", err)
	}
	wantPayloadSHA := sha256HexBytes(payloadJSON)
	if record.PayloadSHA256 != wantPayloadSHA {
		t.Fatalf("payload_sha256 = %q, want %q", record.PayloadSHA256, wantPayloadSHA)
	}
	if record.ChainVersion != "v1" {
		t.Fatalf("chain_version = %q, want v1", record.ChainVersion)
	}
	if strings.TrimSpace(record.RecordSHA256) == "" {
		t.Fatalf("record_sha256 is empty")
	}
}

func TestAuditEventsJSONL_ResultFallbackContract(t *testing.T) {
	repoRoot := t.TempDir()
	spool := newEventSpool(repoRoot)
	spool.SetAutoSync(false)

	payload := map[string]any{
		"event_id": "evt_artifact_schema_contract",
	}
	if err := spool.appendAuditEvent("/v1/events/artifact", payload); err != nil {
		t.Fatalf("appendAuditEvent: %v", err)
	}

	records := readAuditEventRecordsContract(t, spool.auditPath())
	if len(records) != 1 {
		t.Fatalf("records len = %d, want 1", len(records))
	}
	record := records[0]
	assertAuditRequiredFieldsContract(t, record)
	if record.EventType != "artifact" {
		t.Fatalf("event_type = %q, want artifact", record.EventType)
	}
	if record.Result != "recorded" {
		t.Fatalf("result = %q, want recorded", record.Result)
	}
}

func readAuditEventRecordsContract(t *testing.T, path string) []auditEventRecordContract {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("os.Open(%s): %v", path, err)
	}
	defer f.Close()

	var records []auditEventRecordContract
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var record auditEventRecordContract
		if err := json.Unmarshal(line, &record); err != nil {
			t.Fatalf("json.Unmarshal audit line failed: %v\nline=%s", err, string(line))
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scanner.Err: %v", err)
	}
	return records
}

func assertAuditRequiredFieldsContract(t *testing.T, record auditEventRecordContract) {
	t.Helper()
	required := []struct {
		name  string
		value string
	}{
		{name: "event_id", value: record.EventID},
		{name: "event_type", value: record.EventType},
		{name: "timestamp", value: record.Timestamp},
		{name: "result", value: record.Result},
		{name: "endpoint", value: record.Endpoint},
		{name: "payload_sha256", value: record.PayloadSHA256},
		{name: "chain_version", value: record.ChainVersion},
		{name: "record_sha256", value: record.RecordSHA256},
	}
	for _, field := range required {
		if strings.TrimSpace(field.value) == "" {
			t.Fatalf("required field %s is empty: %#v", field.name, record)
		}
	}
}
