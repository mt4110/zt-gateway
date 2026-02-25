package main

import (
	"encoding/json"
	"fmt"
	"path"
	"path/filepath"
	"strings"
	"time"
)

type auditEventRecord struct {
	EventID       string `json:"event_id"`
	EventType     string `json:"event_type"`
	Timestamp     string `json:"timestamp"`
	Result        string `json:"result"`
	Endpoint      string `json:"endpoint"`
	PayloadSHA256 string `json:"payload_sha256"`
}

type auditPayloadFields struct {
	EventID string
	Result  string
	Command string
}

func (s *eventSpool) auditPath() string { return filepath.Join(s.cfg.SpoolDir, "events.jsonl") }

func (s *eventSpool) appendAuditEvent(endpoint string, payload any) error {
	if s == nil {
		return nil
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	record := newAuditEventRecord(endpoint, payloadJSON, now)
	return s.withFileLock(5*time.Second, func() error {
		return appendJSONLine(s.auditPath(), record)
	})
}

func newAuditEventRecord(endpoint string, payloadJSON []byte, now time.Time) auditEventRecord {
	fields := parseAuditPayloadFields(payloadJSON)
	eventID := strings.TrimSpace(fields.EventID)
	if eventID == "" {
		eventID = fmt.Sprintf("audit_evt_%d", now.UnixNano())
	}
	result := strings.TrimSpace(fields.Result)
	if result == "" {
		result = "recorded"
	}
	eventType := resolveAuditEventType(endpoint, fields.Command)
	return auditEventRecord{
		EventID:       eventID,
		EventType:     eventType,
		Timestamp:     now.Format(time.RFC3339Nano),
		Result:        result,
		Endpoint:      strings.TrimSpace(endpoint),
		PayloadSHA256: sha256HexBytes(payloadJSON),
	}
}

func parseAuditPayloadFields(payloadJSON []byte) auditPayloadFields {
	var payload map[string]any
	if err := json.Unmarshal(payloadJSON, &payload); err != nil || payload == nil {
		return auditPayloadFields{}
	}
	return auditPayloadFields{
		EventID: stringFromAnyMap(payload, "event_id"),
		Result:  stringFromAnyMap(payload, "result"),
		Command: stringFromAnyMap(payload, "command"),
	}
}

func resolveAuditEventType(endpoint, command string) string {
	if c := strings.TrimSpace(command); c != "" {
		return c
	}
	tail := path.Base(strings.TrimSpace(endpoint))
	if tail == "" || tail == "." || tail == "/" {
		return "unknown"
	}
	return tail
}

func stringFromAnyMap(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}
