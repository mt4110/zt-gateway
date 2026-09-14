package main

import "testing"

func TestAuditEventsJSONL_AppendOnlyContract(t *testing.T) {
	repoRoot := t.TempDir()
	prevEvents := cpEvents
	cpEvents = newEventSpool(repoRoot)
	cpEvents.SetAutoSync(false)
	defer func() { cpEvents = prevEvents }()

	emitControlPlaneEvent("/v1/events/scan", map[string]any{
		"event_id": "evt_append_1",
		"command":  "send",
		"result":   "allow",
	})
	emitControlPlaneEvent("/v1/events/verify", map[string]any{
		"event_id": "evt_append_2",
		"result":   "verified",
	})

	records := readAuditEventRecordsContract(t, cpEvents.auditPath())
	if len(records) != 2 {
		t.Fatalf("records len = %d, want 2", len(records))
	}
	if records[0].EventID != "evt_append_1" {
		t.Fatalf("records[0].event_id = %q, want evt_append_1", records[0].EventID)
	}
	if records[1].EventID != "evt_append_2" {
		t.Fatalf("records[1].event_id = %q, want evt_append_2", records[1].EventID)
	}
}
