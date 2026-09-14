package main

import "testing"

func TestAuditEventsJSONL_ChainContract(t *testing.T) {
	repoRoot := t.TempDir()
	spool := newEventSpool(repoRoot)
	spool.SetAutoSync(false)

	for i, eventID := range []string{"evt_chain_1", "evt_chain_2", "evt_chain_3"} {
		payload := map[string]any{
			"event_id": eventID,
			"command":  "send",
			"result":   "allow",
		}
		if i == 2 {
			payload["command"] = "verify"
			payload["result"] = "verified"
		}
		if err := spool.appendAuditEvent("/v1/events/scan", payload); err != nil {
			t.Fatalf("appendAuditEvent(%d): %v", i, err)
		}
	}

	records := readAuditEventRecordsContract(t, spool.auditPath())
	if len(records) != 3 {
		t.Fatalf("records len = %d, want 3", len(records))
	}
	if records[0].PrevRecordSHA256 != "" {
		t.Fatalf("records[0].prev_record_sha256 = %q, want empty", records[0].PrevRecordSHA256)
	}
	if records[1].PrevRecordSHA256 != records[0].RecordSHA256 {
		t.Fatalf("records[1].prev_record_sha256 = %q, want %q", records[1].PrevRecordSHA256, records[0].RecordSHA256)
	}
	if records[2].PrevRecordSHA256 != records[1].RecordSHA256 {
		t.Fatalf("records[2].prev_record_sha256 = %q, want %q", records[2].PrevRecordSHA256, records[1].RecordSHA256)
	}

	if err := verifyAuditEventsFile(spool.auditPath(), auditVerifyOptions{}); err != nil {
		t.Fatalf("verifyAuditEventsFile: %v", err)
	}
}
