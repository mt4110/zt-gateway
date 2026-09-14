package main

import (
	"encoding/json"
	"testing"
)

func TestEmitModelPassportQueuesPassportEndpoint(t *testing.T) {
	spool := newEventSpool(t.TempDir())
	spool.SetAutoSync(false)

	prev := cpEvents
	cpEvents = spool
	t.Cleanup(func() {
		cpEvents = prev
	})

	manifest := modelCapsuleManifestV1{
		SchemaVersion: modelCapsuleManifestSchemaV1,
		CapsuleID:     "zmc_demo",
		Model: modelManifestModel{
			ModelID: "mdl_demo",
			Name:    "demo",
			Version: "1",
			Format:  "gguf",
		},
		Policy: modelPolicyV1{
			Profile:             trustProfileConfidential,
			AllowedRuntimes:     []string{"fake"},
			OfflineLeaseSeconds: 60,
		},
		Distribution: modelManifestDistribution{
			TenantID:  "tenant-a",
			ClientID:  "client-a",
			CreatedAt: "2026-05-28T00:00:00Z",
		},
	}
	emitModelPassport(manifest)

	pending, err := readQueuedEvents(spool.pendingPath())
	if err != nil {
		t.Fatalf("readQueuedEvents: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("pending len = %d, want 1", len(pending))
	}
	if pending[0].Endpoint != "/v1/models/passports" {
		t.Fatalf("endpoint = %q, want /v1/models/passports", pending[0].Endpoint)
	}
	var payload map[string]any
	if err := json.Unmarshal(pending[0].Payload, &payload); err != nil {
		t.Fatalf("json.Unmarshal payload: %v", err)
	}
	if payload["schema_version"] != modelCapsuleManifestSchemaV1 || payload["capsule_id"] != "zmc_demo" {
		t.Fatalf("unexpected passport payload: %#v", payload)
	}
}
