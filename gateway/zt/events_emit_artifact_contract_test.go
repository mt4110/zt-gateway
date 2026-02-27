package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestEmitArtifactEvent_IncludesRebuildProvenanceContract(t *testing.T) {
	repoRoot := t.TempDir()
	spool := newEventSpool(repoRoot)
	spool.SetAutoSync(false)

	prev := cpEvents
	cpEvents = spool
	t.Cleanup(func() {
		cpEvents = prev
	})

	input := filepath.Join(repoRoot, "in.txt")
	artifact := filepath.Join(repoRoot, "bundle.spkg.tgz")
	if err := os.WriteFile(input, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifact, []byte("packet"), 0o644); err != nil {
		t.Fatal(err)
	}

	rebuild := map[string]any{
		"status":        "sanitized",
		"input_sha256":  "a",
		"output_sha256": "b",
	}
	emitArtifactEvent("spkg.tgz", artifact, input, "clientA", "rule-1", decisionForVerify(true, "policy_verify_pass"), rebuild)

	pending, err := readQueuedEvents(spool.pendingPath())
	if err != nil {
		t.Fatalf("readQueuedEvents: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("pending len = %d, want 1", len(pending))
	}

	var payload map[string]any
	if err := json.Unmarshal(pending[0].Payload, &payload); err != nil {
		t.Fatalf("json.Unmarshal payload: %v", err)
	}
	raw, ok := payload["rebuild_provenance"].(map[string]any)
	if !ok {
		t.Fatalf("rebuild_provenance missing or invalid: %#v", payload["rebuild_provenance"])
	}
	if raw["status"] != "sanitized" {
		t.Fatalf("rebuild_provenance.status = %v, want sanitized", raw["status"])
	}
}
