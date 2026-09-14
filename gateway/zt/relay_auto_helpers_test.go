package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRelayAutoFileReady_StableWindow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "input.txt")
	if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	states := map[string]relayAutoFileStability{}

	ready, _, err := relayAutoFileReady(path, now, 2*time.Second, states)
	if err != nil {
		t.Fatalf("relayAutoFileReady(first) returned error: %v", err)
	}
	if ready {
		t.Fatalf("relayAutoFileReady(first) = true, want false")
	}

	ready, _, err = relayAutoFileReady(path, now.Add(3*time.Second), 2*time.Second, states)
	if err != nil {
		t.Fatalf("relayAutoFileReady(stable) returned error: %v", err)
	}
	if !ready {
		t.Fatalf("relayAutoFileReady(stable) = false, want true")
	}

	if err := os.WriteFile(path, []byte("hello world"), 0o644); err != nil {
		t.Fatal(err)
	}
	ready, _, err = relayAutoFileReady(path, now.Add(4*time.Second), 2*time.Second, states)
	if err != nil {
		t.Fatalf("relayAutoFileReady(updated) returned error: %v", err)
	}
	if ready {
		t.Fatalf("relayAutoFileReady(updated) = true, want false")
	}
}

func TestRelayAutoBackoffDelay_Cap(t *testing.T) {
	base := 5 * time.Second
	if got := relayAutoBackoffDelay(base, 1); got != 5*time.Second {
		t.Fatalf("attempt1=%s, want 5s", got)
	}
	if got := relayAutoBackoffDelay(base, 2); got != 10*time.Second {
		t.Fatalf("attempt2=%s, want 10s", got)
	}
	if got := relayAutoBackoffDelay(base, 20); got != relayAutoMaxBackoffCap {
		t.Fatalf("attempt20=%s, want cap=%s", got, relayAutoMaxBackoffCap)
	}
}

func TestRelayAutoDedupStore_LoadAndAppend(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dedup.jsonl")
	store, err := loadRelayAutoDedupStore(path)
	if err != nil {
		t.Fatalf("loadRelayAutoDedupStore(initial): %v", err)
	}
	if len(store.Seen) != 0 {
		t.Fatalf("initial seen=%d, want 0", len(store.Seen))
	}

	rec := relayAutoDedupRecord{
		Client:      "clientA",
		SHA256:      "abc123",
		SizeBytes:   42,
		SourcePath:  "/tmp/src.txt",
		PacketPath:  "/tmp/bundle.spkg.tgz",
		CompletedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := appendRelayAutoDedupRecord(&store, rec); err != nil {
		t.Fatalf("appendRelayAutoDedupRecord: %v", err)
	}

	reloaded, err := loadRelayAutoDedupStore(path)
	if err != nil {
		t.Fatalf("loadRelayAutoDedupStore(reload): %v", err)
	}
	key := relayAutoDedupKey("clientA", "abc123", 42)
	if _, ok := reloaded.Seen[key]; !ok {
		t.Fatalf("dedup key %q not found after reload", key)
	}
}
