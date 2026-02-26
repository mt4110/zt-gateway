package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLocalOperationLock_SetAndEnforce(t *testing.T) {
	repoRoot := t.TempDir()

	initial, err := loadLocalOperationLock(repoRoot)
	if err != nil {
		t.Fatalf("loadLocalOperationLock(initial): %v", err)
	}
	if initial.Locked {
		t.Fatalf("initial.Locked = true, want false")
	}

	locked, err := writeLocalOperationLock(repoRoot, true, "incident_investigation", "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("writeLocalOperationLock(lock): %v", err)
	}
	if !locked.Locked {
		t.Fatalf("locked.Locked = false, want true")
	}

	if _, err := ensureOperationUnlocked(repoRoot, "send"); err == nil {
		t.Fatalf("ensureOperationUnlocked(send) = nil, want error")
	}

	unlocked, err := writeLocalOperationLock(repoRoot, false, "incident_closed", "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("writeLocalOperationLock(unlock): %v", err)
	}
	if unlocked.Locked {
		t.Fatalf("unlocked.Locked = true, want false")
	}
	if _, err := ensureOperationUnlocked(repoRoot, "relay"); err != nil {
		t.Fatalf("ensureOperationUnlocked(relay) returned error: %v", err)
	}
}

func TestEnsureOperationUnlocked_BlocksOnMalformedLockFile(t *testing.T) {
	repoRoot := t.TempDir()
	path := defaultLocalLockPath(repoRoot)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{bad-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := ensureOperationUnlocked(repoRoot, "send")
	if err == nil {
		t.Fatalf("ensureOperationUnlocked(send) = nil, want error")
	}
	if !strings.Contains(err.Error(), "local lock state is invalid") {
		t.Fatalf("error = %q, want local lock state is invalid", err.Error())
	}
}
