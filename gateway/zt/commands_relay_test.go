package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunRelayDriveCommand_WritesPacketAndSidecars(t *testing.T) {
	repoRoot := t.TempDir()
	packetPath := filepath.Join(repoRoot, "bundle_clientA_20260225T000000Z.spkg.tgz")
	if err := os.WriteFile(packetPath, []byte("packet"), 0o644); err != nil {
		t.Fatal(err)
	}
	driveDir := filepath.Join(repoRoot, "drive-sync")

	if err := runRelayDriveCommand(repoRoot, []string{
		"--packet", packetPath,
		"--folder", driveDir,
		"--format", "en",
		"--write-json",
	}); err != nil {
		t.Fatalf("runRelayDriveCommand returned error: %v", err)
	}

	copiedPacket := filepath.Join(driveDir, filepath.Base(packetPath))
	if _, err := os.Stat(copiedPacket); err != nil {
		t.Fatalf("copied packet not found: %v", err)
	}
	verifyTextPath := copiedPacket + ".verify.txt"
	verifyText, err := os.ReadFile(verifyTextPath)
	if err != nil {
		t.Fatalf("verify text not found: %v", err)
	}
	if !strings.Contains(string(verifyText), "zt verify --") {
		t.Fatalf("verify text missing command:\n%s", string(verifyText))
	}
	shareJSONPath := copiedPacket + ".share.json"
	if _, err := os.Stat(shareJSONPath); err != nil {
		t.Fatalf("share JSON not found: %v", err)
	}
}

func TestRunRelayCommand_BlockedByLocalLock(t *testing.T) {
	repoRoot := t.TempDir()
	packetPath := filepath.Join(repoRoot, "bundle_clientA_20260225T000000Z.spkg.tgz")
	if err := os.WriteFile(packetPath, []byte("packet"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := writeLocalOperationLock(repoRoot, true, "incident", "test", time.Now().UTC()); err != nil {
		t.Fatalf("writeLocalOperationLock: %v", err)
	}
	err := runRelayCommand(repoRoot, []string{
		"drive",
		"--packet", packetPath,
		"--folder", filepath.Join(repoRoot, "drive-sync"),
	})
	if err == nil {
		t.Fatalf("runRelayCommand returned nil, want local lock error")
	}
	if !strings.Contains(err.Error(), "blocked by local lock") {
		t.Fatalf("error = %q, want blocked by local lock", err.Error())
	}
}
