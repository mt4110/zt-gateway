package main

import (
	"os"
	"path/filepath"
	"reflect"
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

func TestExtractPacketPathFromVerifyCommand(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want string
	}{
		{
			name: "single_quote",
			cmd:  "zt verify -- './bundle_a.spkg.tgz'",
			want: "./bundle_a.spkg.tgz",
		},
		{
			name: "double_quote",
			cmd:  "zt verify -- \"./bundle_b.spkg.tgz\"",
			want: "./bundle_b.spkg.tgz",
		},
		{
			name: "bare",
			cmd:  "zt verify ./bundle_c.spkg.tgz",
			want: "./bundle_c.spkg.tgz",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := extractPacketPathFromVerifyCommand(tc.cmd)
			if err != nil {
				t.Fatalf("extractPacketPathFromVerifyCommand returned error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("extractPacketPathFromVerifyCommand() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestListRelayAutoCandidates(t *testing.T) {
	watchDir := t.TempDir()
	files := []string{
		"a.txt",
		"b.csv",
		"bundle_x.spkg.tgz",
		"bundle_x.spkg.tgz.verify.txt",
		"bundle_x.spkg.tgz.share.json",
		".hidden.tmp",
	}
	for _, name := range files {
		if err := os.WriteFile(filepath.Join(watchDir, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(watchDir, ".zt-done"), 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := listRelayAutoCandidates(watchDir)
	if err != nil {
		t.Fatalf("listRelayAutoCandidates returned error: %v", err)
	}
	want := []string{
		filepath.Join(watchDir, "a.txt"),
		filepath.Join(watchDir, "b.csv"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("candidates = %#v, want %#v", got, want)
	}
}
