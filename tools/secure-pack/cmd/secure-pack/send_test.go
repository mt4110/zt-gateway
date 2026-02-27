package main

import (
	"path/filepath"
	"testing"
)

func resetSendConfigFlagsForTest() {
	sendBaseDir = ""
	sendOutDir = ""
	sendRecipients = ""
	sendToolsLock = ""
	sendRootPubKey = ""
}

func TestBuildSendConfig_DefaultsToCWD(t *testing.T) {
	resetSendConfigFlagsForTest()
	cwd := t.TempDir()
	cfg, err := buildSendConfig(cwd)
	if err != nil {
		t.Fatalf("buildSendConfig returned error: %v", err)
	}
	if cfg.BaseDir != cwd {
		t.Fatalf("BaseDir=%q, want %q", cfg.BaseDir, cwd)
	}
	if cfg.OutDir != filepath.Join(cwd, "dist") {
		t.Fatalf("OutDir=%q, want %q", cfg.OutDir, filepath.Join(cwd, "dist"))
	}
}

func TestBuildSendConfig_AllowsFlagOverrides(t *testing.T) {
	resetSendConfigFlagsForTest()
	base := t.TempDir()
	sendBaseDir = base
	sendRecipients = "custom-recipients"
	sendOutDir = "out"
	sendToolsLock = "supply-chain/tools.lock"
	sendRootPubKey = "keys/ROOT_PUBKEY.asc"

	cfg, err := buildSendConfig(t.TempDir())
	if err != nil {
		t.Fatalf("buildSendConfig returned error: %v", err)
	}
	if cfg.BaseDir != base {
		t.Fatalf("BaseDir=%q, want %q", cfg.BaseDir, base)
	}
	if cfg.RecipientsDir != filepath.Join(base, "custom-recipients") {
		t.Fatalf("RecipientsDir=%q, want %q", cfg.RecipientsDir, filepath.Join(base, "custom-recipients"))
	}
	if cfg.OutDir != filepath.Join(base, "out") {
		t.Fatalf("OutDir=%q, want %q", cfg.OutDir, filepath.Join(base, "out"))
	}
	if cfg.ToolsLock != filepath.Join(base, "supply-chain", "tools.lock") {
		t.Fatalf("ToolsLock=%q, want %q", cfg.ToolsLock, filepath.Join(base, "supply-chain", "tools.lock"))
	}
	if cfg.RootPubKey != filepath.Join(base, "keys", "ROOT_PUBKEY.asc") {
		t.Fatalf("RootPubKey=%q, want %q", cfg.RootPubKey, filepath.Join(base, "keys", "ROOT_PUBKEY.asc"))
	}
}

func TestResolveSendPath_PreservesAbsolute(t *testing.T) {
	base := t.TempDir()
	abs := filepath.Join(t.TempDir(), "root.asc")
	if got := resolveSendPath(base, abs); got != abs {
		t.Fatalf("resolveSendPath(abs)=%q, want %q", got, abs)
	}
}
