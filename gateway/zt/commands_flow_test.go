package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveSendScanStrict_DefaultIsStrict(t *testing.T) {
	strict, msg := resolveSendScanStrict(sendOptions{}, false)
	if !strict {
		t.Fatalf("strict = false, want true")
	}
	if !strings.Contains(msg, "default") {
		t.Fatalf("msg = %q, want default notice", msg)
	}
}

func TestResolveSendScanStrict_AllowDegradedOverridesDefault(t *testing.T) {
	strict, msg := resolveSendScanStrict(sendOptions{AllowDegradedScan: true}, true)
	if strict {
		t.Fatalf("strict = true, want false")
	}
	if !strings.Contains(msg, "--allow-degraded-scan") {
		t.Fatalf("msg = %q, want allow-degraded-scan note", msg)
	}
}

func TestResolveSendScanStrict_ExplicitStrictMessage(t *testing.T) {
	strict, msg := resolveSendScanStrict(sendOptions{Strict: true}, false)
	if !strict {
		t.Fatalf("strict = false, want true")
	}
	if !strings.Contains(msg, "--strict") {
		t.Fatalf("msg = %q, want --strict note", msg)
	}
}

func TestRunSendSecurePackPrecheck_MissingFilesBlocks(t *testing.T) {
	repoRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repoRoot, "tools", "secure-pack"), 0o755); err != nil {
		t.Fatal(err)
	}

	ok, fixes := runSendSecurePackPrecheck(repoRoot)
	if ok {
		t.Fatalf("ok = true, want false when supply-chain files are missing")
	}
	if len(fixes) == 0 {
		t.Fatalf("expected quick fixes when precheck fails")
	}
}
