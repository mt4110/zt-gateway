package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildSetupCompatibilityResolverReport_NoMismatch(t *testing.T) {
	repoRoot := t.TempDir()
	toolDir := t.TempDir()
	gpgPath := writeFakeTool(t, toolDir, "gpg", "gpg (GnuPG) 2.4.4")
	tarPath := writeFakeTool(t, toolDir, "tar", "tar (GNU tar) 1.35")
	t.Setenv("PATH", toolDir)

	writeToolsLockForCompatibility(t, repoRoot, gpgPath, "gpg (GnuPG) 2.4.4", tarPath, "tar (GNU tar) 1.35")

	check, report, fixes := buildSetupCompatibilityResolverReport(
		repoRoot,
		setupCheck{Name: "secure_pack_root_pubkey_fingerprint", Status: "ok"},
		setupCheck{Name: "secure_pack_tools_lock_signature", Status: "ok"},
	)
	if report == nil {
		t.Fatalf("report = nil")
	}
	if report.Status != "ok" {
		t.Fatalf("report.Status = %q, want ok", report.Status)
	}
	if report.Category != setupCompatCategoryNone {
		t.Fatalf("report.Category = %q, want %q", report.Category, setupCompatCategoryNone)
	}
	if check.Status != "ok" {
		t.Fatalf("check.Status = %q, want ok", check.Status)
	}
	if len(fixes) != 0 {
		t.Fatalf("fixes = %v, want empty", fixes)
	}
}

func TestBuildSetupCompatibilityResolverReport_ToolVersionMismatch(t *testing.T) {
	repoRoot := t.TempDir()
	toolDir := t.TempDir()
	gpgPath := writeFakeTool(t, toolDir, "gpg", "gpg (GnuPG) 2.4.4")
	tarPath := writeFakeTool(t, toolDir, "tar", "tar (GNU tar) 1.35")
	t.Setenv("PATH", toolDir)

	writeToolsLockForCompatibility(t, repoRoot, gpgPath, "gpg (GnuPG) 2.4.4", tarPath, "tar (GNU tar) 1.34")

	check, report, fixes := buildSetupCompatibilityResolverReport(
		repoRoot,
		setupCheck{Name: "secure_pack_root_pubkey_fingerprint", Status: "ok"},
		setupCheck{Name: "secure_pack_tools_lock_signature", Status: "ok"},
	)
	if report == nil {
		t.Fatalf("report = nil")
	}
	if report.Status != "warn" {
		t.Fatalf("report.Status = %q, want warn", report.Status)
	}
	if report.Category != setupCompatCategoryToolVersionMismatch {
		t.Fatalf("report.Category = %q, want %q", report.Category, setupCompatCategoryToolVersionMismatch)
	}
	if check.Status != "warn" {
		t.Fatalf("check.Status = %q, want warn", check.Status)
	}
	if len(report.FixCandidates) == 0 || len(fixes) == 0 {
		t.Fatalf("expected non-empty fix candidates")
	}
}

func TestBuildSetupCompatibilityResolverReport_RootPinFailureTakesPriority(t *testing.T) {
	repoRoot := t.TempDir()
	check, report, _ := buildSetupCompatibilityResolverReport(
		repoRoot,
		setupCheck{
			Name:    "secure_pack_root_pubkey_fingerprint",
			Status:  "fail",
			Message: "no trusted root key fingerprint pins configured (set ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS)",
		},
		setupCheck{Name: "secure_pack_tools_lock_signature", Status: "ok"},
	)
	if report == nil {
		t.Fatalf("report = nil")
	}
	if report.Category != setupCompatCategoryRootPinMissing {
		t.Fatalf("report.Category = %q, want %q", report.Category, setupCompatCategoryRootPinMissing)
	}
	if check.Status != "warn" {
		t.Fatalf("check.Status = %q, want warn", check.Status)
	}
}

func writeFakeTool(t *testing.T, dir, name, versionLine string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	content := fmt.Sprintf(`#!/bin/sh
if [ "$1" = "--version" ]; then
  echo %q
  exit 0
fi
echo %q
`, versionLine, name)
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatalf("write fake tool %s: %v", name, err)
	}
	return path
}

func writeToolsLockForCompatibility(t *testing.T, repoRoot, gpgPath, gpgVersion, tarPath, tarVersion string) {
	t.Helper()
	spDir := filepath.Join(repoRoot, "tools", "secure-pack")
	if err := os.MkdirAll(spDir, 0o755); err != nil {
		t.Fatal(err)
	}
	gpgSHA, err := fileSHA256ForSetup(gpgPath)
	if err != nil {
		t.Fatal(err)
	}
	tarSHA, err := fileSHA256ForSetup(tarPath)
	if err != nil {
		t.Fatal(err)
	}
	lock := strings.Join([]string{
		fmt.Sprintf("gpg_sha256=\"%s\"", gpgSHA),
		fmt.Sprintf("gpg_version=\"%s\"", gpgVersion),
		fmt.Sprintf("tar_sha256=\"%s\"", tarSHA),
		fmt.Sprintf("tar_version=\"%s\"", tarVersion),
		"",
	}, "\n")
	if err := os.WriteFile(filepath.Join(spDir, "tools.lock"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
}
