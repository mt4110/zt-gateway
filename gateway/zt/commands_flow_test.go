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

func TestResolveSendScanStrict_PublicProfileDefaultsToStrict(t *testing.T) {
	strict, msg := resolveSendScanStrict(sendOptions{Profile: trustProfilePublic}, false)
	if !strict {
		t.Fatalf("strict = false, want true for public profile default")
	}
	if !strings.Contains(msg, "default") {
		t.Fatalf("msg = %q, want default note", msg)
	}
}

func TestResolveSendScanStrict_ConfidentialForcesStrict(t *testing.T) {
	strict, msg := resolveSendScanStrict(sendOptions{Profile: trustProfileConfidential, AllowDegradedScan: true}, false)
	if !strict {
		t.Fatalf("strict = false, want true for confidential profile")
	}
	if !strings.Contains(msg, "profile=confidential") {
		t.Fatalf("msg = %q, want profile=confidential note", msg)
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

func TestProfileExtensionPolicy_ConfidentialAndRegulatedRequireRebuildForDocs(t *testing.T) {
	repoRoot := filepath.Clean(filepath.Join("..", ".."))
	cases := []struct {
		profile string
	}{
		{profile: trustProfileConfidential},
		{profile: trustProfileRegulated},
	}
	for _, tc := range cases {
		policyPath := filepath.Join(repoRoot, "policy", "profiles", tc.profile, "extension_policy.toml")
		pol, err := loadExtensionPolicy(policyPath)
		if err != nil {
			t.Fatalf("loadExtensionPolicy(%s): %v", policyPath, err)
		}
		for _, name := range []string{"doc.pdf", "doc.docx", "sheet.xlsx", "slide.pptx"} {
			mode, reason := resolveExtensionMode(name, pol)
			if mode != ExtModeScanRebuild {
				t.Fatalf("profile=%s file=%s mode=%s reason=%s, want %s", tc.profile, name, mode, reason, ExtModeScanRebuild)
			}
		}
	}
}
