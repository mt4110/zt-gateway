package main

import (
	"path/filepath"
	"testing"
)

func TestValidateTrustProfile(t *testing.T) {
	got, err := validateTrustProfile("CONFIDENTIAL")
	if err != nil {
		t.Fatalf("validateTrustProfile returned error: %v", err)
	}
	if got != trustProfileConfidential {
		t.Fatalf("got = %q, want %q", got, trustProfileConfidential)
	}
}

func TestResolveTrustProfilePolicySelection_Internal(t *testing.T) {
	repoRoot := t.TempDir()
	got, err := resolveTrustProfilePolicySelection(repoRoot, trustProfileInternal)
	if err != nil {
		t.Fatalf("resolveTrustProfilePolicySelection returned error: %v", err)
	}
	if got.Source != "policy/default" {
		t.Fatalf("Source = %q", got.Source)
	}
	if got.ExtensionPolicyPath != filepath.Join(repoRoot, "policy", "extension_policy.toml") {
		t.Fatalf("ExtensionPolicyPath = %q", got.ExtensionPolicyPath)
	}
	if got.ScanPolicyPath != filepath.Join(repoRoot, "policy", "scan_policy.toml") {
		t.Fatalf("ScanPolicyPath = %q", got.ScanPolicyPath)
	}
}

func TestResolveTrustProfilePolicySelection_NonInternalMissingFails(t *testing.T) {
	repoRoot := t.TempDir()
	if _, err := resolveTrustProfilePolicySelection(repoRoot, trustProfilePublic); err == nil {
		t.Fatalf("expected error when public profile policy files are missing")
	}
}
