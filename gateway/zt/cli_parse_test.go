package main

import "testing"

func TestParseSendArgs_DefaultShareFormatAuto(t *testing.T) {
	opts, err := parseSendArgs([]string{"--client", "alice", "sample.txt"})
	if err != nil {
		t.Fatalf("parseSendArgs returned error: %v", err)
	}
	if opts.ShareFormat != "auto" {
		t.Fatalf("ShareFormat = %q, want auto", opts.ShareFormat)
	}
	if opts.Profile != trustProfileInternal {
		t.Fatalf("Profile = %q, want %s", opts.Profile, trustProfileInternal)
	}
}

func TestParseSendArgs_EmptyShareFormatFallsBackToAuto(t *testing.T) {
	opts, err := parseSendArgs([]string{"--client", "alice", "--share-format", "", "sample.txt"})
	if err != nil {
		t.Fatalf("parseSendArgs returned error: %v", err)
	}
	if opts.ShareFormat != "auto" {
		t.Fatalf("ShareFormat = %q, want auto", opts.ShareFormat)
	}
}

func TestParseSendArgs_InvalidShareFormat(t *testing.T) {
	_, err := parseSendArgs([]string{"--client", "alice", "--share-format", "fr", "sample.txt"})
	if err == nil {
		t.Fatalf("expected error for invalid share-format")
	}
}

func TestParseSendArgs_InvalidProfile(t *testing.T) {
	_, err := parseSendArgs([]string{"--client", "alice", "--profile", "partner", "sample.txt"})
	if err == nil {
		t.Fatalf("expected error for invalid profile")
	}
}

func TestParseSendArgs_StrictProfileRejectsAllowDegraded(t *testing.T) {
	_, err := parseSendArgs([]string{"--client", "alice", "--profile", trustProfileRegulated, "--allow-degraded-scan", "sample.txt"})
	if err == nil {
		t.Fatalf("expected error for strict profile + allow-degraded")
	}
}

func TestParseSendArgs_ShareRoutes(t *testing.T) {
	opts, err := parseSendArgs([]string{
		"--share-route", "none",
		"--share-route", "clipboard",
		"--share-route", "file:/tmp/share.txt",
		"--share-route", "command-file:/tmp/verify.sh",
		"--share-json",
		"--client", "alice",
		"sample.txt",
	})
	if err != nil {
		t.Fatalf("parseSendArgs returned error: %v", err)
	}
	if len(opts.ShareRoutes) != 4 {
		t.Fatalf("ShareRoutes len = %d, want 4", len(opts.ShareRoutes))
	}
	if !opts.ShareJSON {
		t.Fatalf("ShareJSON = false, want true")
	}
}

func TestParseSendArgs_InvalidShareRoute(t *testing.T) {
	_, err := parseSendArgs([]string{"--client", "alice", "--share-route", "s3", "sample.txt"})
	if err == nil {
		t.Fatalf("expected error for invalid share-route")
	}
}

func TestParseSendArgs_RequiresClientOrExplicitLegacyFlag(t *testing.T) {
	_, err := parseSendArgs([]string{"sample.txt"})
	if err == nil {
		t.Fatalf("expected error when --client is not specified")
	}
}

func TestParseSendArgs_WithClientDoesNotRequireLegacyFlag(t *testing.T) {
	opts, err := parseSendArgs([]string{"--client", "alice", "sample.txt"})
	if err != nil {
		t.Fatalf("parseSendArgs returned error: %v", err)
	}
	if opts.Client != "alice" {
		t.Fatalf("Client = %q, want alice", opts.Client)
	}
}

func TestParseSendArgs_AllowDegradedScan(t *testing.T) {
	opts, err := parseSendArgs([]string{"--client", "alice", "--allow-degraded-scan", "sample.txt"})
	if err != nil {
		t.Fatalf("parseSendArgs returned error: %v", err)
	}
	if !opts.AllowDegradedScan {
		t.Fatalf("AllowDegradedScan = false, want true")
	}
}

func TestParseSendArgs_StrictAndAllowDegradedConflict(t *testing.T) {
	_, err := parseSendArgs([]string{"--client", "alice", "--strict", "--allow-degraded-scan", "sample.txt"})
	if err == nil {
		t.Fatalf("expected conflict error for --strict and --allow-degraded-scan")
	}
}

func TestParseVerifyArgs_PacketPath(t *testing.T) {
	opts, err := parseVerifyArgs([]string{"bundle.spkg.tgz"})
	if err != nil {
		t.Fatalf("parseVerifyArgs returned error: %v", err)
	}
	if opts.ArtifactPath != "bundle.spkg.tgz" {
		t.Fatalf("ArtifactPath = %q, want bundle.spkg.tgz", opts.ArtifactPath)
	}
	if opts.ReceiptOut != "" {
		t.Fatalf("ReceiptOut = %q, want empty", opts.ReceiptOut)
	}
}

func TestParseVerifyArgs_WithReceiptOut(t *testing.T) {
	opts, err := parseVerifyArgs([]string{"--receipt-out", "/tmp/receipt.json", "bundle.spkg.tgz"})
	if err != nil {
		t.Fatalf("parseVerifyArgs returned error: %v", err)
	}
	if opts.ArtifactPath != "bundle.spkg.tgz" {
		t.Fatalf("ArtifactPath = %q, want bundle.spkg.tgz", opts.ArtifactPath)
	}
	if opts.ReceiptOut != "/tmp/receipt.json" {
		t.Fatalf("ReceiptOut = %q, want /tmp/receipt.json", opts.ReceiptOut)
	}
}

func TestParseSetupArgs_WithProfile(t *testing.T) {
	opts, err := parseSetupArgs([]string{"--json", "--profile", trustProfileConfidential})
	if err != nil {
		t.Fatalf("parseSetupArgs returned error: %v", err)
	}
	if !opts.JSON {
		t.Fatalf("JSON = false, want true")
	}
	if opts.Profile != trustProfileConfidential {
		t.Fatalf("Profile = %q, want %q", opts.Profile, trustProfileConfidential)
	}
}

func TestParseSyncArgs_JSON(t *testing.T) {
	opts, err := parseSyncArgs([]string{"--force", "--json"})
	if err != nil {
		t.Fatalf("parseSyncArgs returned error: %v", err)
	}
	if !opts.Force {
		t.Fatalf("Force = false, want true")
	}
	if !opts.JSON {
		t.Fatalf("JSON = false, want true")
	}
}
