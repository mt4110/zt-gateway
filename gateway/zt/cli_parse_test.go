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
}
