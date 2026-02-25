package main

import (
	"io"
	"os"
	"strings"
	"testing"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()
	fn()
	_ = w.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	return string(out)
}

func TestPrintUsage_Contract(t *testing.T) {
	out := captureStdout(t, printUsage)
	wants := []string{
		cliUsageRoot,
		"  setup                       - Check local config/tools/key env/control-plane reachability",
		"  send --client <name> <file> - Scan -> sanitize -> pack",
		"  verify <packet.spkg.tgz>    - Verify received packet",
		"  doctor                      - Validate local config resolution",
		"  zt --help-advanced          - Show all commands/flags",
	}
	for _, want := range wants {
		if !strings.Contains(out, want) {
			t.Fatalf("printUsage output missing %q\n---\n%s", want, out)
		}
	}
}

func TestPrintAdvancedUsage_Contract(t *testing.T) {
	out := captureStdout(t, printAdvancedUsage)
	wants := []string{
		cliUsageRoot,
		"  " + cliSetupSignature + " - One-command local setup checks",
		"  " + cliSendSignature + " - Scan, sanitize and package a file",
		"  " + cliScanSignature + " - Risk assessment",
		"  " + cliVerifySignature + " - Verify artifact or packet",
		"  " + cliSyncSignature + " - Retry sending locally spooled events",
		"  " + cliConfigSignature + " - Validate zt client config/env resolution",
		"  " + cliDoctorSignature + " - Alias of `zt config doctor`",
		"  " + cliHelpSignature + " - Show help",
	}
	for _, want := range wants {
		if !strings.Contains(out, want) {
			t.Fatalf("printAdvancedUsage output missing %q\n---\n%s", want, out)
		}
	}
}

func TestParseArgs_UsageContract(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{name: "setup", err: func() error { _, err := parseSetupArgs([]string{"extra"}); return err }(), want: cliSetupUsage},
		{name: "send", err: func() error { _, err := parseSendArgs([]string{"--client", "alice"}); return err }(), want: cliSendUsage},
		{name: "scan", err: func() error { _, err := parseScanArgs(nil); return err }(), want: cliScanUsage},
		{name: "verify", err: func() error { _, err := parseVerifyArgs(nil); return err }(), want: cliVerifyUsage},
		{name: "sync", err: func() error { _, err := parseSyncArgs([]string{"unexpected"}); return err }(), want: cliSyncUsage},
	}
	for _, tc := range cases {
		if tc.err == nil {
			t.Fatalf("%s: expected error", tc.name)
		}
		if tc.err.Error() != tc.want {
			t.Fatalf("%s: error = %q, want %q", tc.name, tc.err.Error(), tc.want)
		}
	}
}

func TestParseSendArgs_ClientRequiredContract(t *testing.T) {
	_, err := parseSendArgs([]string{"sample.txt"})
	if err == nil {
		t.Fatalf("expected error")
	}
	want := "zt send requires --client <name> (legacy artifact.zp path was removed)"
	if err.Error() != want {
		t.Fatalf("error = %q, want %q", err.Error(), want)
	}
}

func TestRunConfigCommand_UsageContract(t *testing.T) {
	_ = captureStdout(t, func() {
		err := runConfigCommand(t.TempDir(), nil)
		if err == nil {
			t.Fatalf("expected error")
		}
		if err.Error() != cliConfigUsage {
			t.Fatalf("error = %q, want %q", err.Error(), cliConfigUsage)
		}
	})
}
