package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseShareRoute(t *testing.T) {
	cases := []struct {
		raw      string
		wantKind string
		wantPath string
		wantErr  bool
	}{
		{raw: "none", wantKind: "none"},
		{raw: "stdout", wantKind: "stdout"},
		{raw: "clipboard", wantKind: "clipboard"},
		{raw: "file:/tmp/share.txt", wantKind: "file", wantPath: "/tmp/share.txt"},
		{raw: "command-file:/tmp/verify.sh", wantKind: "command-file", wantPath: "/tmp/verify.sh"},
		{raw: "file:", wantErr: true},
		{raw: "command-file:", wantErr: true},
		{raw: "s3://bucket", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			got, err := parseShareRoute(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseShareRoute returned error: %v", err)
			}
			if got.Kind != tc.wantKind || got.Path != tc.wantPath {
				t.Fatalf("parseShareRoute(%q) = %#v", tc.raw, got)
			}
		})
	}
}

func TestBuildShareTransports_DefaultAndCopyCommand(t *testing.T) {
	var out bytes.Buffer
	opts := sendOptions{
		CopyCommand: true,
		ShareRoutes: []string{"stdout", "clipboard"},
	}
	transports, err := buildShareTransports(opts, &out)
	if err != nil {
		t.Fatalf("buildShareTransports returned error: %v", err)
	}
	if len(transports) != 2 {
		t.Fatalf("len(transports) = %d, want 2 (stdout + clipboard deduped)", len(transports))
	}
}

func TestBuildShareTransports_NoneSuppressesDefaultStdout(t *testing.T) {
	var out bytes.Buffer
	opts := sendOptions{
		ShareRoutes: []string{"none", "command-file:/tmp/verify.sh"},
	}
	transports, err := buildShareTransports(opts, &out)
	if err != nil {
		t.Fatalf("buildShareTransports returned error: %v", err)
	}
	if len(transports) != 1 {
		t.Fatalf("len(transports) = %d, want 1", len(transports))
	}
	if got := transports[0].Name(); got != "command-file:/tmp/verify.sh" {
		t.Fatalf("transport[0].Name() = %q", got)
	}
}

func TestRenderReceiverShareTextEnglish(t *testing.T) {
	msg := receiverShareMessage{
		Command: "zt verify -- './bundle.spkg.tgz'",
		Format:  "en",
	}
	got := renderReceiverShareText(msg)
	if !strings.Contains(got, "Please run the following command") {
		t.Fatalf("missing English lead: %q", got)
	}
	if !strings.Contains(got, msg.Command) {
		t.Fatalf("missing command in share text: %q", got)
	}
}

func TestFileShareTransportWritesLocalizedText(t *testing.T) {
	tmp := t.TempDir()
	outPath := filepath.Join(tmp, "share.txt")
	msg := receiverShareMessage{
		Command: "zt verify -- './bundle.spkg.tgz'",
		Format:  "ja",
	}
	if err := (fileShareTransport{path: outPath}).Deliver(msg); err != nil {
		t.Fatalf("Deliver returned error: %v", err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	s := string(data)
	if !strings.Contains(s, "受信側で次のコマンド") {
		t.Fatalf("missing Japanese lead: %q", s)
	}
	if !strings.Contains(s, msg.Command) {
		t.Fatalf("missing command: %q", s)
	}
}

func TestFileShareTransportWritesJSON(t *testing.T) {
	tmp := t.TempDir()
	outPath := filepath.Join(tmp, "share.json")
	msg := receiverShareMessage{
		Command: "zt verify -- './bundle.spkg.tgz'",
		Format:  "en",
	}
	if err := (fileShareTransport{path: outPath, jsonMode: true}).Deliver(msg); err != nil {
		t.Fatalf("Deliver returned error: %v", err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	s := string(data)
	if !strings.Contains(s, `"kind":"receiver_verify_hint"`) {
		t.Fatalf("missing JSON kind: %q", s)
	}
	if !strings.Contains(s, `"command":"zt verify -- './bundle.spkg.tgz'"`) {
		t.Fatalf("missing JSON command: %q", s)
	}
}

func TestCommandFileShareTransportWritesCommandOnly(t *testing.T) {
	tmp := t.TempDir()
	outPath := filepath.Join(tmp, "verify.sh")
	msg := receiverShareMessage{
		Command: "zt verify -- './bundle.spkg.tgz'",
		Format:  "ja",
	}
	if err := (commandFileShareTransport{path: outPath}).Deliver(msg); err != nil {
		t.Fatalf("Deliver returned error: %v", err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	if got := string(data); got != msg.Command+"\n" {
		t.Fatalf("command-file contents = %q, want %q", got, msg.Command+"\\n")
	}
}
