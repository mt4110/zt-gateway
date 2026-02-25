package main

import (
	"bytes"
	"encoding/json"
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

func TestRenderReceiverShareJSON_Contract(t *testing.T) {
	msg, ok := buildReceiverShareMessage("bundle.spkg.tgz", "en")
	if !ok {
		t.Fatalf("buildReceiverShareMessage returned ok=false")
	}
	raw := renderReceiverShareJSON(msg)
	if !strings.HasSuffix(raw, "\n") {
		t.Fatalf("JSON payload should end with newline: %q", raw)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &got); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("top-level keys = %d, want 5", len(got))
	}
	if got["kind"] != "receiver_verify_hint" {
		t.Fatalf("kind = %v", got["kind"])
	}
	if got["format"] != "en" {
		t.Fatalf("format = %v", got["format"])
	}
	if got["command"] != msg.Command {
		t.Fatalf("command = %v, want %q", got["command"], msg.Command)
	}
	wantText := "Please run the following command on the receiver side to verify the file.\n" + msg.Command + "\n"
	if got["text"] != wantText {
		t.Fatalf("text = %q, want %q", got["text"], wantText)
	}
	receiptHint, ok := got["receipt_hint"].(map[string]any)
	if !ok {
		t.Fatalf("receipt_hint missing or invalid: %#v", got["receipt_hint"])
	}
	if receiptHint["version"] != "v1" {
		t.Fatalf("receipt_hint.version = %v, want v1", receiptHint["version"])
	}
	if receiptHint["path"] != "./receipt_bundle.json" {
		t.Fatalf("receipt_hint.path = %v, want ./receipt_bundle.json", receiptHint["path"])
	}
	command, ok := receiptHint["command"].(string)
	if !ok {
		t.Fatalf("receipt_hint.command type = %T", receiptHint["command"])
	}
	if !strings.Contains(command, "--receipt-out") {
		t.Fatalf("receipt_hint.command missing --receipt-out: %v", receiptHint["command"])
	}
}

func TestStdoutShareTransport_TextContract(t *testing.T) {
	var out bytes.Buffer
	msg := receiverShareMessage{
		Command: "zt verify -- './bundle.spkg.tgz'",
		Format:  "ja",
	}
	if err := (stdoutShareTransport{w: &out, jsonMode: false}).Deliver(msg); err != nil {
		t.Fatalf("Deliver returned error: %v", err)
	}
	want := "[SHARE TEXT]\n受信側で次のコマンドを実行して検証してください。\nzt verify -- './bundle.spkg.tgz'\n[SHARE] Receiver command example: zt verify -- './bundle.spkg.tgz'\n"
	if out.String() != want {
		t.Fatalf("stdout text contract mismatch\n--- got ---\n%s--- want ---\n%s", out.String(), want)
	}
}

func TestStdoutShareTransport_JSONContract(t *testing.T) {
	var out bytes.Buffer
	msg, ok := buildReceiverShareMessage("bundle.spkg.tgz", "ja")
	if !ok {
		t.Fatalf("buildReceiverShareMessage returned ok=false")
	}
	if err := (stdoutShareTransport{w: &out, jsonMode: true}).Deliver(msg); err != nil {
		t.Fatalf("Deliver returned error: %v", err)
	}
	got := out.String()
	if strings.Contains(got, "[SHARE") {
		t.Fatalf("json mode must not emit share text markers: %q", got)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(got)), &payload); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}
	if payload["kind"] != "receiver_verify_hint" {
		t.Fatalf("kind = %v", payload["kind"])
	}
	if _, ok := payload["receipt_hint"].(map[string]any); !ok {
		t.Fatalf("receipt_hint missing: %#v", payload["receipt_hint"])
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
	msg, ok := buildReceiverShareMessage("bundle.spkg.tgz", "en")
	if !ok {
		t.Fatalf("buildReceiverShareMessage returned ok=false")
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
	if !strings.Contains(s, `"receipt_hint":{"version":"v1","path":"./receipt_bundle.json","command":"zt verify --receipt-out './receipt_bundle.json' -- './bundle.spkg.tgz'"`) {
		t.Fatalf("missing receipt_hint: %q", s)
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
