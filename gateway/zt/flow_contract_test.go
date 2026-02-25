package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestShareJSONToVerifyToReceipt_E2EContract(t *testing.T) {
	tmp := t.TempDir()
	packetBase := "bundle_clientA_20260225T000000Z.spkg.tgz"
	packetPath := filepath.Join(tmp, packetBase)
	if err := os.WriteFile(packetPath, []byte("packet"), 0o644); err != nil {
		t.Fatal(err)
	}

	msg, ok := buildReceiverShareMessage(packetPath, "en")
	if !ok {
		t.Fatalf("buildReceiverShareMessage returned ok=false")
	}
	shareJSON := renderReceiverShareJSON(msg)
	var share struct {
		Kind    string `json:"kind"`
		Format  string `json:"format"`
		Command string `json:"command"`
		Text    string `json:"text"`
	}
	if err := json.Unmarshal([]byte(shareJSON), &share); err != nil {
		t.Fatalf("json.Unmarshal share JSON failed: %v\n%s", err, shareJSON)
	}
	if share.Kind != "receiver_verify_hint" {
		t.Fatalf("kind = %q", share.Kind)
	}
	if share.Command == "" {
		t.Fatalf("share command is empty")
	}

	verifyArgsFromShare, err := parseVerifyArgsFromShareCommand(share.Command)
	if err != nil {
		t.Fatalf("parseVerifyArgsFromShareCommand returned error: %v", err)
	}
	receiptOut := filepath.Join(tmp, "receipt", "verify.json")
	verifyArgs := append([]string{"--receipt-out", receiptOut}, verifyArgsFromShare...)
	opts, err := parseVerifyArgs(verifyArgs)
	if err != nil {
		t.Fatalf("parseVerifyArgs returned error: %v (args=%v)", err, verifyArgs)
	}

	binDir := filepath.Join(tmp, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "go"), []byte("#!/bin/sh\necho \"secure-pack verify ok\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir)

	prevEvents := cpEvents
	cpEvents = nil
	defer func() { cpEvents = prevEvents }()

	prevWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(prevWD) }()

	out := captureStdout(t, func() {
		runVerify(&toolAdapters{repoRoot: t.TempDir()}, opts)
	})
	if !strings.Contains(out, "[VERIFIED] Trust established.") {
		t.Fatalf("missing verified marker:\n%s", out)
	}
	if !strings.Contains(out, "TRUST: verified=true tamper=false policy=pass receipt=") {
		t.Fatalf("missing trust status line:\n%s", out)
	}

	receiptBytes, err := os.ReadFile(receiptOut)
	if err != nil {
		t.Fatalf("failed to read receipt: %v", err)
	}
	var receipt verificationReceipt
	if err := json.Unmarshal(receiptBytes, &receipt); err != nil {
		t.Fatalf("json.Unmarshal receipt failed: %v\n%s", err, receiptBytes)
	}
	if receipt.ReceiptVersion != "v1" {
		t.Fatalf("ReceiptVersion = %q, want v1", receipt.ReceiptVersion)
	}
	if filepath.Base(receipt.Artifact.Path) != packetBase {
		t.Fatalf("Artifact.Path = %q, want base %q", receipt.Artifact.Path, packetBase)
	}
	if receipt.Provenance.Client != "clientA" {
		t.Fatalf("Provenance.Client = %q, want clientA", receipt.Provenance.Client)
	}
}

func parseVerifyArgsFromShareCommand(command string) ([]string, error) {
	command = strings.TrimSpace(command)
	const prefix = "zt verify -- "
	if !strings.HasPrefix(command, prefix) {
		return nil, fmt.Errorf("unsupported command prefix: %q", command)
	}
	rawArg := strings.TrimSpace(strings.TrimPrefix(command, prefix))
	if len(rawArg) < 2 || rawArg[0] != '\'' || rawArg[len(rawArg)-1] != '\'' {
		return nil, fmt.Errorf("unsupported quoted arg: %q", rawArg)
	}
	pathArg := rawArg[1 : len(rawArg)-1]
	pathArg = strings.ReplaceAll(pathArg, `'"'"'`, "'")
	if strings.TrimSpace(pathArg) == "" {
		return nil, fmt.Errorf("empty artifact path in command")
	}
	return []string{"--", pathArg}, nil
}
