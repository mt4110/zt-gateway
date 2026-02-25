package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestShareJSONToVerifyToReceipt_AuditVerifyE2EContract(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(80 + i)
	}
	t.Setenv("ZT_AUDIT_SIGNING_ED25519_PRIV_B64", base64.StdEncoding.EncodeToString(seed))
	t.Setenv("ZT_AUDIT_SIGNING_KEY_ID", "audit-e2e-key")

	repoRoot := setupContractRepoFixture(t)
	installFlowContractGoStub(t, repoRoot)

	inputPath := filepath.Join(repoRoot, "safe.txt")
	if err := os.WriteFile(inputPath, []byte("safe-content"), 0o644); err != nil {
		t.Fatal(err)
	}

	prevEvents := cpEvents
	cpEvents = newEventSpool(repoRoot)
	cpEvents.SetAutoSync(false)
	defer func() { cpEvents = prevEvents }()

	prevWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(repoRoot); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(prevWD) }()

	adapters := newToolAdapters(repoRoot)
	sendOut := captureStdout(t, func() {
		runSend(adapters, sendOptions{
			InputFile:   inputPath,
			Client:      "clientA",
			ShareJSON:   true,
			ShareFormat: "en",
		})
	})
	share, err := extractReceiverSharePayload(sendOut)
	if err != nil {
		t.Fatalf("extractReceiverSharePayload: %v\n--- send output ---\n%s", err, sendOut)
	}
	verifyArgsFromShare, err := parseVerifyArgsFromShareCommand(share.Command)
	if err != nil {
		t.Fatalf("parseVerifyArgsFromShareCommand returned error: %v", err)
	}
	receiptOut := filepath.Join(repoRoot, "receipt", "verify.json")
	verifyArgs := append([]string{"--receipt-out", receiptOut}, verifyArgsFromShare...)
	opts, err := parseVerifyArgs(verifyArgs)
	if err != nil {
		t.Fatalf("parseVerifyArgs returned error: %v (args=%v)", err, verifyArgs)
	}
	verifyOut := captureStdout(t, func() { runVerify(adapters, opts) })
	if !strings.Contains(verifyOut, "[VERIFIED] Trust established.") {
		t.Fatalf("missing verified marker:\n%s", verifyOut)
	}

	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if err := verifyAuditEventsFile(cpEvents.auditPath(), auditVerifyOptions{
		RequireSignature: true,
		PublicKey:        pub,
	}); err != nil {
		t.Fatalf("verifyAuditEventsFile(require signature): %v", err)
	}
}

func TestAuditVerifyE2EContract_DetectsTamper(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(33 + i)
	}
	t.Setenv("ZT_AUDIT_SIGNING_ED25519_PRIV_B64", base64.StdEncoding.EncodeToString(seed))
	t.Setenv("ZT_AUDIT_SIGNING_KEY_ID", "audit-e2e-tamper-key")

	repoRoot := t.TempDir()
	spool := newEventSpool(repoRoot)
	spool.SetAutoSync(false)

	if err := spool.appendAuditEvent("/v1/events/scan", map[string]any{
		"event_id": "evt_tamper_1",
		"command":  "send",
		"result":   "allow",
	}); err != nil {
		t.Fatalf("appendAuditEvent(1): %v", err)
	}
	if err := spool.appendAuditEvent("/v1/events/verify", map[string]any{
		"event_id": "evt_tamper_2",
		"result":   "verified",
	}); err != nil {
		t.Fatalf("appendAuditEvent(2): %v", err)
	}

	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if err := verifyAuditEventsFile(spool.auditPath(), auditVerifyOptions{
		RequireSignature: true,
		PublicKey:        pub,
	}); err != nil {
		t.Fatalf("verify before tamper failed: %v", err)
	}

	if err := tamperAuditFirstRecordResult(spool.auditPath(), "tampered"); err != nil {
		t.Fatalf("tamperAuditFirstRecordResult: %v", err)
	}
	if err := verifyAuditEventsFile(spool.auditPath(), auditVerifyOptions{
		RequireSignature: true,
		PublicKey:        pub,
	}); err == nil {
		t.Fatalf("verifyAuditEventsFile after tamper returned nil, want error")
	}
}

func tamperAuditFirstRecordResult(path string, newResult string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return fmt.Errorf("audit log is empty")
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &payload); err != nil {
		return err
	}
	payload["result"] = newResult
	mutated, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	lines[0] = string(bytes.TrimSpace(mutated))
	data := strings.Join(lines, "\n") + "\n"
	return os.WriteFile(path, []byte(data), 0o644)
}
