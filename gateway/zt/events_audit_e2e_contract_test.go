package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestShareJSONToVerifyToReceipt_AuditE2EContract(t *testing.T) {
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

	records := readAuditEventRecordsContract(t, cpEvents.auditPath())
	sendCount := 0
	verifyCount := 0
	for _, record := range records {
		assertAuditRequiredFieldsContract(t, record)
		switch record.EventType {
		case "send":
			sendCount++
			if record.Endpoint != "/v1/events/scan" {
				t.Fatalf("send endpoint = %q, want /v1/events/scan", record.Endpoint)
			}
		case "verify":
			verifyCount++
			if record.Endpoint != "/v1/events/verify" {
				t.Fatalf("verify endpoint = %q, want /v1/events/verify", record.Endpoint)
			}
		}
	}
	if sendCount != 1 {
		t.Fatalf("send event count = %d, want 1", sendCount)
	}
	if verifyCount != 1 {
		t.Fatalf("verify event count = %d, want 1", verifyCount)
	}
}
