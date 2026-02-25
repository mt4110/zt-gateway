package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicyDecisionContract_ScanCLIJSONIncludesPolicyDecision(t *testing.T) {
	repoRoot := setupContractRepoFixture(t)
	installFlowContractGoStub(t, repoRoot)
	inputPath := filepath.Join(repoRoot, "safe.txt")
	if err := os.WriteFile(inputPath, []byte("safe-content"), 0o644); err != nil {
		t.Fatal(err)
	}
	adapters := newToolAdapters(repoRoot)

	prevWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(repoRoot); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(prevWD) }()

	out := captureStdout(t, func() {
		runScan(adapters, scanOptions{Target: inputPath})
	})
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("json.Unmarshal(scan output): %v\n%s", err, out)
	}
	pd, ok := got["policy_decision"].(map[string]any)
	if !ok {
		t.Fatalf("policy_decision missing in scan output: %#v", got)
	}
	if pd["decision"] != policyDecisionAllow {
		t.Fatalf("policy_decision.decision = %v, want allow", pd["decision"])
	}
	if pd["reason_code"] != "policy_scan_clean" {
		t.Fatalf("policy_decision.reason_code = %v, want policy_scan_clean", pd["reason_code"])
	}
}

func TestPolicyDecisionContract_CLIReceiptAuditConsistency(t *testing.T) {
	repoRoot := setupContractRepoFixture(t)
	installFlowContractGoStub(t, repoRoot)
	inputPath := filepath.Join(repoRoot, "safe.txt")
	if err := os.WriteFile(inputPath, []byte("safe-content"), 0o644); err != nil {
		t.Fatal(err)
	}

	prevEvents := cpEvents
	cpEvents = newEventSpool(repoRoot)
	cpEvents.SetAutoSync(false)
	cpEvents.SetControlPlaneURL("")
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
		runSend(adapters, sendOptions{InputFile: inputPath, Client: "clientA", ShareJSON: true, ShareFormat: "en"})
	})
	share, err := extractReceiverSharePayload(sendOut)
	if err != nil {
		t.Fatalf("extractReceiverSharePayload: %v\n%s", err, sendOut)
	}
	verifyArgsFromShare, err := parseVerifyArgsFromShareCommand(share.Command)
	if err != nil {
		t.Fatalf("parseVerifyArgsFromShareCommand: %v", err)
	}
	receiptOut := filepath.Join(repoRoot, "receipt", "verify-policy-decision.json")
	verifyArgs := append([]string{"--receipt-out", receiptOut}, verifyArgsFromShare...)
	opts, err := parseVerifyArgs(verifyArgs)
	if err != nil {
		t.Fatalf("parseVerifyArgs: %v", err)
	}

	verifyOut := captureStdout(t, func() {
		runVerify(adapters, opts)
	})
	cliDecision, err := extractPolicyDecisionFromOutput(verifyOut)
	if err != nil {
		t.Fatalf("extractPolicyDecisionFromOutput: %v\n%s", err, verifyOut)
	}

	receiptBytes, err := os.ReadFile(receiptOut)
	if err != nil {
		t.Fatalf("os.ReadFile(receipt): %v", err)
	}
	var receipt verificationReceipt
	if err := json.Unmarshal(receiptBytes, &receipt); err != nil {
		t.Fatalf("json.Unmarshal(receipt): %v", err)
	}
	if receipt.Verification.PolicyDecision.Decision != cliDecision.Decision {
		t.Fatalf("receipt decision=%q cli=%q", receipt.Verification.PolicyDecision.Decision, cliDecision.Decision)
	}
	if receipt.Verification.PolicyDecision.ReasonCode != cliDecision.ReasonCode {
		t.Fatalf("receipt reason=%q cli=%q", receipt.Verification.PolicyDecision.ReasonCode, cliDecision.ReasonCode)
	}

	records := readAuditEventRecordsWithDecisionContract(t, cpEvents.auditPath())
	if len(records) == 0 {
		t.Fatalf("audit records are empty")
	}
	last := records[len(records)-1]
	if last.PolicyDecision.Decision != cliDecision.Decision {
		t.Fatalf("audit decision=%q cli=%q", last.PolicyDecision.Decision, cliDecision.Decision)
	}
	if last.PolicyDecision.ReasonCode != cliDecision.ReasonCode {
		t.Fatalf("audit reason=%q cli=%q", last.PolicyDecision.ReasonCode, cliDecision.ReasonCode)
	}
}

type auditEventWithDecisionContract struct {
	EventType      string         `json:"event_type"`
	PolicyDecision policyDecision `json:"policy_decision"`
}

func readAuditEventRecordsWithDecisionContract(t *testing.T, path string) []auditEventWithDecisionContract {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("os.ReadFile(%s): %v", path, err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	out := make([]auditEventWithDecisionContract, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec auditEventWithDecisionContract
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("json.Unmarshal(audit): %v", err)
		}
		if rec.EventType == "verify" {
			out = append(out, rec)
		}
	}
	return out
}

func extractPolicyDecisionFromOutput(out string) (policyDecision, error) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "POLICY_DECISION: ") {
			continue
		}
		var dec policyDecision
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "POLICY_DECISION: ")), &dec); err != nil {
			return policyDecision{}, err
		}
		return normalizePolicyDecision(dec), nil
	}
	return policyDecision{}, os.ErrNotExist
}
