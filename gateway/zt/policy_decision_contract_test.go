package main

import (
	"encoding/json"
	"fmt"
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

func TestScanPosture_ProfileContract(t *testing.T) {
	repoRoot := setupContractRepoFixture(t)
	installFlowContractGoStub(t, repoRoot)
	t.Setenv("ZT_TEST_SCAN_JSON", `{"result":"allow","reason":"clean.no_scanners_available","rule_hash":"flow-contract-rule"}`)

	inputPath := filepath.Join(repoRoot, "safe.txt")
	if err := os.WriteFile(inputPath, []byte("safe-content"), 0o644); err != nil {
		t.Fatal(err)
	}

	profileDir := filepath.Join(repoRoot, "policy", "profiles", trustProfilePublic)
	if err := os.MkdirAll(profileDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profileDir, "extension_policy.toml"), []byte("scan_only_extensions=[\".txt\"]\nmax_size_mb=50\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profileDir, "scan_policy.toml"), []byte("required_scanners=[\"ClamAV\",\"YARA\"]\nrequire_clamav_db=true\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	prevEvents := cpEvents
	cpEvents = nil
	defer func() { cpEvents = prevEvents }()

	adapters := newToolAdapters(repoRoot)
	prevWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(repoRoot); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(prevWD) }()

	sendOut := captureStdout(t, func() {
		runSend(adapters, sendOptions{
			InputFile:         inputPath,
			Client:            "clientA",
			Profile:           trustProfilePublic,
			AllowDegradedScan: true,
			ShareJSON:         true,
			ShareFormat:       "en",
		})
	})
	if !strings.Contains(sendOut, "[SUCCESS] Packet generated.") {
		t.Fatalf("send did not complete successfully:\n%s", sendOut)
	}
	dec, err := extractPolicyDecisionFromOutput(sendOut)
	if err != nil {
		t.Fatalf("extractPolicyDecisionFromOutput: %v\n%s", err, sendOut)
	}
	if dec.Decision != policyDecisionDegraded {
		t.Fatalf("decision = %q, want degraded", dec.Decision)
	}
	if dec.ReasonCode != "policy_scan_no_scanners_available" {
		t.Fatalf("reason_code = %q, want policy_scan_no_scanners_available", dec.ReasonCode)
	}
	if dec.ScanPosture == nil {
		t.Fatalf("scan_posture is nil")
	}
	if dec.ScanPosture.StrictEffective {
		t.Fatalf("scan_posture.strict_effective = true, want false")
	}
	if !dec.ScanPosture.AllowDegraded {
		t.Fatalf("scan_posture.allow_degraded_scan = false, want true")
	}
	if !dec.ScanPosture.RequireClamAVDB {
		t.Fatalf("scan_posture.require_clamav_db = false, want true")
	}
	if len(dec.ScanPosture.RequiredScanners) != 2 || dec.ScanPosture.RequiredScanners[0] != "ClamAV" || dec.ScanPosture.RequiredScanners[1] != "YARA" {
		t.Fatalf("scan_posture.required_scanners = %#v, want [ClamAV YARA]", dec.ScanPosture.RequiredScanners)
	}
}

func TestScanPosture_ViolationContract(t *testing.T) {
	repoRoot := setupContractRepoFixture(t)
	installFlowContractGoStub(t, repoRoot)
	t.Setenv("ZT_TEST_SCAN_JSON", `{"result":"allow","reason":"clean.no_scanners_available","rule_hash":"flow-contract-rule"}`)

	inputPath := filepath.Join(repoRoot, "safe.txt")
	if err := os.WriteFile(inputPath, []byte("safe-content"), 0o644); err != nil {
		t.Fatal(err)
	}

	prevEvents := cpEvents
	cpEvents = nil
	defer func() { cpEvents = prevEvents }()

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
		runScan(adapters, scanOptions{Target: inputPath, Strict: true})
	})
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("json.Unmarshal(scan output): %v\n%s", err, out)
	}
	pd, ok := got["policy_decision"].(map[string]any)
	if !ok {
		t.Fatalf("policy_decision missing in scan output: %#v", got)
	}
	if pd["decision"] != policyDecisionDeny {
		t.Fatalf("policy_decision.decision = %v, want deny", pd["decision"])
	}
	if pd["reason_code"] != "policy_scan_posture_violation" {
		t.Fatalf("policy_decision.reason_code = %v, want policy_scan_posture_violation", pd["reason_code"])
	}
	if pd["error_code"] != "policy_scan_posture_violation" {
		t.Fatalf("policy_decision.error_code = %v, want policy_scan_posture_violation", pd["error_code"])
	}
	posture, ok := pd["scan_posture"].(map[string]any)
	if !ok {
		t.Fatalf("scan_posture missing or invalid: %#v", pd["scan_posture"])
	}
	if gotStrict, _ := posture["strict_effective"].(bool); !gotStrict {
		t.Fatalf("scan_posture.strict_effective = %v, want true", posture["strict_effective"])
	}
	if gotAllow, _ := posture["allow_degraded_scan"].(bool); gotAllow {
		t.Fatalf("scan_posture.allow_degraded_scan = %v, want false", posture["allow_degraded_scan"])
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

func TestFileTypeGuard_JSONExplainabilityContract(t *testing.T) {
	runFileTypeGuardJSONExplainabilityContract(t)
}

func TestPolicyDecisionContract_FileTypeGuardExplainabilityContract(t *testing.T) {
	runFileTypeGuardJSONExplainabilityContract(t)
}

func runFileTypeGuardJSONExplainabilityContract(t *testing.T) {
	dec := decisionForSendPolicyBlockWithCause(
		trustProfileInternal,
		"local_internal_extension_policy_aaaaaaaaaaaaaaaa",
		"policy_magic_mismatch",
		fmt.Errorf("policy.magic_mismatch:expected_pdf (ext=.pdf detected=zip mime=application/zip)"),
	)
	dec = normalizePolicyDecision(dec)
	if dec.Decision != policyDecisionDeny {
		t.Fatalf("decision = %q, want deny", dec.Decision)
	}
	if dec.ReasonCode != "policy_magic_mismatch" {
		t.Fatalf("reason_code = %q, want policy_magic_mismatch", dec.ReasonCode)
	}
	if dec.FileTypeGuard == nil {
		t.Fatalf("file_type_guard is nil")
	}
	if dec.FileTypeGuard.Extension != ".pdf" {
		t.Fatalf("file_type_guard.extension = %q, want .pdf", dec.FileTypeGuard.Extension)
	}
	if dec.FileTypeGuard.DetectedKind != "zip" {
		t.Fatalf("file_type_guard.detected_kind = %q, want zip", dec.FileTypeGuard.DetectedKind)
	}
	if dec.FileTypeGuard.DetectedMIME != "application/zip" {
		t.Fatalf("file_type_guard.detected_mime = %q, want application/zip", dec.FileTypeGuard.DetectedMIME)
	}
	if dec.FileTypeGuard.ReasonCode != "expected_pdf" {
		t.Fatalf("file_type_guard.reason_code = %q, want expected_pdf", dec.FileTypeGuard.ReasonCode)
	}

	raw, err := json.Marshal(dec)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	ftg, ok := got["file_type_guard"].(map[string]any)
	if !ok {
		t.Fatalf("file_type_guard missing in JSON: %#v", got["file_type_guard"])
	}
	if gotReason, _ := ftg["reason_code"].(string); gotReason != "expected_pdf" {
		t.Fatalf("file_type_guard.reason_code(JSON) = %q, want expected_pdf", gotReason)
	}
}

func TestPolicyDecisionContract_FileTypeGuardIncludedInEventPayloadContract(t *testing.T) {
	repoRoot := t.TempDir()
	t.Setenv("ZT_EVENT_SIGNING_ED25519_PRIV_B64", "")
	prevEvents := cpEvents
	cpEvents = newEventSpool(repoRoot)
	cpEvents.SetAutoSync(false)
	cpEvents.SetControlPlaneURL("")
	defer func() { cpEvents = prevEvents }()

	artifact := filepath.Join(repoRoot, "sample.spkg.tgz")
	if err := os.WriteFile(artifact, []byte("packet"), 0o644); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}
	dec := normalizePolicyDecision(policyDecision{
		Decision:   policyDecisionDeny,
		ReasonCode: "policy_magic_mismatch",
		ManifestID: "local_internal_extension_policy_aaaaaaaaaaaaaaaa",
		Profile:    trustProfileInternal,
		RuleHash:   "none",
		ErrorClass: "fail_closed",
		ErrorCode:  "policy_verify_failed",
		FileTypeGuard: &fileTypeGuardSummary{
			Extension:    ".pdf",
			DetectedKind: "zip",
			DetectedMIME: "application/zip",
			ReasonCode:   "expected_pdf",
		},
	})

	emitVerifyEvent(artifact, false, "policy.blocked", "blocked by file type guard", dec)
	pending, err := readQueuedEvents(cpEvents.pendingPath())
	if err != nil {
		t.Fatalf("readQueuedEvents: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("pending len = %d, want 1", len(pending))
	}

	var payload map[string]any
	if err := json.Unmarshal(pending[0].Payload, &payload); err != nil {
		t.Fatalf("json.Unmarshal payload: %v", err)
	}
	pd, ok := payload["policy_decision"].(map[string]any)
	if !ok {
		t.Fatalf("policy_decision missing: %#v", payload["policy_decision"])
	}
	ftg, ok := pd["file_type_guard"].(map[string]any)
	if !ok {
		t.Fatalf("file_type_guard missing: %#v", pd["file_type_guard"])
	}
	if gotReason, _ := ftg["reason_code"].(string); gotReason != "expected_pdf" {
		t.Fatalf("file_type_guard.reason_code(payload) = %q, want expected_pdf", gotReason)
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
