package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type receiverSharePayload struct {
	Kind             string                        `json:"kind"`
	Format           string                        `json:"format"`
	Command          string                        `json:"command"`
	Text             string                        `json:"text"`
	ReceiptHint      receiverShareReceiptHint      `json:"receipt_hint"`
	ChannelTemplates receiverShareChannelTemplates `json:"channel_templates"`
}

func TestShareJSONToVerifyToReceipt_E2EContract(t *testing.T) {
	const packetBase = "bundle_clientA_20260225T000000Z.spkg.tgz"
	repoRoot := setupContractRepoFixture(t)
	installFlowContractGoStub(t, repoRoot)

	inputPath := filepath.Join(repoRoot, "safe.txt")
	if err := os.WriteFile(inputPath, []byte("safe-content"), 0o644); err != nil {
		t.Fatal(err)
	}

	prevEvents := cpEvents
	cpEvents = nil
	defer func() { cpEvents = prevEvents }()

	prevWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(repoRoot); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(prevWD) }()

	if ok, fixes := runSendSecurePackPrecheck(repoRoot); !ok {
		t.Fatalf("send precheck failed in fixture: %#v", fixes)
	}
	if err := enforceFileTypeConsistency(inputPath); err != nil {
		t.Fatalf("fixture input rejected by file type guard: %v", err)
	}
	if _, err := loadExtensionPolicy(filepath.Join(repoRoot, "policy", "extension_policy.toml")); err != nil {
		t.Fatalf("loadExtensionPolicy failed in fixture: %v", err)
	}
	if _, err := loadScanPolicy(filepath.Join(repoRoot, "policy", "scan_policy.toml")); err != nil {
		t.Fatalf("loadScanPolicy failed in fixture: %v", err)
	}
	adapters := newToolAdapters(repoRoot)
	scanOut, scanStderr, scanErr := adapters.modernScanCheckJSON(inputPath, false, false, true, nil, false)
	if scanErr != nil {
		t.Fatalf("modernScanCheckJSON failed in fixture: %v (stdout=%s stderr=%s)", scanErr, string(scanOut), string(scanStderr))
	}
	var scanResult ScanResult
	if err := json.Unmarshal(scanOut, &scanResult); err != nil {
		t.Fatalf("scan JSON unmarshal failed in fixture: %v\n%s", err, string(scanOut))
	}
	if scanResult.Result != "allow" {
		t.Fatalf("scan fixture result=%q, want allow", scanResult.Result)
	}
	packedPath, packOut, packErr := adapters.modernPackSingleFile(inputPath, repoRoot, "clientA")
	if packErr != nil {
		t.Fatalf("modernPackSingleFile failed in fixture: %v (out=%s)", packErr, string(packOut))
	}
	if filepath.Base(packedPath) != packetBase {
		t.Fatalf("fixture packet base=%q, want %q", filepath.Base(packedPath), packetBase)
	}
	_ = os.Remove(packedPath)

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
	if share.Kind != "receiver_verify_hint" {
		t.Fatalf("kind = %q", share.Kind)
	}
	if share.Command == "" {
		t.Fatalf("share command is empty")
	}
	if share.ReceiptHint.Version != "v1" {
		t.Fatalf("receipt_hint.version = %q, want v1", share.ReceiptHint.Version)
	}
	if strings.TrimSpace(share.ReceiptHint.Path) == "" {
		t.Fatalf("receipt_hint.path is empty")
	}
	if strings.TrimSpace(share.ReceiptHint.Command) == "" {
		t.Fatalf("receipt_hint.command is empty")
	}
	if share.ChannelTemplates.Version != "v1" {
		t.Fatalf("channel_templates.version = %q, want v1", share.ChannelTemplates.Version)
	}
	if strings.TrimSpace(share.ChannelTemplates.SlackText) == "" {
		t.Fatalf("channel_templates.slack_text is empty")
	}
	if strings.TrimSpace(share.ChannelTemplates.EmailSubject) == "" {
		t.Fatalf("channel_templates.email_subject is empty")
	}
	if strings.TrimSpace(share.ChannelTemplates.EmailBody) == "" {
		t.Fatalf("channel_templates.email_body is empty")
	}
	if !strings.Contains(share.ChannelTemplates.SlackText, share.Command) {
		t.Fatalf("channel_templates.slack_text does not include share command: %q", share.ChannelTemplates.SlackText)
	}
	if !strings.Contains(share.ChannelTemplates.SlackText, share.ReceiptHint.Command) {
		t.Fatalf("channel_templates.slack_text does not include receipt command: %q", share.ChannelTemplates.SlackText)
	}
	if !strings.Contains(share.ChannelTemplates.EmailBody, share.Command) {
		t.Fatalf("channel_templates.email_body does not include share command: %q", share.ChannelTemplates.EmailBody)
	}
	if !strings.Contains(share.ChannelTemplates.EmailBody, share.ReceiptHint.Command) {
		t.Fatalf("channel_templates.email_body does not include receipt command: %q", share.ChannelTemplates.EmailBody)
	}
	wantReceiptCommand := fmt.Sprintf("zt verify --receipt-out %s -- %s", shellQuotePOSIX(share.ReceiptHint.Path), strings.TrimSpace(strings.TrimPrefix(share.Command, "zt verify --")))
	if share.ReceiptHint.Command != wantReceiptCommand {
		t.Fatalf("receipt_hint.command = %q, want %q", share.ReceiptHint.Command, wantReceiptCommand)
	}

	verifyArgsFromShare, err := parseVerifyArgsFromShareCommand(share.Command)
	if err != nil {
		t.Fatalf("parseVerifyArgsFromShareCommand returned error: %v", err)
	}
	receiptOut := filepath.Join(repoRoot, strings.TrimPrefix(share.ReceiptHint.Path, "./"))
	verifyArgs := append([]string{"--receipt-out", receiptOut}, verifyArgsFromShare...)
	opts, err := parseVerifyArgs(verifyArgs)
	if err != nil {
		t.Fatalf("parseVerifyArgs returned error: %v (args=%v)", err, verifyArgs)
	}

	out := captureStdout(t, func() {
		runVerify(adapters, opts)
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
	if receipt.Provenance.KeyFingerprint != "0123456789ABCDEF0123456789ABCDEF01234567" {
		t.Fatalf("Provenance.KeyFingerprint = %q", receipt.Provenance.KeyFingerprint)
	}
}

func installFlowContractGoStub(t *testing.T, repoRoot string) {
	t.Helper()
	path := filepath.Join(repoRoot, "bin", "go")
	stub := `#!/bin/sh
set -eu
if [ "${1:-}" = "run" ] && [ "${2:-}" = "./tools/secure-scan/cmd/secure-scan" ]; then
  if [ -n "${ZT_TEST_SCAN_JSON:-}" ]; then
    printf '%s\n' "${ZT_TEST_SCAN_JSON}"
  else
    echo '{"result":"allow","reason":"clean","rule_hash":"flow-contract-rule"}'
  fi
  exit 0
fi
if [ "${1:-}" = "run" ] && [ "${3:-}" = "verify" ]; then
  echo "SIGNER_FINGERPRINT=0123456789ABCDEF0123456789ABCDEF01234567"
  echo "secure-pack verify ok"
  exit 0
fi
if [ "${1:-}" = "build" ]; then
  out=""
  shift
  while [ "$#" -gt 0 ]; do
    if [ "$1" = "-o" ] && [ "$#" -ge 2 ]; then
      out="$2"
      shift 2
      continue
    fi
    shift
  done
  if [ "$out" = "" ]; then
    echo "missing -o output path" >&2
    exit 1
  fi
  cat > "$out" <<'EOS'
#!/bin/sh
set -eu
if [ "${1:-}" = "send" ] && [ "${2:-}" = "--client" ] && [ -n "${3:-}" ]; then
  mkdir -p dist
  packet="dist/bundle_${3}_20260225T000000Z.spkg.tgz"
  printf "packet" > "${packet}"
  echo "secure-pack send ok"
  exit 0
fi
echo "unsupported secure-pack command: $*" >&2
exit 1
EOS
  chmod +x "$out"
  exit 0
fi
echo "unsupported go invocation: $*" >&2
exit 1
`
	if err := os.WriteFile(path, []byte(stub), 0o755); err != nil {
		t.Fatalf("WriteFile go stub: %v", err)
	}
}

func extractReceiverSharePayload(output string) (receiverSharePayload, error) {
	var share receiverSharePayload
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") || !strings.Contains(line, `"kind":"receiver_verify_hint"`) {
			continue
		}
		if err := json.Unmarshal([]byte(line), &share); err != nil {
			return share, err
		}
		return share, nil
	}
	return share, fmt.Errorf("receiver share JSON not found")
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
