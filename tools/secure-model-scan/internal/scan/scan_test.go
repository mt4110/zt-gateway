package scan

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mt4110/zt-gateway/tools/secure-model-scan/internal/policy"
)

func TestScanGGUFAllow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "demo.gguf")
	if err := os.WriteFile(path, []byte("GGUFdemo"), 0644); err != nil {
		t.Fatal(err)
	}
	result, err := ScanPath(path, Options{Profile: policy.ProfileConfidential})
	if err != nil {
		t.Fatalf("ScanPath: %v", err)
	}
	if result.Result != policy.DecisionAllow {
		t.Fatalf("result=%s reason=%s", result.Result, result.Reason)
	}
	if result.ModelFormat != "gguf" {
		t.Fatalf("format=%q", result.ModelFormat)
	}
}

func TestScanPickleDeniedForConfidential(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "model.pt")
	if err := os.WriteFile(path, []byte("pickle-ish"), 0644); err != nil {
		t.Fatal(err)
	}
	result, err := ScanPath(path, Options{Profile: policy.ProfileConfidential})
	if err != nil {
		t.Fatalf("ScanPath: %v", err)
	}
	if result.Result != policy.DecisionDeny {
		t.Fatalf("result=%s, want deny", result.Result)
	}
}

func TestScanRenamedPickleDeniedForConfidential(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "model.gguf")
	if err := os.WriteFile(path, []byte("pickle-ish"), 0644); err != nil {
		t.Fatal(err)
	}
	result, err := ScanPath(path, Options{Profile: policy.ProfileConfidential})
	if err != nil {
		t.Fatalf("ScanPath: %v", err)
	}
	if result.Result != policy.DecisionDeny {
		t.Fatalf("result=%s reason=%s, want deny", result.Result, result.Reason)
	}
	if result.PolicyDecision.ReasonCode != "model_safe_format_unconfirmed" {
		t.Fatalf("reason_code=%s, want model_safe_format_unconfirmed", result.PolicyDecision.ReasonCode)
	}
	if len(result.Findings) == 0 || result.Findings[0].Category != "unconfirmed_safe_format" {
		t.Fatalf("findings=%+v, want unconfirmed_safe_format", result.Findings)
	}
}

func TestScanUnknownFormatDeniedForConfidential(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "weights.dat")
	if err := os.WriteFile(path, []byte("opaque"), 0644); err != nil {
		t.Fatal(err)
	}
	result, err := ScanPath(path, Options{Profile: policy.ProfileConfidential})
	if err != nil {
		t.Fatalf("ScanPath: %v", err)
	}
	if result.Result != policy.DecisionDeny {
		t.Fatalf("result=%s reason=%s, want deny", result.Result, result.Reason)
	}
	if result.PolicyDecision.ReasonCode != "model_unknown_format_denied" {
		t.Fatalf("reason_code=%s, want model_unknown_format_denied", result.PolicyDecision.ReasonCode)
	}
}

func TestScanDirectoryUnknownFileDeniedForConfidential(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "safe.gguf"), []byte("GGUFdemo"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "weights.dat"), []byte("opaque"), 0644); err != nil {
		t.Fatal(err)
	}
	result, err := ScanPath(dir, Options{Profile: policy.ProfileConfidential})
	if err != nil {
		t.Fatalf("ScanPath: %v", err)
	}
	if result.ModelFormat != "gguf" {
		t.Fatalf("model_format=%s, want dominant gguf", result.ModelFormat)
	}
	if result.Result != policy.DecisionDeny {
		t.Fatalf("result=%s reason=%s, want deny", result.Result, result.Reason)
	}
	if result.PolicyDecision.ReasonCode != "model_unknown_format_denied" {
		t.Fatalf("reason_code=%s, want model_unknown_format_denied", result.PolicyDecision.ReasonCode)
	}
}

func TestScanDirectoryDeniesUnsafeSerializationEvenWhenGGUFDominates(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "safe.gguf"), []byte("GGUFdemo"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "unsafe.pt"), []byte("pickle-ish"), 0644); err != nil {
		t.Fatal(err)
	}
	result, err := ScanPath(dir, Options{Profile: policy.ProfileConfidential})
	if err != nil {
		t.Fatalf("ScanPath: %v", err)
	}
	if result.ModelFormat != "gguf" {
		t.Fatalf("model_format=%s, want dominant gguf", result.ModelFormat)
	}
	if result.Result != policy.DecisionDeny {
		t.Fatalf("result=%s reason=%s, want deny", result.Result, result.Reason)
	}
}

func TestScanDirectoryDeniesSymlink(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.gguf")
	if err := os.WriteFile(outside, []byte("GGUFoutside"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "linked.gguf")); err != nil {
		t.Skipf("symlink not available: %v", err)
	}
	result, err := ScanPath(dir, Options{Profile: policy.ProfileConfidential})
	if err != nil {
		t.Fatalf("ScanPath: %v", err)
	}
	if result.Result != policy.DecisionDeny {
		t.Fatalf("result=%s reason=%s, want deny", result.Result, result.Reason)
	}
	if len(result.Findings) == 0 || result.Findings[0].Category != "unsafe_path" {
		t.Fatalf("findings=%+v, want unsafe_path", result.Findings)
	}
}

func TestScanPathDeniesTopLevelSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.gguf")
	if err := os.WriteFile(target, []byte("GGUFtarget"), 0644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "linked.gguf")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink not available: %v", err)
	}
	result, err := ScanPath(link, Options{Profile: policy.ProfileConfidential})
	if err != nil {
		t.Fatalf("ScanPath: %v", err)
	}
	if result.Result != policy.DecisionDeny {
		t.Fatalf("result=%s reason=%s, want deny", result.Result, result.Reason)
	}
	if result.Reason != "model.unsafe_path" {
		t.Fatalf("reason=%s, want model.unsafe_path", result.Reason)
	}
	if result.ModelFormat != "symlink" {
		t.Fatalf("model_format=%s, want symlink", result.ModelFormat)
	}
	if len(result.Findings) == 0 || result.Findings[0].Category != "unsafe_path" {
		t.Fatalf("findings=%+v, want unsafe_path", result.Findings)
	}
}

func TestHashDirectoryFilesRejectsSymlinkAtRead(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.gguf")
	if err := os.WriteFile(outside, []byte("GGUFoutside"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "linked.gguf")); err != nil {
		t.Skipf("symlink not available: %v", err)
	}
	if _, err := hashDirectoryFiles(dir, []string{"linked.gguf"}); err == nil {
		t.Fatalf("hashDirectoryFiles accepted symlink")
	}
}

func TestSecretScanErrorDeniesInternalProfile(t *testing.T) {
	decision, _ := decideScanPolicy(policy.ProfileInternal, "gguf", []Finding{
		{Category: "secret_scan_error"},
	})
	if decision.Decision != policy.DecisionDeny {
		t.Fatalf("decision=%s, want deny", decision.Decision)
	}
	if decision.ReasonCode != "model_secret_scan_failed" {
		t.Fatalf("reason_code=%s, want model_secret_scan_failed", decision.ReasonCode)
	}
}

func TestScanFileRecordsSecretScanError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokenizer.json")
	if err := os.Mkdir(path, 0755); err != nil {
		t.Fatal(err)
	}
	_, findings := scanFile(path)
	found := false
	for _, finding := range findings {
		if finding.Category == "secret_scan_error" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("findings=%+v, want secret_scan_error", findings)
	}
}

func TestScanONNXModelProtoAllow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "model.onnx")
	if err := os.WriteFile(path, minimalONNXModelProto(), 0644); err != nil {
		t.Fatal(err)
	}
	result, err := ScanPath(path, Options{Profile: policy.ProfileConfidential})
	if err != nil {
		t.Fatalf("ScanPath: %v", err)
	}
	if result.Result != policy.DecisionAllow {
		t.Fatalf("result=%s reason=%s, want allow", result.Result, result.Reason)
	}
	if result.ModelFormat != "onnx" {
		t.Fatalf("model_format=%s, want onnx", result.ModelFormat)
	}
}

func TestScanONNXArbitraryBytesDeniedForConfidential(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "model.onnx")
	if err := os.WriteFile(path, []byte("ONNXpickle-ish"), 0644); err != nil {
		t.Fatal(err)
	}
	result, err := ScanPath(path, Options{Profile: policy.ProfileConfidential})
	if err != nil {
		t.Fatalf("ScanPath: %v", err)
	}
	if result.Result != policy.DecisionDeny {
		t.Fatalf("result=%s reason=%s, want deny", result.Result, result.Reason)
	}
	if result.PolicyDecision.ReasonCode != "model_safe_format_unconfirmed" {
		t.Fatalf("reason_code=%s, want model_safe_format_unconfirmed", result.PolicyDecision.ReasonCode)
	}
}

func TestScanSecretDeniedForRegulated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokenizer.json")
	if err := os.WriteFile(path, []byte(`{"token":"sk-abcdefghijklmnopqrstuvwxyz123456"}`), 0644); err != nil {
		t.Fatal(err)
	}
	result, err := ScanPath(path, Options{Profile: policy.ProfileRegulated})
	if err != nil {
		t.Fatalf("ScanPath: %v", err)
	}
	if result.Result != policy.DecisionDeny {
		t.Fatalf("result=%s, want deny", result.Result)
	}
}

func TestDetectMagicDoesNotTreatArbitraryHeaderAsSafetensors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blob.bin")
	if err := os.WriteFile(path, make([]byte, 32), 0644); err != nil {
		t.Fatal(err)
	}
	format, ok := detectMagic(path)
	if ok || format == "safetensors" {
		t.Fatalf("detectMagic() = %q, %t; arbitrary binary must not be safetensors", format, ok)
	}
}

func minimalONNXModelProto() []byte {
	return []byte{
		0x08, 0x08, // ir_version: 8
		0x3a, 0x06, // graph length: 6
		0x12, 0x04, 'd', 'e', 'm', 'o', // graph.name: "demo"
	}
}
