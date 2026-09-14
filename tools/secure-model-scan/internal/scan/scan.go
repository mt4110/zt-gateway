package scan

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/mt4110/zt-gateway/tools/secure-model-scan/internal/policy"
)

const SchemaVersion = "zt-model-scan-v1"

var secretPattern = regexp.MustCompile(`(?i)(AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9_-]{20,}|hf_[A-Za-z0-9]{20,}|-----BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----)`)

type Options struct {
	Profile string
}

type Result struct {
	SchemaVersion  string          `json:"schema_version"`
	Result         string          `json:"result"`
	Reason         string          `json:"reason"`
	ModelFormat    string          `json:"model_format"`
	Findings       []Finding       `json:"findings"`
	Hashes         Hashes          `json:"hashes"`
	PolicyDecision policy.Decision `json:"policy_decision"`
}

type Finding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Category string `json:"category"`
	Path     string `json:"path"`
	Message  string `json:"message"`
}

type Hashes struct {
	SHA256 string `json:"sha256"`
}

func ScanPath(path string, opts Options) (Result, error) {
	profile, err := policy.NormalizeProfile(opts.Profile)
	if err != nil {
		return Result{}, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return Result{}, err
	}
	var findings []Finding
	var format string
	var sha string
	if info.Mode()&os.ModeSymlink != 0 {
		findings = append(findings, Finding{
			ID:       findingID(len(findings)),
			Severity: "high",
			Category: "unsafe_path",
			Path:     path,
			Message:  "symlinked top-level model targets are not allowed",
		})
		decision, decisionFormat := decideScanPolicy(profile, "symlink", findings)
		return Result{
			SchemaVersion:  SchemaVersion,
			Result:         decision.Decision,
			Reason:         reasonForDecision(decision, decisionFormat),
			ModelFormat:    "symlink",
			Findings:       findings,
			Hashes:         Hashes{},
			PolicyDecision: decision,
		}, nil
	}
	if info.IsDir() {
		findings, format, sha, err = scanDirectory(path)
		if err != nil {
			return Result{}, err
		}
	} else {
		sha, err = fileSHA256(path)
		if err != nil {
			return Result{}, err
		}
		format, findings = scanFile(path)
	}

	decision, decisionFormat := decideScanPolicy(profile, format, findings)
	result := Result{
		SchemaVersion:  SchemaVersion,
		Result:         decision.Decision,
		Reason:         reasonForDecision(decision, decisionFormat),
		ModelFormat:    format,
		Findings:       findings,
		Hashes:         Hashes{SHA256: sha},
		PolicyDecision: decision,
	}
	return result, nil
}

func decideScanPolicy(profile, format string, findings []Finding) (policy.Decision, string) {
	hasSecret := false
	hasUnsafeSerialization := false
	hasUnconfirmedSafeFormat := false
	hasUnknownFormat := false
	hasUnsafePath := false
	hasSecretScanError := false
	for _, f := range findings {
		if f.Category == "secret" {
			hasSecret = true
		}
		if f.Category == "unsafe_serialization" {
			hasUnsafeSerialization = true
		}
		if f.Category == "unconfirmed_safe_format" {
			hasUnconfirmedSafeFormat = true
		}
		if f.Category == "unknown_format" {
			hasUnknownFormat = true
		}
		if f.Category == "unsafe_path" {
			hasUnsafePath = true
		}
		if f.Category == "secret_scan_error" {
			hasSecretScanError = true
		}
	}
	decisionFormat := format
	if hasUnsafeSerialization {
		decisionFormat = "pt"
	}
	decision := policy.Decide(profile, decisionFormat, hasSecret)
	if hasUnknownFormat && policy.IsStrictProfile(profile) && decision.Decision != policy.DecisionDeny {
		decision = policy.Decision{Decision: policy.DecisionDeny, Profile: profile, ReasonCode: "model_unknown_format_denied"}
	}
	if hasUnsafePath {
		decision = policy.Decision{Decision: policy.DecisionDeny, Profile: profile, ReasonCode: "model_unsafe_path"}
	}
	if hasUnconfirmedSafeFormat && policy.IsStrictProfile(profile) {
		decision = policy.Decision{Decision: policy.DecisionDeny, Profile: profile, ReasonCode: "model_safe_format_unconfirmed"}
	}
	if hasSecretScanError {
		decision = policy.Decision{Decision: policy.DecisionDeny, Profile: profile, ReasonCode: "model_secret_scan_failed"}
	}
	return decision, decisionFormat
}

func scanFile(path string) (string, []Finding) {
	format := inferFormat(path)
	findings := make([]Finding, 0)
	magicFormat, magicOK := detectMagic(path)
	if magicFormat != "" && format != "" && magicFormat != format {
		findings = append(findings, Finding{
			ID:       findingID(len(findings)),
			Severity: "high",
			Category: "format_mismatch",
			Path:     path,
			Message:  fmt.Sprintf("extension suggests %s but magic bytes suggest %s", format, magicFormat),
		})
	}
	if magicFormat != "" {
		format = magicFormat
	}
	if format == "" {
		format = "unknown"
		findings = append(findings, Finding{
			ID:       findingID(len(findings)),
			Severity: "medium",
			Category: "unknown_format",
			Path:     path,
			Message:  "model format could not be determined from extension or magic bytes",
		})
	}
	if !magicOK && isMagicConfirmedSafeFormat(format) {
		findings = append(findings, Finding{
			ID:       findingID(len(findings)),
			Severity: "high",
			Category: "unconfirmed_safe_format",
			Path:     path,
			Message:  "model extension is known but magic/header check did not confirm it",
		})
	}
	if format == "pt" || format == "pth" || format == "bin" {
		findings = append(findings, Finding{
			ID:       findingID(len(findings)),
			Severity: "high",
			Category: "unsafe_serialization",
			Path:     path,
			Message:  "pickle-based model requires explicit trust policy",
		})
	}
	if isTextLikeModelSidecar(path) {
		hasSecret, err := fileContainsSecret(path)
		if err != nil {
			findings = append(findings, Finding{
				ID:       findingID(len(findings)),
				Severity: "high",
				Category: "secret_scan_error",
				Path:     path,
				Message:  fmt.Sprintf("model sidecar could not be scanned for secrets: %v", err),
			})
		} else if hasSecret {
			findings = append(findings, Finding{
				ID:       findingID(len(findings)),
				Severity: "high",
				Category: "secret",
				Path:     path,
				Message:  "secret-like token found in model sidecar",
			})
		}
	}
	return format, findings
}

func isMagicConfirmedSafeFormat(format string) bool {
	switch format {
	case "gguf", "safetensors", "onnx":
		return true
	default:
		return false
	}
}

func scanDirectory(root string) ([]Finding, string, string, error) {
	findings := make([]Finding, 0)
	formats := map[string]int{}
	files := make([]string, 0)
	if err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d == nil || d.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		if d.Type()&os.ModeSymlink != 0 {
			findings = append(findings, Finding{
				ID:       findingID(len(findings)),
				Severity: "high",
				Category: "unsafe_path",
				Path:     rel,
				Message:  "symlinked model files are not allowed",
			})
			return nil
		}
		files = append(files, rel)
		format, fs := scanFile(path)
		if format != "unknown" {
			formats[format]++
		}
		for _, f := range fs {
			f.Path = rel
			f.ID = findingID(len(findings))
			findings = append(findings, f)
		}
		return nil
	}); err != nil {
		return nil, "", "", err
	}
	sha, err := hashDirectoryFiles(root, files)
	if err != nil {
		return nil, "", "", err
	}
	if len(formats) == 0 {
		return findings, "directory", sha, nil
	}
	type pair struct {
		format string
		count  int
	}
	pairs := make([]pair, 0, len(formats))
	for k, v := range formats {
		pairs = append(pairs, pair{k, v})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].count == pairs[j].count {
			return pairs[i].format < pairs[j].format
		}
		return pairs[i].count > pairs[j].count
	})
	return findings, pairs[0].format, sha, nil
}

func inferFormat(path string) string {
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(path), "."))
	switch ext {
	case "gguf", "safetensors", "pt", "pth", "bin", "onnx":
		return ext
	default:
		return ""
	}
}

func detectMagic(path string) (format string, ok bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", false
	}
	buf := make([]byte, 16)
	n, _ := io.ReadFull(f, buf)
	buf = buf[:n]
	if len(buf) >= 4 && string(buf[:4]) == "GGUF" {
		return "gguf", true
	}
	if len(buf) >= 8 {
		headerLen := binary.LittleEndian.Uint64(buf[:8])
		if headerLen > 0 && headerLen <= 128<<20 && int64(headerLen)+8 <= info.Size() && len(buf) >= 9 && buf[8] == '{' {
			return "safetensors", true
		}
	}
	if looksLikeONNXModelProto(f, info.Size()) {
		return "onnx", true
	}
	return "", false
}

func looksLikeONNXModelProto(f *os.File, size int64) bool {
	if size <= 0 {
		return false
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return false
	}
	data, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return false
	}
	return hasONNXModelProtoSignals(data)
}

func hasONNXModelProtoSignals(data []byte) bool {
	offset := 0
	hasIRVersion := false
	hasGraph := false
	graphLooksONNX := false
	for offset < len(data) {
		key, ok := readProtoVarint(data, &offset)
		if !ok {
			return false
		}
		field := key >> 3
		wire := key & 0x7
		if field == 0 {
			return false
		}
		switch {
		case field == 1 && wire == 0:
			irVersion, ok := readProtoVarint(data, &offset)
			if !ok {
				return false
			}
			hasIRVersion = irVersion > 0 && irVersion <= 20
		case field == 7 && wire == 2:
			value, ok := readLengthDelimitedProtoValue(data, &offset)
			if !ok || len(value) == 0 {
				return false
			}
			hasGraph = true
			graphLooksONNX = looksLikeONNXGraphProto(value)
		default:
			if !skipProtoValue(data, &offset, wire) {
				return false
			}
		}
		if hasIRVersion && hasGraph && graphLooksONNX {
			return true
		}
	}
	return false
}

func looksLikeONNXGraphProto(data []byte) bool {
	offset := 0
	for offset < len(data) {
		key, ok := readProtoVarint(data, &offset)
		if !ok {
			return false
		}
		field := key >> 3
		wire := key & 0x7
		if field == 0 {
			return false
		}
		if wire == 2 {
			value, ok := readLengthDelimitedProtoValue(data, &offset)
			if !ok {
				return false
			}
			switch field {
			case 1, 2, 5, 11, 12, 13:
				if len(value) > 0 {
					return true
				}
			}
			continue
		}
		if !skipProtoValue(data, &offset, wire) {
			return false
		}
	}
	return false
}

func readLengthDelimitedProtoValue(data []byte, offset *int) ([]byte, bool) {
	length, ok := readProtoVarint(data, offset)
	if !ok || length > uint64(len(data)-*offset) {
		return nil, false
	}
	start := *offset
	*offset += int(length)
	return data[start:*offset], true
}

func skipProtoValue(data []byte, offset *int, wire uint64) bool {
	switch wire {
	case 0:
		_, ok := readProtoVarint(data, offset)
		return ok
	case 1:
		if len(data)-*offset < 8 {
			return false
		}
		*offset += 8
		return true
	case 2:
		_, ok := readLengthDelimitedProtoValue(data, offset)
		return ok
	case 5:
		if len(data)-*offset < 4 {
			return false
		}
		*offset += 4
		return true
	default:
		return false
	}
}

func readProtoVarint(data []byte, offset *int) (uint64, bool) {
	var value uint64
	for i := 0; i < 10 && *offset < len(data); i++ {
		b := data[*offset]
		*offset = *offset + 1
		if i == 9 && b > 1 {
			return 0, false
		}
		value |= uint64(b&0x7f) << uint(7*i)
		if b < 0x80 {
			return value, true
		}
	}
	return 0, false
}

func isTextLikeModelSidecar(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json", ".txt", ".yaml", ".yml", ".py", ".toml":
		return true
	default:
		return false
	}
}

func fileContainsSecret(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return false, err
	}
	return secretPattern.Match(data), nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func hashDirectoryFiles(root string, files []string) (string, error) {
	h := sha256.New()
	sort.Strings(files)
	for _, rel := range files {
		_, _ = fmt.Fprintf(h, "path:%d:", len([]byte(rel)))
		_, _ = io.WriteString(h, rel)
		fp := filepath.Join(root, rel)
		info, err := os.Lstat(fp)
		if err != nil {
			return "", err
		}
		if !info.Mode().IsRegular() {
			return "", fmt.Errorf("directory file %q is not a regular file", rel)
		}
		f, err := os.Open(fp)
		if err != nil {
			return "", err
		}
		openedInfo, err := f.Stat()
		if err != nil {
			_ = f.Close()
			return "", err
		}
		if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
			_ = f.Close()
			return "", fmt.Errorf("directory file %q changed before hashing", rel)
		}
		_, _ = fmt.Fprintf(h, "file:%d:", openedInfo.Size())
		if _, err := io.Copy(h, f); err != nil {
			_ = f.Close()
			return "", err
		}
		_ = f.Close()
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func reasonForDecision(decision policy.Decision, format string) string {
	switch decision.ReasonCode {
	case "model_pickle_denied":
		return "model.pickle_rce_risk"
	case "model_pickle_warn":
		return "model.pickle_rce_warn"
	case "model_secret_detected", "model_secret_warn":
		return "model.secret_detected"
	case "model_secret_scan_failed":
		return "model.secret_scan_failed"
	case "model_safe_format_unconfirmed":
		return "model.safe_format_unconfirmed"
	case "model_unsafe_path":
		return "model.unsafe_path"
	case "model_unknown_format_denied", "model_unknown_format_warn":
		return "model.unknown_format"
	default:
		if format == "unknown" {
			return "model.unknown_format"
		}
		return "model.safe"
	}
}

func findingID(n int) string {
	return fmt.Sprintf("finding_%03d", n+1)
}
