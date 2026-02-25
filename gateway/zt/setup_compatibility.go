package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

const (
	setupCompatCategoryNone                    = "none"
	setupCompatCategoryRootPinInvalidConfig    = "root_pin_invalid_config"
	setupCompatCategoryRootPinMissing          = "root_pin_missing"
	setupCompatCategoryRootPinMismatch         = "root_pin_mismatch"
	setupCompatCategoryToolsLockSignature      = "tools_lock_signature_invalid"
	setupCompatCategoryToolsLockUnavailable    = "tools_lock_unavailable"
	setupCompatCategoryToolMissing             = "tool_missing"
	setupCompatCategoryToolHashMismatch        = "tool_hash_mismatch"
	setupCompatCategoryToolVersionMismatch     = "tool_version_mismatch"
	setupCompatCategoryToolPinParseError       = "tool_pin_parse_error"
	setupCompatCategoryToolPinInspectionFailed = "tool_pin_inspection_failed"
)

type securePackToolPins struct {
	GPGSHA256  string
	GPGVersion string
	TarSHA256  string
	TarVersion string
}

type toolPinMismatch struct {
	Tool     string
	Field    string
	Expected string
	Actual   string
}

type toolPinInspection struct {
	PackageSource string
	Mismatches    []toolPinMismatch
	MissingTools  []string
}

func buildSetupCompatibilityResolverReport(repoRoot string, rootPinCheck, sigCheck setupCheck) (setupCheck, *setupCompatibilityResolver, []string) {
	pins, pinSource, _ := resolveSecurePackRootPubKeyFingerprintPinsWithSource()
	env := setupCompatibilityEnvironment{
		OS:        runtime.GOOS + "/" + runtime.GOARCH,
		PinSource: pinSource,
	}
	_ = pins

	category := setupCompatCategoryNone
	reason := "compatible with current environment"

	if c := rootPinCompatibilityCategory(rootPinCheck); c != "" {
		category = c
		reason = normalizeSetupMessage(rootPinCheck.Message)
	} else if c := signatureCompatibilityCategory(sigCheck); c != "" {
		category = c
		reason = normalizeSetupMessage(sigCheck.Message)
	} else {
		inspection, err := inspectSecurePackToolPinCompatibility(repoRoot)
		if inspection.PackageSource != "" {
			env.PackageSource = inspection.PackageSource
		}
		if err != nil {
			switch {
			case os.IsNotExist(err):
				category = setupCompatCategoryToolsLockUnavailable
				reason = normalizeSetupMessage(err.Error())
			case strings.Contains(err.Error(), "parse"):
				category = setupCompatCategoryToolPinParseError
				reason = normalizeSetupMessage(err.Error())
			default:
				category = setupCompatCategoryToolPinInspectionFailed
				reason = normalizeSetupMessage(err.Error())
			}
		} else if len(inspection.MissingTools) > 0 {
			category = setupCompatCategoryToolMissing
			reason = fmt.Sprintf("required tools missing in PATH: %s", strings.Join(inspection.MissingTools, ", "))
		} else if len(inspection.Mismatches) > 0 {
			category = classifyToolMismatchCategory(inspection.Mismatches)
			reason = formatToolMismatchReason(inspection.Mismatches)
		}
	}

	if env.PackageSource == "" {
		env.PackageSource = "unknown"
	}

	report := &setupCompatibilityResolver{
		Status:      "ok",
		Category:    setupCompatCategoryNone,
		Reason:      reason,
		Environment: env,
	}
	check := setupCheck{
		Name:    "compatibility_resolver",
		Status:  "ok",
		Message: "no compatibility blockers detected",
	}
	if category != setupCompatCategoryNone {
		report.Status = "warn"
		report.Category = category
		report.Reason = reason
		report.FixCandidates = buildCompatibilityFixCandidates(category, env)
		check.Status = "warn"
		check.Message = fmt.Sprintf("%s: %s", category, reason)
	}
	fixes := extractCompatibilityFixCommands(report.FixCandidates)
	return check, report, fixes
}

func rootPinCompatibilityCategory(c setupCheck) string {
	if c.Status != "fail" {
		return ""
	}
	msg := strings.ToLower(c.Message)
	switch {
	case strings.Contains(msg, "pin configuration invalid"):
		return setupCompatCategoryRootPinInvalidConfig
	case strings.Contains(msg, "no trusted root key fingerprint pins configured"):
		return setupCompatCategoryRootPinMissing
	case strings.Contains(msg, "fingerprint mismatch"):
		return setupCompatCategoryRootPinMismatch
	default:
		return setupCompatCategoryRootPinMismatch
	}
}

func signatureCompatibilityCategory(c setupCheck) string {
	if c.Status != "fail" {
		return ""
	}
	if strings.Contains(strings.ToLower(c.Message), "signature verification failed") {
		return setupCompatCategoryToolsLockSignature
	}
	return ""
}

func inspectSecurePackToolPinCompatibility(repoRoot string) (toolPinInspection, error) {
	lockPath := filepath.Join(repoRoot, "tools", "secure-pack", "tools.lock")
	if _, err := os.Stat(lockPath); err != nil {
		return toolPinInspection{}, err
	}

	pins, err := loadSecurePackToolPins(lockPath)
	if err != nil {
		return toolPinInspection{}, err
	}

	gpgPath, gpgErr := exec.LookPath("gpg")
	tarPath, tarErr := exec.LookPath("tar")
	var missing []string
	if gpgErr != nil {
		missing = append(missing, "gpg")
	}
	if tarErr != nil {
		missing = append(missing, "tar")
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		return toolPinInspection{
			PackageSource: packageSourceForPaths(gpgPath, tarPath),
			MissingTools:  missing,
		}, nil
	}

	out := toolPinInspection{
		PackageSource: packageSourceForPaths(gpgPath, tarPath),
	}

	gpgVersion, err := commandVersionLineForSetup("gpg")
	if err != nil {
		return out, fmt.Errorf("gpg version inspect failed: %w", err)
	}
	if gpgVersion != pins.GPGVersion {
		out.Mismatches = append(out.Mismatches, toolPinMismatch{
			Tool:     "gpg",
			Field:    "version",
			Expected: pins.GPGVersion,
			Actual:   gpgVersion,
		})
	}
	gpgSHA, err := fileSHA256ForSetup(gpgPath)
	if err != nil {
		return out, fmt.Errorf("gpg sha256 inspect failed: %w", err)
	}
	if gpgSHA != strings.ToLower(pins.GPGSHA256) {
		out.Mismatches = append(out.Mismatches, toolPinMismatch{
			Tool:     "gpg",
			Field:    "sha256",
			Expected: strings.ToLower(pins.GPGSHA256),
			Actual:   gpgSHA,
		})
	}

	tarVersion, err := commandVersionLineForSetup("tar")
	if err != nil {
		return out, fmt.Errorf("tar version inspect failed: %w", err)
	}
	if tarVersion != pins.TarVersion {
		out.Mismatches = append(out.Mismatches, toolPinMismatch{
			Tool:     "tar",
			Field:    "version",
			Expected: pins.TarVersion,
			Actual:   tarVersion,
		})
	}
	tarSHA, err := fileSHA256ForSetup(tarPath)
	if err != nil {
		return out, fmt.Errorf("tar sha256 inspect failed: %w", err)
	}
	if tarSHA != strings.ToLower(pins.TarSHA256) {
		out.Mismatches = append(out.Mismatches, toolPinMismatch{
			Tool:     "tar",
			Field:    "sha256",
			Expected: strings.ToLower(pins.TarSHA256),
			Actual:   tarSHA,
		})
	}

	return out, nil
}

func loadSecurePackToolPins(path string) (securePackToolPins, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return securePackToolPins{}, err
	}
	values := map[string]string{}
	for idx, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return securePackToolPins{}, fmt.Errorf("parse tools.lock line %d: invalid assignment syntax", idx+1)
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		val = strings.Trim(val, "\"")
		values[key] = val
	}
	out := securePackToolPins{
		GPGSHA256:  values["gpg_sha256"],
		GPGVersion: values["gpg_version"],
		TarSHA256:  values["tar_sha256"],
		TarVersion: values["tar_version"],
	}
	if out.GPGSHA256 == "" || out.GPGVersion == "" || out.TarSHA256 == "" || out.TarVersion == "" {
		return securePackToolPins{}, fmt.Errorf("parse tools.lock: missing required keys")
	}
	return out, nil
}

func classifyToolMismatchCategory(items []toolPinMismatch) string {
	for _, item := range items {
		if item.Field == "sha256" {
			return setupCompatCategoryToolHashMismatch
		}
	}
	return setupCompatCategoryToolVersionMismatch
}

func formatToolMismatchReason(items []toolPinMismatch) string {
	parts := make([]string, 0, len(items))
	for _, item := range items {
		parts = append(parts, fmt.Sprintf("%s.%s expected=%q actual=%q", item.Tool, item.Field, item.Expected, item.Actual))
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func buildCompatibilityFixCandidates(category string, env setupCompatibilityEnvironment) []setupCompatibilityFixCandidate {
	candidates := make([]setupCompatibilityFixCandidate, 0, 4)
	add := func(priority int, cmd, why string) {
		candidates = append(candidates, setupCompatibilityFixCandidate{
			Priority: priority,
			Command:  cmd,
			Why:      why,
		})
	}

	switch category {
	case setupCompatCategoryRootPinInvalidConfig:
		add(1, "export ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS='<40HEX[,40HEX...]>'", "Fix malformed fingerprint pin format (comma/newline separated hex).")
		add(2, "bash ./scripts/ci/check-zt-setup-json-actual-gate.sh", "Re-check root pin resolution and signature checks.")
	case setupCompatCategoryRootPinMissing:
		add(1, "export ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS=\"$(gpg --show-keys --with-colons ./tools/secure-pack/ROOT_PUBKEY.asc | awk -F: '/^fpr:/ {print $10; exit}')\"", "Set root key fingerprint pin (fail-closed prerequisite).")
		add(2, "bash ./scripts/ci/check-zt-setup-json-actual-gate.sh", "Validate `resolved.pin_match_count >= 1`.")
	case setupCompatCategoryRootPinMismatch:
		add(1, "export ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS='OLD_FPR_40HEX,NEW_FPR_40HEX'", "Update approved root fingerprint pins (use dual pins during rotation).")
		add(2, "bash ./scripts/ci/check-zt-setup-json-actual-gate.sh", "Re-check fingerprint match and signature checks.")
	case setupCompatCategoryToolsLockSignature:
		add(1, "gpg --verify ./tools/secure-pack/tools.lock.sig ./tools/secure-pack/tools.lock", "Verify detached signature diagnostics.")
		add(2, "bash ./scripts/dev/generate-secure-pack-tools-lock.sh --root-key <gpg_uid_or_fpr>", "Regenerate/sign CI-canonical tools.lock artifacts.")
	case setupCompatCategoryToolMissing:
		add(1, quickFixForMissingTool("gpg"), "Install gpg to satisfy secure-pack verification.")
		add(2, "Install tar (required by secure-pack packet build/extract)", "Install tar in PATH.")
		add(3, "bash ./scripts/dev/run-secure-pack-smoketest.sh --diagnose-only", "Confirm the environment after installing required tools.")
	case setupCompatCategoryToolHashMismatch, setupCompatCategoryToolVersionMismatch:
		add(1, "bash ./scripts/dev/run-secure-pack-smoketest.sh --diagnose-only", "Diagnose tools.lock gpg/tar pin mismatch before send.")
		if strings.HasPrefix(env.OS, "darwin/") {
			add(2, "bash ./scripts/dev/run-secure-pack-smoketest-ubuntu-docker.sh --diagnose-only", "Use Ubuntu/Linux CI-equivalent diagnosis for canonical pin compatibility.")
		}
		add(3, "bash ./scripts/dev/generate-secure-pack-tools-lock.sh --root-key <gpg_uid_or_fpr>", "Regenerate CI-canonical tools.lock only when pin update is intentional.")
	case setupCompatCategoryToolsLockUnavailable:
		add(1, "ls ./tools/secure-pack/tools.lock ./tools/secure-pack/tools.lock.sig ./tools/secure-pack/ROOT_PUBKEY.asc", "Confirm supply-chain files exist.")
	default:
		// no-op for "none"
	}
	return dedupeCompatibilityFixCandidates(candidates)
}

func dedupeCompatibilityFixCandidates(in []setupCompatibilityFixCandidate) []setupCompatibilityFixCandidate {
	if len(in) == 0 {
		return nil
	}
	out := make([]setupCompatibilityFixCandidate, 0, len(in))
	seen := map[string]struct{}{}
	for _, item := range in {
		cmd := strings.TrimSpace(item.Command)
		if cmd == "" {
			continue
		}
		if _, ok := seen[cmd]; ok {
			continue
		}
		seen[cmd] = struct{}{}
		item.Command = cmd
		out = append(out, item)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Priority < out[j].Priority
	})
	return out
}

func extractCompatibilityFixCommands(candidates []setupCompatibilityFixCandidate) []string {
	if len(candidates) == 0 {
		return nil
	}
	out := make([]string, 0, len(candidates))
	for _, item := range candidates {
		if cmd := strings.TrimSpace(item.Command); cmd != "" {
			out = append(out, cmd)
		}
	}
	return dedupeStrings(out)
}

func packageSourceForPaths(paths ...string) string {
	sources := make([]string, 0, len(paths))
	seen := map[string]struct{}{}
	for _, p := range paths {
		s := packageSourceForPath(p)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		sources = append(sources, s)
	}
	if len(sources) == 0 {
		return ""
	}
	sort.Strings(sources)
	if len(sources) == 1 {
		return sources[0]
	}
	return "mixed:" + strings.Join(sources, "+")
}

func packageSourceForPath(path string) string {
	p := strings.ToLower(strings.TrimSpace(path))
	switch {
	case p == "":
		return ""
	case strings.Contains(p, "/nix/store/"):
		return "nix"
	case strings.Contains(p, "/opt/homebrew/"), strings.Contains(p, "/usr/local/cellar/"), strings.Contains(p, "homebrew"):
		return "homebrew"
	case strings.HasPrefix(p, "/usr/bin/"), strings.HasPrefix(p, "/bin/"), strings.HasPrefix(p, "/usr/sbin/"), strings.HasPrefix(p, "/sbin/"):
		return "system"
	default:
		return "custom"
	}
}

func fileSHA256ForSetup(path string) (string, error) {
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

func commandVersionLineForSetup(toolName string) (string, error) {
	out, err := exec.Command(toolName, "--version").CombinedOutput()
	if err != nil {
		msg := normalizeSetupMessage(string(out))
		if msg != "" {
			return "", fmt.Errorf("%w: %s", err, msg)
		}
		return "", err
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line != "" {
			return line, nil
		}
	}
	return "", fmt.Errorf("empty version output")
}

func normalizeSetupMessage(msg string) string {
	msg = strings.TrimSpace(msg)
	if len(msg) > 320 {
		msg = msg[:320] + "..."
	}
	return msg
}
