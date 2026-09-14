package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	policyDecisionAllow    = "allow"
	policyDecisionDeny     = "deny"
	policyDecisionDegraded = "degraded"
)

type policyDecision struct {
	Decision      string                `json:"decision"`
	ReasonCode    string                `json:"reason_code"`
	ManifestID    string                `json:"manifest_id"`
	Profile       string                `json:"profile"`
	RuleHash      string                `json:"rule_hash"`
	ErrorClass    string                `json:"error_class,omitempty"`
	ErrorCode     string                `json:"error_code,omitempty"`
	Source        string                `json:"source,omitempty"`
	MinGatewayVer string                `json:"min_gateway_version,omitempty"`
	FileTypeGuard *fileTypeGuardSummary `json:"file_type_guard,omitempty"`
	ScanPosture   *scanPostureSummary   `json:"scan_posture,omitempty"`
}

type fileTypeGuardSummary struct {
	Extension    string `json:"extension,omitempty"`
	DetectedKind string `json:"detected_kind,omitempty"`
	DetectedMIME string `json:"detected_mime,omitempty"`
	ReasonCode   string `json:"reason_code,omitempty"`
}

type scanPostureSummary struct {
	StrictEffective  bool     `json:"strict_effective"`
	RequiredScanners []string `json:"required_scanners,omitempty"`
	RequireClamAVDB  bool     `json:"require_clamav_db"`
	AllowDegraded    bool     `json:"allow_degraded_scan"`
}

func emitPolicyDecisionCLI(dec policyDecision) {
	payload, err := json.Marshal(normalizePolicyDecision(dec))
	if err != nil {
		return
	}
	fmt.Printf("POLICY_DECISION: %s\n", string(payload))
}

func normalizePolicyDecision(dec policyDecision) policyDecision {
	dec.Decision = strings.ToLower(strings.TrimSpace(dec.Decision))
	switch dec.Decision {
	case policyDecisionAllow, policyDecisionDeny, policyDecisionDegraded:
	default:
		dec.Decision = policyDecisionDeny
	}
	dec.ReasonCode = normalizeDecisionReasonCode(dec.ReasonCode)
	if strings.TrimSpace(dec.ManifestID) == "" {
		dec.ManifestID = "unknown"
	}
	if strings.TrimSpace(dec.Profile) == "" {
		dec.Profile = trustProfileInternal
	}
	if strings.TrimSpace(dec.RuleHash) == "" {
		dec.RuleHash = "none"
	}
	if strings.TrimSpace(dec.ErrorClass) == "" {
		dec.ErrorClass = "none"
	}
	if strings.TrimSpace(dec.ErrorCode) == "" {
		dec.ErrorCode = "none"
	}
	dec.FileTypeGuard = normalizeFileTypeGuardSummary(dec.FileTypeGuard)
	dec.ScanPosture = normalizeScanPostureSummary(dec.ScanPosture)
	return dec
}

func normalizeDecisionReasonCode(code string) string {
	code = strings.TrimSpace(strings.ToLower(code))
	if code == "" {
		return "policy_unknown"
	}
	var b strings.Builder
	for _, r := range code {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == ':' || r == '.' || r == '-' {
			b.WriteRune(r)
			continue
		}
		b.WriteRune('_')
	}
	return b.String()
}

func buildLocalPolicyManifestID(policyPath string, profile string) string {
	profile = strings.TrimSpace(profile)
	if profile == "" {
		profile = trustProfileInternal
	}
	if strings.TrimSpace(policyPath) == "" {
		return fmt.Sprintf("local_%s_builtin", profile)
	}
	b, err := os.ReadFile(policyPath)
	if err != nil {
		base := filepath.Base(policyPath)
		return fmt.Sprintf("local_%s_%s_missing", profile, strings.TrimSuffix(base, filepath.Ext(base)))
	}
	base := filepath.Base(policyPath)
	name := strings.TrimSuffix(base, filepath.Ext(base))
	sha := sha256HexBytes(b)
	if len(sha) > 16 {
		sha = sha[:16]
	}
	return fmt.Sprintf("local_%s_%s_%s", profile, name, sha)
}

func decisionFromScanResult(scan ScanResult, profile, manifestID, ruleHash string) policyDecision {
	decision := policyDecision{
		Decision:   policyDecisionAllow,
		ReasonCode: "policy_scan_clean",
		ManifestID: manifestID,
		Profile:    profile,
		RuleHash:   strings.TrimSpace(ruleHash),
		ErrorClass: "none",
		ErrorCode:  "none",
	}
	if scan.Result != "allow" {
		decision.Decision = policyDecisionDeny
		decision.ReasonCode = "policy_scan_denied"
		decision.ErrorClass = "fail_closed"
		decision.ErrorCode = "policy_verify_failed"
	}
	if scan.Reason == "clean.no_scanners_available" {
		decision.Decision = policyDecisionDegraded
		decision.ReasonCode = "policy_scan_no_scanners_available"
		decision.ErrorClass = "retryable"
		decision.ErrorCode = "policy_stale"
	}
	return normalizePolicyDecision(decision)
}

func decisionFromScanResultWithPosture(scan ScanResult, profile, manifestID, ruleHash string, posture *scanPostureSummary) policyDecision {
	decision := decisionFromScanResult(scan, profile, manifestID, ruleHash)
	decision.ScanPosture = normalizeScanPostureSummary(posture)
	if isScanPostureViolation(scan, posture) {
		decision.Decision = policyDecisionDeny
		decision.ReasonCode = "policy_scan_posture_violation"
		decision.ErrorClass = "fail_closed"
		decision.ErrorCode = "policy_scan_posture_violation"
	}
	return normalizePolicyDecision(decision)
}

func decisionForVerify(ok bool, reasonCode string) policyDecision {
	dec := policyDecision{
		Decision:   policyDecisionAllow,
		ReasonCode: normalizeDecisionReasonCode(reasonCode),
		ManifestID: "verify.local",
		Profile:    trustProfileInternal,
		RuleHash:   "none",
	}
	if !ok {
		dec.Decision = policyDecisionDeny
		dec.ErrorClass = "fail_closed"
		dec.ErrorCode = "policy_verify_failed"
	} else {
		dec.ErrorClass = "none"
		dec.ErrorCode = "none"
	}
	return normalizePolicyDecision(dec)
}

func decisionForSendPolicyBlock(profile, manifestID, reasonCode string) policyDecision {
	return decisionForSendPolicyBlockWithCause(profile, manifestID, reasonCode, nil)
}

func decisionForSendPolicyBlockWithCause(profile, manifestID, reasonCode string, cause error) policyDecision {
	dec := policyDecision{
		Decision:   policyDecisionDeny,
		ReasonCode: reasonCode,
		ManifestID: manifestID,
		Profile:    profile,
		RuleHash:   "none",
		ErrorClass: "fail_closed",
		ErrorCode:  "policy_verify_failed",
	}
	if strings.TrimSpace(reasonCode) == "policy_magic_mismatch" {
		dec.FileTypeGuard = parseFileTypeGuardSummaryFromError(cause)
	}
	return normalizePolicyDecision(dec)
}

func normalizeFileTypeGuardSummary(v *fileTypeGuardSummary) *fileTypeGuardSummary {
	if v == nil {
		return nil
	}
	out := &fileTypeGuardSummary{
		Extension:    strings.ToLower(strings.TrimSpace(v.Extension)),
		DetectedKind: strings.ToLower(strings.TrimSpace(v.DetectedKind)),
		DetectedMIME: strings.TrimSpace(v.DetectedMIME),
		ReasonCode:   normalizeDecisionReasonCode(v.ReasonCode),
	}
	if out.Extension == "" && out.DetectedKind == "" && out.DetectedMIME == "" && out.ReasonCode == "policy_unknown" {
		return nil
	}
	return out
}

func normalizeScanPostureSummary(v *scanPostureSummary) *scanPostureSummary {
	if v == nil {
		return nil
	}
	out := &scanPostureSummary{
		StrictEffective:  v.StrictEffective,
		RequiredScanners: normalizeStringList(v.RequiredScanners),
		RequireClamAVDB:  v.RequireClamAVDB,
		AllowDegraded:    v.AllowDegraded,
	}
	return out
}

func parseFileTypeGuardSummaryFromError(err error) *fileTypeGuardSummary {
	if err == nil {
		return nil
	}
	raw := strings.TrimSpace(err.Error())
	const prefix = "policy.magic_mismatch:"
	idx := strings.Index(raw, prefix)
	if idx < 0 {
		return nil
	}
	s := strings.TrimSpace(raw[idx+len(prefix):])
	reason := s
	ext := ""
	detected := ""
	mime := ""

	if open := strings.Index(s, "("); open >= 0 {
		reason = strings.TrimSpace(s[:open])
		detail := strings.TrimSpace(s[open:])
		if strings.HasPrefix(detail, "(") && strings.HasSuffix(detail, ")") {
			detail = strings.TrimSuffix(strings.TrimPrefix(detail, "("), ")")
			for _, token := range strings.Fields(detail) {
				parts := strings.SplitN(token, "=", 2)
				if len(parts) != 2 {
					continue
				}
				key := strings.TrimSpace(parts[0])
				val := strings.TrimSpace(parts[1])
				switch key {
				case "ext":
					ext = val
				case "detected":
					detected = val
				case "mime":
					mime = val
				}
			}
		}
	}
	return normalizeFileTypeGuardSummary(&fileTypeGuardSummary{
		Extension:    ext,
		DetectedKind: detected,
		DetectedMIME: mime,
		ReasonCode:   reason,
	})
}

func isScanPostureViolation(scan ScanResult, posture *scanPostureSummary) bool {
	if posture == nil {
		return false
	}
	if strings.TrimSpace(scan.Reason) != "clean.no_scanners_available" {
		return false
	}
	return !posture.AllowDegraded || posture.StrictEffective
}
