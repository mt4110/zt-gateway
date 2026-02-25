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
	Decision      string `json:"decision"`
	ReasonCode    string `json:"reason_code"`
	ManifestID    string `json:"manifest_id"`
	Profile       string `json:"profile"`
	RuleHash      string `json:"rule_hash"`
	ErrorClass    string `json:"error_class,omitempty"`
	ErrorCode     string `json:"error_code,omitempty"`
	Source        string `json:"source,omitempty"`
	MinGatewayVer string `json:"min_gateway_version,omitempty"`
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
	return normalizePolicyDecision(policyDecision{
		Decision:   policyDecisionDeny,
		ReasonCode: reasonCode,
		ManifestID: manifestID,
		Profile:    profile,
		RuleHash:   "none",
		ErrorClass: "fail_closed",
		ErrorCode:  "policy_verify_failed",
	})
}
