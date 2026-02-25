package main

import (
	"fmt"
	"strings"
)

type trustStatus struct {
	Verified bool   `json:"verified"`
	Tamper   string `json:"tamper"`
	Policy   string `json:"policy"`
	Receipt  string `json:"receipt,omitempty"`
	Reason   string `json:"reason,omitempty"`
	Line     string `json:"line"`
}

type quickFixBundle struct {
	Why      string   `json:"why"`
	Commands []string `json:"commands,omitempty"`
	Runbook  string   `json:"runbook,omitempty"`
	Retry    string   `json:"retry,omitempty"`
}

func newTrustStatusSuccess(receiptID string) trustStatus {
	receiptID = strings.TrimSpace(receiptID)
	if receiptID == "" {
		receiptID = "none"
	}
	line := fmt.Sprintf("TRUST: verified=true tamper=false policy=pass receipt=%s", receiptID)
	return trustStatus{
		Verified: true,
		Tamper:   "false",
		Policy:   "pass",
		Receipt:  receiptID,
		Line:     line,
	}
}

func newTrustStatusFailure(reason string) trustStatus {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "UNKNOWN"
	}
	line := fmt.Sprintf("TRUST: verified=false tamper=unknown policy=fail reason=%s", reason)
	return trustStatus{
		Verified: false,
		Tamper:   "unknown",
		Policy:   "fail",
		Reason:   reason,
		Line:     line,
	}
}

func printTrustStatusLine(status trustStatus) {
	fmt.Println(status.Line)
}

func buildQuickFixBundle(summary string, quickFixes []string, retryCommand string) *quickFixBundle {
	why := strings.TrimSpace(summary)
	if why == "" {
		why = "operation failed; apply fixes and retry"
	}
	retry := strings.TrimSpace(retryCommand)
	if retry == "" {
		retry = "zt setup --json"
	}
	commands := dedupeStrings(append([]string(nil), quickFixes...))
	if len(commands) == 0 {
		commands = []string{retry}
	}
	return &quickFixBundle{
		Why:      why,
		Commands: commands,
		Runbook:  "docs/OPERATIONS.md",
		Retry:    retry,
	}
}
