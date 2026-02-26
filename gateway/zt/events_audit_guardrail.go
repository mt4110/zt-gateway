package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	auditTrailAppendabilityCheckName = "audit_trail_appendability"
	auditTrailAppendUnavailableCode  = "policy_audit_trail_append_unavailable"
)

func resolveEventSpoolDir(repoRoot string) string {
	spoolDir := strings.TrimSpace(os.Getenv("ZT_EVENT_SPOOL_DIR"))
	if spoolDir == "" {
		spoolDir = filepath.Join(repoRoot, ".zt-spool")
	}
	return spoolDir
}

func buildAuditTrailSetupCheck(repoRoot string) (setupCheck, []string) {
	check := setupCheck{Name: auditTrailAppendabilityCheckName}
	quickFixes := make([]string, 0, 2)

	spoolDir := resolveEventSpoolDir(repoRoot)
	auditPath := filepath.Join(spoolDir, "events.jsonl")
	if err := os.MkdirAll(spoolDir, 0o755); err != nil {
		check.Status = "fail"
		check.Code = auditTrailAppendUnavailableCode
		check.Message = fmt.Sprintf("spool dir create failed: %v", err)
		quickFixes = append(quickFixes,
			"Fix spool directory permissions/ownership and ensure the process can write under `ZT_EVENT_SPOOL_DIR` (or default `.zt-spool`).",
			"Re-run `zt config doctor --json` and confirm `audit_trail_appendability=ok`.")
		return check, quickFixes
	}
	if _, err := readLastAuditRecordHash(auditPath); err != nil {
		check.Status = "fail"
		check.Code = auditTrailAppendUnavailableCode
		check.Message = fmt.Sprintf("audit chain read failed: %v", err)
		quickFixes = append(quickFixes,
			"Repair malformed `.zt-spool/events.jsonl` (backup and restore valid JSONL chain).",
			"Run `zt audit verify --file <events.jsonl>` and fix chain issues before retrying send/verify.")
		return check, quickFixes
	}

	if fileExists(auditPath) {
		f, err := os.OpenFile(auditPath, os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			check.Status = "fail"
			check.Code = auditTrailAppendUnavailableCode
			check.Message = fmt.Sprintf("audit log open-for-append failed: %v", err)
			quickFixes = append(quickFixes,
				"Fix write permissions/ownership on `.zt-spool/events.jsonl` so `zt` can append audit records.",
				"Re-run `zt config doctor --json` and verify `audit_trail_appendability=ok`.")
			return check, quickFixes
		}
		_ = f.Close()
		check.Status = "ok"
		check.Message = fmt.Sprintf("appendable path=%s", auditPath)
		return check, nil
	}

	probePath := filepath.Join(spoolDir, ".audit-append-test.jsonl")
	probe := newAuditEventRecord(
		"/v1/events/diagnostic",
		[]byte(`{"event_id":"audit_probe","result":"recorded","command":"doctor"}`),
		time.Now().UTC(),
		"",
	)
	if err := appendJSONLine(probePath, probe); err != nil {
		check.Status = "fail"
		check.Code = auditTrailAppendUnavailableCode
		check.Message = fmt.Sprintf("audit append probe failed: %v", err)
		quickFixes = append(quickFixes,
			"Fix audit log write permissions (`.zt-spool/events.jsonl`) and lock-file cleanup (`.zt-spool/.lock`).",
			"Run `zt config doctor --json` and verify `audit_trail_appendability=ok` before production send/verify.")
		return check, quickFixes
	}
	_ = os.Remove(probePath)

	check.Status = "ok"
	check.Message = fmt.Sprintf("appendable path=%s", auditPath)
	return check, nil
}

func buildAuditTrailDoctorCheck(repoRoot string) doctorCheck {
	c, _ := buildAuditTrailSetupCheck(repoRoot)
	return doctorCheck{
		Name:    c.Name,
		Status:  c.Status,
		Code:    c.Code,
		Message: c.Message,
	}
}
