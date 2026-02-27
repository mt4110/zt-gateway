package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunAuditCommand_Report_GeneratesJSONAndPDF(t *testing.T) {
	repoRoot := t.TempDir()
	spool := newEventSpool(repoRoot)
	spool.SetAutoSync(false)
	auditPath := spool.auditPath()

	if err := writeAuditContractRecordWithTimestamp(auditPath, auditEventRecord{
		EventID:       "evt-rpt-1",
		EventType:     "verify",
		Timestamp:     "2026-01-15T00:00:00Z",
		Result:        "verified",
		Endpoint:      "/v1/events/verify",
		PayloadSHA256: "a",
		ChainVersion:  "v1",
	}); err != nil {
		t.Fatalf("writeAuditContractRecordWithTimestamp(1): %v", err)
	}
	if err := writeAuditContractRecordWithTimestamp(auditPath, auditEventRecord{
		EventID:       "evt-rpt-2",
		EventType:     "scan",
		Timestamp:     "2026-02-10T00:00:00Z",
		Result:        "allow",
		Endpoint:      "/v1/events/scan",
		PayloadSHA256: "b",
		ChainVersion:  "v1",
	}); err != nil {
		t.Fatalf("writeAuditContractRecordWithTimestamp(2): %v", err)
	}

	jsonOut := filepath.Join(repoRoot, "report-2026-01.json")
	pdfOut := filepath.Join(repoRoot, "report-2026-01.pdf")
	code := runAuditCommand(repoRoot, []string{
		"report",
		"--file", auditPath,
		"--month", "2026-01",
		"--json-out", jsonOut,
		"--pdf-out", pdfOut,
	})
	if code != 0 {
		t.Fatalf("runAuditCommand(report) code=%d, want 0", code)
	}
	rawJSON, err := os.ReadFile(jsonOut)
	if err != nil {
		t.Fatalf("read json report: %v", err)
	}
	var report auditMonthlyReport
	if err := json.Unmarshal(rawJSON, &report); err != nil {
		t.Fatalf("json.Unmarshal(report): %v", err)
	}
	if report.Month != "2026-01" {
		t.Fatalf("month=%q, want 2026-01", report.Month)
	}
	if report.SelectedRecords != 1 {
		t.Fatalf("selected_records=%d, want 1", report.SelectedRecords)
	}
	rawPDF, err := os.ReadFile(pdfOut)
	if err != nil {
		t.Fatalf("read pdf report: %v", err)
	}
	if !strings.HasPrefix(string(rawPDF), "%PDF-1.4") {
		t.Fatalf("pdf header missing: %q", string(rawPDF[:minIntAudit(len(rawPDF), 16)]))
	}
}

func TestRunAuditCommand_Rotate_ArchivesOldMonthsAndRetainsCurrent(t *testing.T) {
	repoRoot := t.TempDir()
	spool := newEventSpool(repoRoot)
	spool.SetAutoSync(false)
	auditPath := spool.auditPath()
	archiveDir := filepath.Join(repoRoot, ".zt-spool", "audit-archive")

	now := time.Now().UTC()
	currentTS := now.Format(time.RFC3339)
	oldTS := now.AddDate(0, -2, 0).Format(time.RFC3339)

	if err := writeAuditContractRecordWithTimestamp(auditPath, auditEventRecord{
		EventID:       "evt-rot-old",
		EventType:     "scan",
		Timestamp:     oldTS,
		Result:        "allow",
		Endpoint:      "/v1/events/scan",
		PayloadSHA256: "c",
		ChainVersion:  "v1",
	}); err != nil {
		t.Fatalf("write old record: %v", err)
	}
	if err := writeAuditContractRecordWithTimestamp(auditPath, auditEventRecord{
		EventID:       "evt-rot-current",
		EventType:     "verify",
		Timestamp:     currentTS,
		Result:        "verified",
		Endpoint:      "/v1/events/verify",
		PayloadSHA256: "d",
		ChainVersion:  "v1",
	}); err != nil {
		t.Fatalf("write current record: %v", err)
	}

	code := runAuditCommand(repoRoot, []string{
		"rotate",
		"--file", auditPath,
		"--archive-dir", archiveDir,
		"--retention-days", "365",
	})
	if code != 0 {
		t.Fatalf("runAuditCommand(rotate) code=%d, want 0", code)
	}

	archiveFile := filepath.Join(archiveDir, "events-"+now.AddDate(0, -2, 0).Format("2006-01")+".jsonl")
	if _, err := os.Stat(archiveFile); err != nil {
		t.Fatalf("archive file missing: %v", err)
	}

	lines := readAuditLinesForContract(t, auditPath)
	if len(lines) != 1 {
		t.Fatalf("active audit lines=%d, want 1", len(lines))
	}
	if !strings.Contains(lines[0], "evt-rot-current") {
		t.Fatalf("active audit line does not contain current record: %s", lines[0])
	}
}

func TestRotateAuditEventsFile_DoesNotTruncateSourceWhenArchiveInitFails(t *testing.T) {
	repoRoot := t.TempDir()
	spool := newEventSpool(repoRoot)
	spool.SetAutoSync(false)
	auditPath := spool.auditPath()
	now := time.Now().UTC()

	oldTS := now.AddDate(0, -2, 0).Format(time.RFC3339)
	currentTS := now.Format(time.RFC3339)
	if err := writeAuditContractRecordWithTimestamp(auditPath, auditEventRecord{
		EventID:       "evt-old-preserve",
		EventType:     "scan",
		Timestamp:     oldTS,
		Result:        "allow",
		Endpoint:      "/v1/events/scan",
		PayloadSHA256: "x",
		ChainVersion:  "v1",
	}); err != nil {
		t.Fatalf("write old record: %v", err)
	}
	if err := writeAuditContractRecordWithTimestamp(auditPath, auditEventRecord{
		EventID:       "evt-current-preserve",
		EventType:     "verify",
		Timestamp:     currentTS,
		Result:        "verified",
		Endpoint:      "/v1/events/verify",
		PayloadSHA256: "y",
		ChainVersion:  "v1",
	}); err != nil {
		t.Fatalf("write current record: %v", err)
	}

	archiveDir := filepath.Join(repoRoot, "archive-as-file")
	if err := os.WriteFile(archiveDir, []byte("not-a-dir"), 0o644); err != nil {
		t.Fatalf("write archive sentinel file: %v", err)
	}
	_, err := rotateAuditEventsFile(auditRotateCLIOptions{
		FilePath:      auditPath,
		ArchiveDir:    archiveDir,
		RetentionDays: 365,
	}, now)
	if err == nil {
		t.Fatalf("rotateAuditEventsFile error=nil, want mkdir failure")
	}

	lines := readAuditLinesForContract(t, auditPath)
	if len(lines) != 2 {
		t.Fatalf("active audit lines=%d, want 2 (source must remain intact)", len(lines))
	}
}

func TestRunAuditCommand_Report_LegalTemplate(t *testing.T) {
	repoRoot := t.TempDir()
	spool := newEventSpool(repoRoot)
	spool.SetAutoSync(false)
	auditPath := spool.auditPath()

	if err := writeAuditContractRecordWithTimestamp(auditPath, auditEventRecord{
		EventID:        "evt-legal-1",
		EventType:      "event_key_patch",
		Timestamp:      "2026-02-10T00:00:00Z",
		Result:         "ok",
		Endpoint:       "/v1/admin/event-keys",
		PayloadSHA256:  "a",
		ChainVersion:   "v1",
		SignatureKeyID: "audit-key-1",
	}); err != nil {
		t.Fatalf("write record 1: %v", err)
	}
	if err := writeAuditContractRecordWithTimestamp(auditPath, auditEventRecord{
		EventID:       "evt-legal-2",
		EventType:     "audit_rotate",
		Timestamp:     "2026-02-11T00:00:00Z",
		Result:        "ok",
		Endpoint:      "/v1/events/audit",
		PayloadSHA256: "b",
		ChainVersion:  "v1",
	}); err != nil {
		t.Fatalf("write record 2: %v", err)
	}
	if err := writeAuditContractRecordWithTimestamp(auditPath, auditEventRecord{
		EventID:       "evt-legal-3",
		EventType:     "incident_lock",
		Timestamp:     "2026-02-11T01:00:00Z",
		Result:        "ok",
		Endpoint:      "/v1/events/incident",
		PayloadSHA256: "c",
		ChainVersion:  "v1",
	}); err != nil {
		t.Fatalf("write record 3: %v", err)
	}

	jsonOut := filepath.Join(repoRoot, "report-2026-02-legal.json")
	pdfOut := filepath.Join(repoRoot, "report-2026-02-legal.pdf")
	code := runAuditCommand(repoRoot, []string{
		"report",
		"--file", auditPath,
		"--month", "2026-02",
		"--template", "legal-v1",
		"--contract-id", "C-2026-02",
		"--json-out", jsonOut,
		"--pdf-out", pdfOut,
	})
	if code != 0 {
		t.Fatalf("runAuditCommand(report legal-v1) code=%d, want 0", code)
	}
	rawJSON, err := os.ReadFile(jsonOut)
	if err != nil {
		t.Fatalf("read json report: %v", err)
	}
	var report auditMonthlyReport
	if err := json.Unmarshal(rawJSON, &report); err != nil {
		t.Fatalf("json.Unmarshal(report): %v", err)
	}
	if report.LegalTemplate == nil {
		t.Fatalf("legal_template=nil, want non-nil")
	}
	if report.LegalTemplate.Template != "legal-v1" {
		t.Fatalf("template=%q, want legal-v1", report.LegalTemplate.Template)
	}
	if report.LegalTemplate.ContractID != "C-2026-02" {
		t.Fatalf("contract_id=%q, want C-2026-02", report.LegalTemplate.ContractID)
	}
	if report.LegalTemplate.ChecksTotal == 0 {
		t.Fatalf("checks_total=0, want >0")
	}
}

func writeAuditContractRecordWithTimestamp(path string, rec auditEventRecord) error {
	prev, err := readLastAuditRecordHash(path)
	if err != nil {
		return err
	}
	rec.PrevRecordSHA256 = strings.TrimSpace(prev)
	rec.RecordSHA256 = calculateAuditRecordSHA256(rec)
	return appendJSONLine(path, rec)
}

func readAuditLinesForContract(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("os.Open(%s): %v", path, err)
	}
	defer f.Close()
	out := make([]string, 0, 8)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		out = append(out, line)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scanner.Err: %v", err)
	}
	return out
}

func minIntAudit(a, b int) int {
	if a < b {
		return a
	}
	return b
}
