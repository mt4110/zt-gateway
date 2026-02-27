package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type auditVerifyCLIOptions struct {
	FilePath         string
	RequireSignature bool
	AllowLegacyV05A  bool
}

type auditReportCLIOptions struct {
	FilePath   string
	Month      string
	JSONOut    string
	PDFOut     string
	Template   string
	ContractID string
}

type auditRotateCLIOptions struct {
	FilePath      string
	ArchiveDir    string
	RetentionDays int
}

type auditMonthlyReport struct {
	SchemaVersion      int                        `json:"schema_version"`
	GeneratedAt        string                     `json:"generated_at"`
	Month              string                     `json:"month"`
	WindowStart        string                     `json:"window_start"`
	WindowEnd          string                     `json:"window_end"`
	SourceFile         string                     `json:"source_file"`
	TotalRecords       int                        `json:"total_records"`
	SelectedRecords    int                        `json:"selected_records"`
	InvalidRecords     int                        `json:"invalid_records"`
	EventTypeCounts    map[string]int             `json:"event_type_counts"`
	ResultCounts       map[string]int             `json:"result_counts"`
	SignatureKeyCounts map[string]int             `json:"signature_key_counts"`
	LegalTemplate      *auditLegalTemplateSummary `json:"legal_template,omitempty"`
}

type auditLegalTemplateSummary struct {
	Template      string          `json:"template"`
	ContractID    string          `json:"contract_id,omitempty"`
	Coverage      map[string]bool `json:"coverage"`
	CoverageRatio float64         `json:"coverage_ratio"`
	ChecksPassed  int             `json:"checks_passed"`
	ChecksTotal   int             `json:"checks_total"`
	Notes         []string        `json:"notes,omitempty"`
}

type auditRotateResult struct {
	SchemaVersion  int      `json:"schema_version"`
	GeneratedAt    string   `json:"generated_at"`
	SourceFile     string   `json:"source_file"`
	ArchiveDir     string   `json:"archive_dir"`
	RetentionDays  int      `json:"retention_days"`
	ArchivedMonths []string `json:"archived_months,omitempty"`
	ArchivedLines  int      `json:"archived_lines"`
	RetainedLines  int      `json:"retained_lines"`
	PurgedFiles    []string `json:"purged_files,omitempty"`
}

var auditArchiveFilePattern = regexp.MustCompile(`^events-\d{4}-\d{2}\.jsonl$`)

func runAuditCommand(repoRoot string, args []string) int {
	if len(args) == 0 {
		printZTErrorCode(ztErrorCodeAuditUsage)
		fmt.Println(cliAuditUsage)
		return 1
	}
	switch args[0] {
	case "verify":
		return runAuditVerifyCommand(repoRoot, args[1:])
	case "report":
		return runAuditReportCommand(repoRoot, args[1:])
	case "rotate":
		return runAuditRotateCommand(repoRoot, args[1:])
	default:
		printZTErrorCode(ztErrorCodeAuditUsage)
		fmt.Printf("Unknown audit subcommand: %s\n", args[0])
		fmt.Println(cliAuditUsage)
		return 1
	}
}

func parseAuditVerifyArgs(repoRoot string, args []string) (auditVerifyCLIOptions, error) {
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	defaultPath := defaultAuditEventsPath(repoRoot)
	opts := auditVerifyCLIOptions{
		FilePath:         defaultPath,
		RequireSignature: envBool("ZT_AUDIT_VERIFY_REQUIRE_SIGNATURE"),
		AllowLegacyV05A:  envBool("ZT_AUDIT_VERIFY_ALLOW_LEGACY_V05A"),
	}
	fs.StringVar(&opts.FilePath, "file", defaultPath, "Path to audit events JSONL")
	fs.BoolVar(&opts.RequireSignature, "require-signature", opts.RequireSignature, "Require per-record signature verification (fail-closed)")
	fs.BoolVar(&opts.AllowLegacyV05A, "compat-v05a", opts.AllowLegacyV05A, "Allow legacy v0.5-A records (without chain/signature fields)")

	if err := fs.Parse(args); err != nil {
		return auditVerifyCLIOptions{}, err
	}
	if len(fs.Args()) != 0 {
		return auditVerifyCLIOptions{}, fmt.Errorf(cliAuditUsage)
	}
	opts.FilePath = strings.TrimSpace(opts.FilePath)
	if opts.FilePath == "" {
		return auditVerifyCLIOptions{}, fmt.Errorf(cliAuditUsage)
	}
	absPath, err := filepath.Abs(opts.FilePath)
	if err != nil {
		return auditVerifyCLIOptions{}, err
	}
	opts.FilePath = absPath
	return opts, nil
}

func runAuditVerifyCommand(repoRoot string, args []string) int {
	opts, err := parseAuditVerifyArgs(repoRoot, args)
	if err != nil {
		printZTErrorCode(ztErrorCodeAuditUsage)
		fmt.Println(cliAuditUsage)
		return 1
	}
	keys, err := loadAuditVerifyPublicKeysFromEnv()
	if err != nil {
		printZTErrorCode(ztErrorCodeAuditVerifyFailed)
		fmt.Printf("[AUDIT] FAIL: invalid key configuration: %v\n", err)
		return 1
	}

	fmt.Printf("[AUDIT] Verify target: %s\n", opts.FilePath)
	if opts.RequireSignature {
		fmt.Println("[AUDIT] Signature policy: required (fail-closed)")
	}
	if opts.AllowLegacyV05A {
		fmt.Println("[AUDIT] Legacy policy: compat-v05a enabled")
	}
	if err := verifyAuditEventsFile(opts.FilePath, auditVerifyOptions{
		RequireSignature: opts.RequireSignature,
		PublicKeys:       keys,
		AllowLegacyV05A:  opts.AllowLegacyV05A,
	}); err != nil {
		printZTErrorCode(ztErrorCodeAuditVerifyFailed)
		fmt.Printf("[AUDIT] FAIL: %v\n", err)
		return 1
	}
	fmt.Println("[AUDIT] PASS: audit events contract verified")
	return 0
}

func parseAuditReportArgs(repoRoot string, args []string) (auditReportCLIOptions, error) {
	fs := flag.NewFlagSet("audit report", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	defaultMonth := time.Now().UTC().Format("2006-01")
	defaultJSONOut := filepath.Join(repoRoot, ".zt-spool", "audit-report-"+defaultMonth+".json")
	defaultPDFOut := filepath.Join(repoRoot, ".zt-spool", "audit-report-"+defaultMonth+".pdf")
	opts := auditReportCLIOptions{
		FilePath: defaultAuditEventsPath(repoRoot),
		Month:    defaultMonth,
		JSONOut:  defaultJSONOut,
		PDFOut:   defaultPDFOut,
		Template: "standard",
	}
	fs.StringVar(&opts.FilePath, "file", opts.FilePath, "Path to audit events JSONL")
	fs.StringVar(&opts.Month, "month", opts.Month, "Target month in YYYY-MM (UTC)")
	fs.StringVar(&opts.JSONOut, "json-out", opts.JSONOut, "Output path for monthly JSON report")
	fs.StringVar(&opts.PDFOut, "pdf-out", opts.PDFOut, "Output path for monthly PDF report")
	fs.StringVar(&opts.Template, "template", opts.Template, "Report template (standard|legal-v1)")
	fs.StringVar(&opts.ContractID, "contract-id", "", "Contract/compliance ID for legal template output")
	if err := fs.Parse(args); err != nil {
		return auditReportCLIOptions{}, err
	}
	if len(fs.Args()) != 0 {
		return auditReportCLIOptions{}, fmt.Errorf(cliAuditUsage)
	}
	opts.FilePath = strings.TrimSpace(opts.FilePath)
	opts.Month = strings.TrimSpace(opts.Month)
	opts.JSONOut = strings.TrimSpace(opts.JSONOut)
	opts.PDFOut = strings.TrimSpace(opts.PDFOut)
	opts.Template = strings.ToLower(strings.TrimSpace(opts.Template))
	opts.ContractID = strings.TrimSpace(opts.ContractID)
	if opts.FilePath == "" || opts.Month == "" || opts.JSONOut == "" || opts.PDFOut == "" {
		return auditReportCLIOptions{}, fmt.Errorf(cliAuditUsage)
	}
	switch opts.Template {
	case "", "standard":
		opts.Template = "standard"
	case "legal-v1":
	default:
		return auditReportCLIOptions{}, fmt.Errorf("invalid --template: expected standard|legal-v1")
	}
	if _, err := time.Parse("2006-01", opts.Month); err != nil {
		return auditReportCLIOptions{}, fmt.Errorf("invalid --month: expected YYYY-MM")
	}
	absFile, err := filepath.Abs(opts.FilePath)
	if err != nil {
		return auditReportCLIOptions{}, err
	}
	absJSON, err := filepath.Abs(opts.JSONOut)
	if err != nil {
		return auditReportCLIOptions{}, err
	}
	absPDF, err := filepath.Abs(opts.PDFOut)
	if err != nil {
		return auditReportCLIOptions{}, err
	}
	opts.FilePath = absFile
	opts.JSONOut = absJSON
	opts.PDFOut = absPDF
	return opts, nil
}

func runAuditReportCommand(repoRoot string, args []string) int {
	opts, err := parseAuditReportArgs(repoRoot, args)
	if err != nil {
		printZTErrorCode(ztErrorCodeAuditUsage)
		fmt.Println(err.Error())
		return 1
	}
	report, err := generateAuditMonthlyReport(opts)
	if err != nil {
		printZTErrorCode(ztErrorCodeAuditReportFailed)
		fmt.Printf("[AUDIT] FAIL report: %v\n", err)
		return 1
	}
	if err := writeAuditMonthlyReportJSON(opts.JSONOut, report); err != nil {
		printZTErrorCode(ztErrorCodeAuditReportFailed)
		fmt.Printf("[AUDIT] FAIL write json: %v\n", err)
		return 1
	}
	if err := writeAuditMonthlyReportPDF(opts.PDFOut, report); err != nil {
		printZTErrorCode(ztErrorCodeAuditReportFailed)
		fmt.Printf("[AUDIT] FAIL write pdf: %v\n", err)
		return 1
	}
	fmt.Printf("[AUDIT] report month=%s template=%s json=%s pdf=%s selected=%d total=%d invalid=%d\n",
		report.Month, opts.Template, opts.JSONOut, opts.PDFOut, report.SelectedRecords, report.TotalRecords, report.InvalidRecords)
	return 0
}

func generateAuditMonthlyReport(opts auditReportCLIOptions) (auditMonthlyReport, error) {
	f, err := os.Open(opts.FilePath)
	if err != nil {
		return auditMonthlyReport{}, err
	}
	defer f.Close()

	windowStart, _ := time.Parse("2006-01", opts.Month)
	windowEnd := windowStart.AddDate(0, 1, 0)
	out := auditMonthlyReport{
		SchemaVersion:      1,
		GeneratedAt:        time.Now().UTC().Format(time.RFC3339),
		Month:              opts.Month,
		WindowStart:        windowStart.UTC().Format(time.RFC3339),
		WindowEnd:          windowEnd.UTC().Format(time.RFC3339),
		SourceFile:         opts.FilePath,
		EventTypeCounts:    map[string]int{},
		ResultCounts:       map[string]int{},
		SignatureKeyCounts: map[string]int{},
	}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		out.TotalRecords++
		var rec auditEventRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			out.InvalidRecords++
			continue
		}
		ts, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(rec.Timestamp))
		if err != nil {
			ts, err = time.Parse(time.RFC3339, strings.TrimSpace(rec.Timestamp))
		}
		if err != nil {
			out.InvalidRecords++
			continue
		}
		ts = ts.UTC()
		if ts.Before(windowStart) || !ts.Before(windowEnd) {
			continue
		}
		out.SelectedRecords++
		out.EventTypeCounts[strings.TrimSpace(rec.EventType)]++
		out.ResultCounts[strings.TrimSpace(rec.Result)]++
		if key := strings.TrimSpace(rec.SignatureKeyID); key != "" {
			out.SignatureKeyCounts[key]++
		}
	}
	if err := scanner.Err(); err != nil {
		return auditMonthlyReport{}, err
	}
	if opts.Template == "legal-v1" {
		out.LegalTemplate = buildAuditLegalTemplateSummary(opts, out)
	}
	return out, nil
}

func buildAuditLegalTemplateSummary(opts auditReportCLIOptions, report auditMonthlyReport) *auditLegalTemplateSummary {
	coverage := map[string]bool{
		"chain_integrity":             report.InvalidRecords == 0,
		"signature_verification":      len(report.SignatureKeyCounts) > 0,
		"incident_traceability":       hasAuditEventTypeContaining(report.EventTypeCounts, "incident"),
		"key_governance_evidence":     hasAuditEventTypeContaining(report.EventTypeCounts, "key"),
		"retention_rotation_evidence": hasAuditEventTypeContaining(report.EventTypeCounts, "audit_rotate"),
	}
	passed := 0
	total := len(coverage)
	notes := make([]string, 0, total)
	for key, ok := range coverage {
		if ok {
			passed++
			continue
		}
		notes = append(notes, "missing coverage: "+key)
	}
	sort.Strings(notes)
	return &auditLegalTemplateSummary{
		Template:      "legal-v1",
		ContractID:    strings.TrimSpace(opts.ContractID),
		Coverage:      coverage,
		CoverageRatio: dashboardRatio(float64(passed), float64(total)),
		ChecksPassed:  passed,
		ChecksTotal:   total,
		Notes:         notes,
	}
}

func hasAuditEventTypeContaining(counts map[string]int, needle string) bool {
	needle = strings.TrimSpace(strings.ToLower(needle))
	if needle == "" {
		return false
	}
	for eventType, n := range counts {
		if n <= 0 {
			continue
		}
		if strings.Contains(strings.ToLower(strings.TrimSpace(eventType)), needle) {
			return true
		}
	}
	return false
}

func writeAuditMonthlyReportJSON(path string, report auditMonthlyReport) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}

func writeAuditMonthlyReportPDF(path string, report auditMonthlyReport) error {
	lines := []string{
		"zt-gateway Monthly Audit Report",
		"month: " + report.Month,
		"window_start: " + report.WindowStart,
		"window_end: " + report.WindowEnd,
		"source_file: " + report.SourceFile,
		fmt.Sprintf("total_records: %d", report.TotalRecords),
		fmt.Sprintf("selected_records: %d", report.SelectedRecords),
		fmt.Sprintf("invalid_records: %d", report.InvalidRecords),
		"",
		"event_type_counts:",
	}
	lines = append(lines, formatAuditReportCountLines(report.EventTypeCounts)...)
	lines = append(lines, "")
	lines = append(lines, "result_counts:")
	lines = append(lines, formatAuditReportCountLines(report.ResultCounts)...)
	lines = append(lines, "")
	lines = append(lines, "signature_key_counts:")
	lines = append(lines, formatAuditReportCountLines(report.SignatureKeyCounts)...)
	if report.LegalTemplate != nil {
		lines = append(lines, "")
		lines = append(lines, "legal_template:")
		lines = append(lines, "template: "+report.LegalTemplate.Template)
		if strings.TrimSpace(report.LegalTemplate.ContractID) != "" {
			lines = append(lines, "contract_id: "+strings.TrimSpace(report.LegalTemplate.ContractID))
		}
		lines = append(lines, fmt.Sprintf("coverage_ratio: %.4f", report.LegalTemplate.CoverageRatio))
		lines = append(lines, fmt.Sprintf("checks_passed: %d/%d", report.LegalTemplate.ChecksPassed, report.LegalTemplate.ChecksTotal))
		lines = append(lines, "coverage:")
		lines = append(lines, formatAuditReportBoolLines(report.LegalTemplate.Coverage)...)
		if len(report.LegalTemplate.Notes) > 0 {
			lines = append(lines, "notes:")
			lines = append(lines, report.LegalTemplate.Notes...)
		}
	}
	raw, err := renderSimpleTextPDF(lines)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o644)
}

func formatAuditReportCountLines(m map[string]int) []string {
	if len(m) == 0 {
		return []string{"- (none)"}
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		key := strings.TrimSpace(k)
		if key == "" {
			key = "(empty)"
		}
		out = append(out, fmt.Sprintf("- %s: %d", key, m[k]))
	}
	return out
}

func formatAuditReportBoolLines(m map[string]bool) []string {
	if len(m) == 0 {
		return []string{"- (none)"}
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, fmt.Sprintf("- %s: %t", strings.TrimSpace(k), m[k]))
	}
	return out
}

func renderSimpleTextPDF(lines []string) ([]byte, error) {
	content := buildPDFTextContent(lines)
	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
		fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(content), content),
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
	}

	var buf bytes.Buffer
	buf.WriteString("%PDF-1.4\n")
	offsets := make([]int, len(objects)+1)
	for i, obj := range objects {
		offsets[i+1] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n%s\nendobj\n", i+1, obj)
	}
	xrefPos := buf.Len()
	fmt.Fprintf(&buf, "xref\n0 %d\n", len(objects)+1)
	buf.WriteString("0000000000 65535 f \n")
	for i := 1; i <= len(objects); i++ {
		fmt.Fprintf(&buf, "%010d 00000 n \n", offsets[i])
	}
	fmt.Fprintf(&buf, "trailer << /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xrefPos)
	return buf.Bytes(), nil
}

func buildPDFTextContent(lines []string) string {
	content := make([]string, 0, len(lines)+2)
	content = append(content, "BT")
	content = append(content, "/F1 11 Tf")
	content = append(content, "72 760 Td")
	for i, line := range lines {
		if i > 0 {
			content = append(content, "T*")
		}
		content = append(content, "("+escapePDFText(line)+") Tj")
	}
	content = append(content, "ET")
	return strings.Join(content, "\n")
}

func escapePDFText(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "(", `\(`)
	s = strings.ReplaceAll(s, ")", `\)`)
	return s
}

func parseAuditRotateArgs(repoRoot string, args []string) (auditRotateCLIOptions, error) {
	fs := flag.NewFlagSet("audit rotate", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	defaultPath := defaultAuditEventsPath(repoRoot)
	defaultArchiveDir := filepath.Join(filepath.Dir(defaultPath), "audit-archive")
	opts := auditRotateCLIOptions{
		FilePath:      defaultPath,
		ArchiveDir:    defaultArchiveDir,
		RetentionDays: resolveAuditRetentionDays(),
	}
	fs.StringVar(&opts.FilePath, "file", opts.FilePath, "Path to audit events JSONL")
	fs.StringVar(&opts.ArchiveDir, "archive-dir", opts.ArchiveDir, "Archive directory for rotated monthly audit files")
	fs.IntVar(&opts.RetentionDays, "retention-days", opts.RetentionDays, "Retention period (days) for archived monthly audit files")
	if err := fs.Parse(args); err != nil {
		return auditRotateCLIOptions{}, err
	}
	if len(fs.Args()) != 0 {
		return auditRotateCLIOptions{}, fmt.Errorf(cliAuditUsage)
	}
	opts.FilePath = strings.TrimSpace(opts.FilePath)
	opts.ArchiveDir = strings.TrimSpace(opts.ArchiveDir)
	if opts.FilePath == "" || opts.ArchiveDir == "" || opts.RetentionDays <= 0 {
		return auditRotateCLIOptions{}, fmt.Errorf(cliAuditUsage)
	}
	absFile, err := filepath.Abs(opts.FilePath)
	if err != nil {
		return auditRotateCLIOptions{}, err
	}
	absArchive, err := filepath.Abs(opts.ArchiveDir)
	if err != nil {
		return auditRotateCLIOptions{}, err
	}
	opts.FilePath = absFile
	opts.ArchiveDir = absArchive
	return opts, nil
}

func resolveAuditRetentionDays() int {
	raw := strings.TrimSpace(os.Getenv("ZT_AUDIT_RETENTION_DAYS"))
	if raw == "" {
		return 90
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return 90
	}
	return n
}

func runAuditRotateCommand(repoRoot string, args []string) int {
	opts, err := parseAuditRotateArgs(repoRoot, args)
	if err != nil {
		printZTErrorCode(ztErrorCodeAuditUsage)
		fmt.Println(err.Error())
		return 1
	}
	result, err := rotateAuditEventsFile(opts, time.Now().UTC())
	if err != nil {
		printZTErrorCode(ztErrorCodeAuditRotateFailed)
		fmt.Printf("[AUDIT] FAIL rotate: %v\n", err)
		return 1
	}
	fmt.Printf("[AUDIT] rotate source=%s archived_lines=%d retained_lines=%d retention_days=%d archive_dir=%s\n",
		result.SourceFile, result.ArchivedLines, result.RetainedLines, result.RetentionDays, result.ArchiveDir)
	return 0
}

func rotateAuditEventsFile(opts auditRotateCLIOptions, now time.Time) (auditRotateResult, error) {
	raw, err := os.ReadFile(opts.FilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return auditRotateResult{
				SchemaVersion: 1,
				GeneratedAt:   now.UTC().Format(time.RFC3339),
				SourceFile:    opts.FilePath,
				ArchiveDir:    opts.ArchiveDir,
				RetentionDays: opts.RetentionDays,
			}, nil
		}
		return auditRotateResult{}, err
	}
	currentMonth := now.UTC().Format("2006-01")
	archived := map[string][]string{}
	retained := make([]string, 0, 128)

	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec auditEventRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			retained = append(retained, line)
			continue
		}
		ts, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(rec.Timestamp))
		if err != nil {
			ts, err = time.Parse(time.RFC3339, strings.TrimSpace(rec.Timestamp))
		}
		if err != nil {
			retained = append(retained, line)
			continue
		}
		month := ts.UTC().Format("2006-01")
		if month == currentMonth {
			retained = append(retained, line)
			continue
		}
		archived[month] = append(archived[month], line)
	}

	if err := os.MkdirAll(filepath.Dir(opts.FilePath), 0o755); err != nil {
		return auditRotateResult{}, err
	}
	if err := os.MkdirAll(opts.ArchiveDir, 0o755); err != nil {
		return auditRotateResult{}, err
	}
	months := make([]string, 0, len(archived))
	archivedLines := 0
	for month, lines := range archived {
		month = strings.TrimSpace(month)
		if month == "" || len(lines) == 0 {
			continue
		}
		months = append(months, month)
		archivedLines += len(lines)
		if err := appendAuditArchiveMonth(opts.ArchiveDir, month, lines); err != nil {
			return auditRotateResult{}, err
		}
	}
	sort.Strings(months)
	if err := writeAuditJSONLLinesAtomic(opts.FilePath, retained); err != nil {
		return auditRotateResult{}, err
	}

	purged, err := purgeExpiredAuditArchives(opts.ArchiveDir, opts.RetentionDays, now.UTC())
	if err != nil {
		return auditRotateResult{}, err
	}
	return auditRotateResult{
		SchemaVersion:  1,
		GeneratedAt:    now.UTC().Format(time.RFC3339),
		SourceFile:     opts.FilePath,
		ArchiveDir:     opts.ArchiveDir,
		RetentionDays:  opts.RetentionDays,
		ArchivedMonths: months,
		ArchivedLines:  archivedLines,
		RetainedLines:  len(retained),
		PurgedFiles:    purged,
	}, nil
}

func writeAuditJSONLLinesAtomic(path string, lines []string) error {
	tmp := path + ".tmp"
	var b strings.Builder
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	if err := os.WriteFile(tmp, []byte(b.String()), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func appendAuditArchiveMonth(archiveDir, month string, lines []string) error {
	if _, err := time.Parse("2006-01", month); err != nil {
		return fmt.Errorf("invalid archive month %q", month)
	}
	name := "events-" + month + ".jsonl"
	path := filepath.Join(archiveDir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if _, err := f.WriteString(line + "\n"); err != nil {
			return err
		}
	}
	return nil
}

func purgeExpiredAuditArchives(archiveDir string, retentionDays int, now time.Time) ([]string, error) {
	entries, err := os.ReadDir(archiveDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	cutoff := now.AddDate(0, 0, -retentionDays)
	purged := make([]string, 0, 8)
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		name := strings.TrimSpace(entry.Name())
		if !auditArchiveFilePattern.MatchString(name) {
			continue
		}
		month := strings.TrimSuffix(strings.TrimPrefix(name, "events-"), ".jsonl")
		start, err := time.Parse("2006-01", month)
		if err != nil {
			continue
		}
		end := start.AddDate(0, 1, 0)
		if !end.Before(cutoff) {
			continue
		}
		path := filepath.Join(archiveDir, name)
		if err := os.Remove(path); err != nil {
			return purged, err
		}
		purged = append(purged, path)
	}
	sort.Strings(purged)
	return purged, nil
}

func defaultAuditEventsPath(repoRoot string) string {
	spoolDir := strings.TrimSpace(os.Getenv("ZT_EVENT_SPOOL_DIR"))
	if spoolDir == "" {
		spoolDir = filepath.Join(repoRoot, ".zt-spool")
	}
	return filepath.Join(spoolDir, "events.jsonl")
}
