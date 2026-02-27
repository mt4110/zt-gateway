package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnforceFileTypeConsistency_AllowsPDFMagic(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ok.pdf")
	if err := os.WriteFile(p, []byte("%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := enforceFileTypeConsistency(p); err != nil {
		t.Fatalf("enforceFileTypeConsistency returned error: %v", err)
	}
}

func TestEnforceFileTypeConsistency_BlocksPDFWithoutEOFMarker(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.pdf")
	if err := os.WriteFile(p, []byte("%PDF-1.7\nnot really pdf\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := enforceFileTypeConsistency(p)
	if err == nil {
		t.Fatalf("expected mismatch error")
	}
	if !strings.Contains(err.Error(), "pdf_missing_eof_marker") {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := extractMagicMismatchReason(err); got != "pdf_missing_eof_marker" {
		t.Fatalf("reason = %q, want pdf_missing_eof_marker", got)
	}
}

func TestEnforceFileTypeConsistency_BlocksExeRenamedTxt(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.txt")
	if err := os.WriteFile(p, []byte{'M', 'Z', 0x90, 0x00}, 0o644); err != nil {
		t.Fatal(err)
	}
	err := enforceFileTypeConsistency(p)
	if err == nil {
		t.Fatalf("expected mismatch error")
	}
	if !strings.Contains(err.Error(), "policy.magic_mismatch") {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := extractMagicMismatchReason(err); got != "expected_text_like" {
		t.Fatalf("reason = %q, want expected_text_like", got)
	}
}

func TestEnforceFileTypeConsistency_BlocksZipRenamedPDF(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.pdf")
	if err := os.WriteFile(p, []byte{'P', 'K', 0x03, 0x04, 0x14, 0x00}, 0o644); err != nil {
		t.Fatal(err)
	}
	err := enforceFileTypeConsistency(p)
	if err == nil {
		t.Fatalf("expected mismatch error")
	}
	if !strings.Contains(err.Error(), "expected_pdf") {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := extractMagicMismatchReason(err); got != "expected_pdf" {
		t.Fatalf("reason = %q, want expected_pdf", got)
	}
}

func TestEnforceFileTypeConsistency_AllowsOOXMLDocx(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ok.docx")
	createZipFile(t, p, map[string]string{
		"[Content_Types].xml": "<Types/>",
		"_rels/.rels":         "<Relationships/>",
		"word/document.xml":   "<w:document/>",
	})
	if err := enforceFileTypeConsistency(p); err != nil {
		t.Fatalf("enforceFileTypeConsistency returned error: %v", err)
	}
}

func TestEnforceFileTypeConsistency_BlocksPseudoOOXMLDocxWithoutMainPart(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.docx")
	createZipFile(t, p, map[string]string{
		"[Content_Types].xml": "<Types/>",
		"_rels/.rels":         "<Relationships/>",
		"word/other.xml":      "<x/>",
	})
	err := enforceFileTypeConsistency(p)
	if err == nil {
		t.Fatalf("expected mismatch error")
	}
	if !strings.Contains(err.Error(), "expected_docx_ooxml") {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := extractMagicMismatchReason(err); got != "expected_docx_ooxml" {
		t.Fatalf("reason = %q, want expected_docx_ooxml", got)
	}
}

func TestEnforceFileTypeConsistency_BlocksPlainZipRenamedDocx(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.docx")
	createZipFile(t, p, map[string]string{
		"hello.txt": "hi",
	})
	err := enforceFileTypeConsistency(p)
	if err == nil {
		t.Fatalf("expected mismatch error")
	}
	if !strings.Contains(err.Error(), "expected_docx_ooxml") {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := extractMagicMismatchReason(err); got != "expected_docx_ooxml" {
		t.Fatalf("reason = %q, want expected_docx_ooxml", got)
	}
}

func TestEnforceFileTypeConsistency_AllowsTextJSON(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ok.json")
	if err := os.WriteFile(p, []byte("{\"a\":1}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := enforceFileTypeConsistency(p); err != nil {
		t.Fatalf("enforceFileTypeConsistency returned error: %v", err)
	}
}

func TestEnforceFileTypeConsistency_AllowsExtendedTextExtensions(t *testing.T) {
	cases := []struct {
		name    string
		content []byte
	}{
		{name: "ok.yaml", content: []byte("key: value\n")},
		{name: "ok.toml", content: []byte("name = \"zt\"\n")},
		{name: "ok.jsonl", content: []byte("{\"k\":1}\n{\"k\":2}\n")},
		{name: "ok.ndjson", content: []byte("{\"k\":1}\n{\"k\":2}\n")},
		{name: "ok.log", content: []byte("2026-02-27T12:00:00Z info started\n")},
		{name: "ok.sql", content: []byte("select 1;\n")},
	}
	for _, tc := range cases {
		p := filepath.Join(t.TempDir(), tc.name)
		if err := os.WriteFile(p, tc.content, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := enforceFileTypeConsistency(p); err != nil {
			t.Fatalf("enforceFileTypeConsistency(%s) returned error: %v", tc.name, err)
		}
	}
}

func TestEnforceFileTypeConsistency_BlocksExeRenamedYAML(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(p, []byte{'M', 'Z', 0x90, 0x00}, 0o644); err != nil {
		t.Fatal(err)
	}
	err := enforceFileTypeConsistency(p)
	if err == nil {
		t.Fatalf("expected mismatch error")
	}
	if got := extractMagicMismatchReason(err); got != "expected_text_like" {
		t.Fatalf("reason = %q, want expected_text_like", got)
	}
}

func TestEnforceFileTypeConsistency_AllowsShiftJISText(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ok.txt")
	// "こんにちは\r\n" in Shift-JIS
	data := []byte{0x82, 0xb1, 0x82, 0xf1, 0x82, 0xc9, 0x82, 0xbf, 0x82, 0xcd, '\r', '\n'}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := enforceFileTypeConsistency(p); err != nil {
		t.Fatalf("enforceFileTypeConsistency returned error for Shift-JIS text: %v", err)
	}
}

func createZipFile(t *testing.T, path string, files map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
}

func extractMagicMismatchReason(err error) string {
	if err == nil {
		return ""
	}
	raw := strings.TrimSpace(err.Error())
	const prefix = "policy.magic_mismatch:"
	idx := strings.Index(raw, prefix)
	if idx < 0 {
		return ""
	}
	s := strings.TrimSpace(raw[idx+len(prefix):])
	if i := strings.Index(s, "("); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	return s
}
