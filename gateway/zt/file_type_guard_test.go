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
