package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

type fileMagicKind string

const (
	fileMagicUnknown   fileMagicKind = "unknown"
	fileMagicText      fileMagicKind = "text"
	fileMagicPDF       fileMagicKind = "pdf"
	fileMagicPNG       fileMagicKind = "png"
	fileMagicJPEG      fileMagicKind = "jpeg"
	fileMagicGIF       fileMagicKind = "gif"
	fileMagicWEBP      fileMagicKind = "webp"
	fileMagicZIP       fileMagicKind = "zip"
	fileMagicGZIP      fileMagicKind = "gzip"
	fileMagicRAR       fileMagicKind = "rar"
	fileMagicSevenZip  fileMagicKind = "7z"
	fileMagicTAR       fileMagicKind = "tar"
	fileMagicPEExe     fileMagicKind = "pe_exe"
	fileMagicOOXMLDocx fileMagicKind = "ooxml_docx"
	fileMagicOOXMLXlsx fileMagicKind = "ooxml_xlsx"
	fileMagicOOXMLPptx fileMagicKind = "ooxml_pptx"
)

type fileMagicInfo struct {
	Kind fileMagicKind
	MIME string
}

func enforceFileTypeConsistency(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("policy.magic.stat_error:%w", err)
	}
	if fi.IsDir() {
		return nil
	}

	ext := strings.ToLower(filepath.Ext(path))
	if ext == "" {
		return nil
	}

	info, err := detectFileMagic(path)
	if err != nil {
		return fmt.Errorf("policy.magic.inspect_error:%w", err)
	}

	if ok, reason := extensionMatchesMagic(ext, info.Kind); !ok {
		return fmt.Errorf("policy.magic_mismatch:%s (ext=%s detected=%s mime=%s)", reason, ext, info.Kind, info.MIME)
	}
	if ext == ".pdf" && info.Kind == fileMagicPDF {
		ok, err := pdfHasEOFMarker(path)
		if err != nil {
			return fmt.Errorf("policy.magic.inspect_error:%w", err)
		}
		if !ok {
			return fmt.Errorf("policy.magic_mismatch:pdf_missing_eof_marker (ext=%s detected=%s mime=%s)", ext, info.Kind, info.MIME)
		}
	}
	return nil
}

func detectFileMagic(path string) (fileMagicInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return fileMagicInfo{}, err
	}
	defer f.Close()

	buf := make([]byte, 8192)
	n, err := f.Read(buf)
	if err != nil && err != io.EOF && n == 0 {
		return fileMagicInfo{}, err
	}
	buf = buf[:n]
	mime := http.DetectContentType(buf)

	kind := sniffBinaryMagic(buf)
	if kind == fileMagicZIP {
		if ooxmlKind, ok := detectOOXMLKind(path); ok {
			kind = ooxmlKind
		}
	}
	if kind == fileMagicUnknown && looksLikeText(buf) {
		kind = fileMagicText
	}

	return fileMagicInfo{Kind: kind, MIME: mime}, nil
}

func sniffBinaryMagic(b []byte) fileMagicKind {
	if len(b) >= 2 && b[0] == 'M' && b[1] == 'Z' {
		return fileMagicPEExe
	}
	if len(b) >= 5 && bytes.Equal(b[:5], []byte("%PDF-")) {
		return fileMagicPDF
	}
	if len(b) >= 8 && bytes.Equal(b[:8], []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}) {
		return fileMagicPNG
	}
	if len(b) >= 6 && (bytes.Equal(b[:6], []byte("GIF87a")) || bytes.Equal(b[:6], []byte("GIF89a"))) {
		return fileMagicGIF
	}
	if len(b) >= 3 && b[0] == 0xff && b[1] == 0xd8 && b[2] == 0xff {
		return fileMagicJPEG
	}
	if len(b) >= 12 && bytes.Equal(b[:4], []byte("RIFF")) && bytes.Equal(b[8:12], []byte("WEBP")) {
		return fileMagicWEBP
	}
	if len(b) >= 6 && bytes.Equal(b[:6], []byte{0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c}) {
		return fileMagicSevenZip
	}
	if len(b) >= 8 && bytes.Equal(b[:8], []byte("Rar!\x1a\x07\x00")) {
		return fileMagicRAR
	}
	if len(b) >= 8 && bytes.Equal(b[:8], []byte("Rar!\x1a\x07\x01\x00")) {
		return fileMagicRAR
	}
	if len(b) >= 2 && b[0] == 0x1f && b[1] == 0x8b {
		return fileMagicGZIP
	}
	if len(b) >= 4 && bytes.Equal(b[:4], []byte{'P', 'K', 0x03, 0x04}) {
		return fileMagicZIP
	}
	if len(b) >= 4 && bytes.Equal(b[:4], []byte{'P', 'K', 0x05, 0x06}) {
		return fileMagicZIP
	}
	if len(b) >= 4 && bytes.Equal(b[:4], []byte{'P', 'K', 0x07, 0x08}) {
		return fileMagicZIP
	}
	if len(b) >= 262 && bytes.Equal(b[257:262], []byte("ustar")) {
		return fileMagicTAR
	}
	return fileMagicUnknown
}

func detectOOXMLKind(path string) (fileMagicKind, bool) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return fileMagicUnknown, false
	}
	defer zr.Close()

	hasContentTypes := false
	hasRootRels := false
	hasWord := false
	hasXL := false
	hasPPT := false
	for _, f := range zr.File {
		name := strings.ReplaceAll(f.Name, "\\", "/")
		switch {
		case name == "[Content_Types].xml":
			hasContentTypes = true
		case name == "_rels/.rels":
			hasRootRels = true
		case name == "word/document.xml":
			hasWord = true
		case name == "xl/workbook.xml":
			hasXL = true
		case name == "ppt/presentation.xml":
			hasPPT = true
		}
	}
	if !hasContentTypes || !hasRootRels {
		return fileMagicUnknown, false
	}
	switch {
	case hasWord:
		return fileMagicOOXMLDocx, true
	case hasXL:
		return fileMagicOOXMLXlsx, true
	case hasPPT:
		return fileMagicOOXMLPptx, true
	default:
		return fileMagicUnknown, false
	}
}

func looksLikeText(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	if len(b) >= 2 {
		if (b[0] == 0xff && b[1] == 0xfe) || (b[0] == 0xfe && b[1] == 0xff) {
			return true
		}
	}
	if bytes.Contains(b, []byte{0x00}) {
		return false
	}
	if !utf8.Valid(b) {
		return looksLikeShiftJISText(b)
	}
	ctrl := 0
	for _, c := range b {
		if c == '\n' || c == '\r' || c == '\t' {
			continue
		}
		if c < 0x20 {
			ctrl++
		}
	}
	return ctrl <= len(b)/20
}

func looksLikeShiftJISText(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	if bytes.Contains(b, []byte{0x00}) {
		return false
	}
	hasNonASCII := false
	for i := 0; i < len(b); {
		c := b[i]
		switch {
		case c == '\n' || c == '\r' || c == '\t':
			i++
		case c < 0x20:
			return false
		case c <= 0x7e:
			i++
		case c >= 0xa1 && c <= 0xdf:
			hasNonASCII = true
			i++
		case isShiftJISLeadByte(c):
			if i+1 >= len(b) {
				return false
			}
			if !isShiftJISTrailByte(b[i+1]) {
				return false
			}
			hasNonASCII = true
			i += 2
		default:
			return false
		}
	}
	return hasNonASCII
}

func isShiftJISLeadByte(b byte) bool {
	return (b >= 0x81 && b <= 0x9f) || (b >= 0xe0 && b <= 0xfc)
}

func isShiftJISTrailByte(b byte) bool {
	if b == 0x7f {
		return false
	}
	return (b >= 0x40 && b <= 0x7e) || (b >= 0x80 && b <= 0xfc)
}

func pdfHasEOFMarker(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return false, err
	}
	const tailWindow = int64(4096)
	size := info.Size()
	start := int64(0)
	if size > tailWindow {
		start = size - tailWindow
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return false, err
	}
	tail, err := io.ReadAll(f)
	if err != nil {
		return false, err
	}
	return bytes.Contains(tail, []byte("%%EOF")), nil
}

func extensionMatchesMagic(ext string, kind fileMagicKind) (bool, string) {
	switch ext {
	case ".jpg", ".jpeg":
		if kind != fileMagicJPEG {
			return false, "expected_jpeg"
		}
		return true, ""
	case ".png":
		if kind != fileMagicPNG {
			return false, "expected_png"
		}
		return true, ""
	case ".gif":
		if kind != fileMagicGIF {
			return false, "expected_gif"
		}
		return true, ""
	case ".webp":
		if kind != fileMagicWEBP {
			return false, "expected_webp"
		}
		return true, ""
	case ".pdf":
		if kind != fileMagicPDF {
			return false, "expected_pdf"
		}
		return true, ""
	case ".docx":
		if kind != fileMagicOOXMLDocx {
			return false, "expected_docx_ooxml"
		}
		return true, ""
	case ".xlsx":
		if kind != fileMagicOOXMLXlsx {
			return false, "expected_xlsx_ooxml"
		}
		return true, ""
	case ".pptx":
		if kind != fileMagicOOXMLPptx {
			return false, "expected_pptx_ooxml"
		}
		return true, ""
	case ".txt", ".md", ".csv", ".json":
		switch kind {
		case fileMagicText:
			return true, ""
		case fileMagicUnknown:
			// Text sniffing is intentionally conservative; unknown is treated as mismatch for allowed text extensions.
			return false, "expected_text_like"
		default:
			return false, "expected_text_like"
		}
	default:
		// Only enforce allowlisted extensions for now; ext policy still denies unknown/high-risk extensions.
		return true, ""
	}
}
