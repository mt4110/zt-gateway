package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"zt-control-plane-api/internal/eventkeyspec"
)

const (
	beginMarker = "# BEGIN GENERATED: EventSigningKeyAuditAction"
	endMarker   = "# END GENERATED: EventSigningKeyAuditAction"
)

func main() {
	var openapiPath string
	var write bool
	flag.StringVar(&openapiPath, "openapi", "", "Path to OpenAPI yaml")
	flag.BoolVar(&write, "write", true, "Write file in-place")
	flag.Parse()

	if strings.TrimSpace(openapiPath) == "" {
		cwd, _ := os.Getwd()
		openapiPath = filepath.Clean(filepath.Join(cwd, "../../docs/openapi/control-plane-v1.yaml"))
	}

	b, err := os.ReadFile(openapiPath)
	if err != nil {
		fatalf("read openapi: %v", err)
	}
	out, err := replaceGeneratedBlock(string(b), renderAuditActionEnumBlock())
	if err != nil {
		fatalf("sync enum: %v", err)
	}
	if !write {
		fmt.Print(out)
		return
	}
	if bytes.Equal([]byte(out), b) {
		fmt.Fprintf(os.Stderr, "no changes: %s\n", openapiPath)
		return
	}
	if err := os.WriteFile(openapiPath, []byte(out), 0o644); err != nil {
		fatalf("write openapi: %v", err)
	}
	fmt.Fprintf(os.Stderr, "updated: %s\n", openapiPath)
}

func renderAuditActionEnumBlock() string {
	lines := []string{
		"      enum:",
		"        " + beginMarker,
	}
	for _, v := range eventkeyspec.AllAuditActionStrings() {
		lines = append(lines, "        - "+v)
	}
	lines = append(lines, "        "+endMarker)
	return strings.Join(lines, "\n")
}

func replaceGeneratedBlock(src, replacement string) (string, error) {
	beginIdx := strings.Index(src, beginMarker)
	endIdx := strings.Index(src, endMarker)
	if beginIdx < 0 || endIdx < 0 || endIdx < beginIdx {
		return "", fmt.Errorf("markers not found")
	}

	lineStart := strings.LastIndex(src[:beginIdx], "\n")
	if lineStart < 0 {
		lineStart = 0
	} else {
		lineStart++
	}
	lineEnd := strings.Index(src[endIdx:], "\n")
	if lineEnd < 0 {
		lineEnd = len(src)
	} else {
		lineEnd = endIdx + lineEnd
	}
	return src[:lineStart] + replacement + src[lineEnd:], nil
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
