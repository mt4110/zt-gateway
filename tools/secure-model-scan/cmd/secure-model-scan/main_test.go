package main

import (
	"errors"
	"testing"

	"github.com/mt4110/zt-gateway/tools/secure-model-scan/internal/scan"
)

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

func TestWriteJSONResultReturnsEncodeError(t *testing.T) {
	err := writeJSONResult(failingWriter{}, scan.Result{SchemaVersion: scan.SchemaVersion})
	if err == nil {
		t.Fatalf("writeJSONResult returned nil, want write error")
	}
}
