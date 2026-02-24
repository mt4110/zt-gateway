package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestEmitDoctorJSON_IncludesErrorCodeField(t *testing.T) {
	tmp := t.TempDir()
	outPath := filepath.Join(tmp, "doctor.json")
	f, err := os.Create(outPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	origStdout := os.Stdout
	os.Stdout = f
	defer func() { os.Stdout = origStdout }()

	emitDoctorJSON(doctorResult{OK: false, ErrorCode: ztErrorCodeConfigDoctorFailed, SchemaVersion: 1})
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("json.Unmarshal failed: %v\n%s", err, data)
	}
	if got["error_code"] != ztErrorCodeConfigDoctorFailed {
		t.Fatalf("error_code = %v", got["error_code"])
	}
}
