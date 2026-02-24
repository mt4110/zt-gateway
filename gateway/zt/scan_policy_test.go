package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDefaultScanPolicySecureDefaults(t *testing.T) {
	got := defaultScanPolicy()
	if got.Source != "built-in secure defaults" {
		t.Fatalf("Source = %q, want built-in secure defaults", got.Source)
	}
	if !got.RequireClamAVDB {
		t.Fatalf("RequireClamAVDB = false, want true")
	}
	wantScanners := []string{"ClamAV", "YARA"}
	if !reflect.DeepEqual(got.RequiredScanners, wantScanners) {
		t.Fatalf("RequiredScanners = %#v, want %#v", got.RequiredScanners, wantScanners)
	}
}

func TestLoadScanPolicyMissingReturnsSecureDefaultsWithError(t *testing.T) {
	got, err := loadScanPolicy(filepath.Join(t.TempDir(), "missing.toml"))
	if err == nil {
		t.Fatalf("expected error for missing file")
	}
	if !got.RequireClamAVDB {
		t.Fatalf("RequireClamAVDB = false, want true")
	}
	if len(got.RequiredScanners) == 0 {
		t.Fatalf("RequiredScanners empty, want secure defaults")
	}
}

func TestLoadScanPolicyParsesOverrides(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "scan_policy.toml")
	body := "required_scanners = [\"ClamAV\"]\nrequire_clamav_db = false\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := loadScanPolicy(path)
	if err != nil {
		t.Fatalf("loadScanPolicy returned error: %v", err)
	}
	if got.Source != path {
		t.Fatalf("Source = %q, want %q", got.Source, path)
	}
	if got.RequireClamAVDB {
		t.Fatalf("RequireClamAVDB = true, want false")
	}
	wantScanners := []string{"ClamAV"}
	if !reflect.DeepEqual(got.RequiredScanners, wantScanners) {
		t.Fatalf("RequiredScanners = %#v, want %#v", got.RequiredScanners, wantScanners)
	}
}
