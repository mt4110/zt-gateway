package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultExtensionPolicyHasSecureFailClosedBasics(t *testing.T) {
	got := defaultExtensionPolicy()
	if got.Source != "built-in defaults" {
		t.Fatalf("Source = %q, want built-in defaults", got.Source)
	}
	if got.MaxSizeMB <= 0 {
		t.Fatalf("MaxSizeMB = %d, want > 0", got.MaxSizeMB)
	}
	if mode, ok := got.Table[".exe"]; !ok || mode != ExtModeDeny {
		t.Fatalf(".exe mode = %q, want %q", mode, ExtModeDeny)
	}
	if mode, ok := got.Table[".txt"]; !ok || mode != ExtModeScanOnly {
		t.Fatalf(".txt mode = %q, want %q", mode, ExtModeScanOnly)
	}
}

func TestLoadExtensionPolicyParsesOverrides(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "extension_policy.toml")
	body := `
max_size_mb = 10
deny_extensions = [".bin"]
scan_only_extensions = [".txt"]
scan_rebuild_extensions = [".png"]
force_rebuild_extensions = [".png"]
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := loadExtensionPolicy(path)
	if err != nil {
		t.Fatalf("loadExtensionPolicy returned error: %v", err)
	}
	if got.Source != path {
		t.Fatalf("Source = %q, want %q", got.Source, path)
	}
	if got.MaxSizeMB != 10 {
		t.Fatalf("MaxSizeMB = %d, want 10", got.MaxSizeMB)
	}
	if got.Table[".bin"] != ExtModeDeny {
		t.Fatalf(".bin mode = %q, want %q", got.Table[".bin"], ExtModeDeny)
	}
	if got.Table[".txt"] != ExtModeScanOnly {
		t.Fatalf(".txt mode = %q, want %q", got.Table[".txt"], ExtModeScanOnly)
	}
	if got.Table[".png"] != ExtModeScanRebuild {
		t.Fatalf(".png mode = %q, want %q", got.Table[".png"], ExtModeScanRebuild)
	}
	if _, ok := got.ForceRebuildExtensions[".png"]; !ok {
		t.Fatalf("ForceRebuildExtensions missing .png")
	}
}
