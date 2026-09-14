package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRuntimeLeaseRoundTrip(t *testing.T) {
	manifest := testRuntimePermitManifest(t)
	pub, priv := generateRuntimePermitKey(t)
	now := time.Date(2026, 5, 26, 0, 0, 0, 0, time.UTC)
	permit, err := newRuntimePermitForManifest(manifest, "dev-a", "llama.cpp", "", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	permit, err = signRuntimePermit(permit, "rtp_test", priv)
	if err != nil {
		t.Fatal(err)
	}
	leasePath := filepath.Join(t.TempDir(), "lease.json")
	if err := writeRuntimeLeaseFile(leasePath, runtimeLeaseFileV1{
		SchemaVersion: runtimeLeaseSchemaV1,
		SavedAt:       now.Format(time.RFC3339),
		Permit:        permit,
	}); err != nil {
		t.Fatalf("writeRuntimeLeaseFile: %v", err)
	}
	lease, err := validateRuntimeLeaseForManifest(leasePath, manifest, "dev-a", "llama.cpp", now.Add(time.Minute), pub)
	if err != nil {
		t.Fatalf("validateRuntimeLeaseForManifest: %v", err)
	}
	if lease.Permit.PermitID != permit.PermitID {
		t.Fatalf("permit_id=%q, want %q", lease.Permit.PermitID, permit.PermitID)
	}
}

func TestRuntimeLeaseAcceptsBarePermitFile(t *testing.T) {
	manifest := testRuntimePermitManifest(t)
	pub, priv := generateRuntimePermitKey(t)
	now := time.Date(2026, 5, 26, 0, 0, 0, 0, time.UTC)
	permit, err := newRuntimePermitForManifest(manifest, "dev-a", "llama.cpp", "", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	permit, err = signRuntimePermit(permit, "rtp_test", priv)
	if err != nil {
		t.Fatal(err)
	}
	permitJSON, err := marshalModelJSON(permit)
	if err != nil {
		t.Fatal(err)
	}
	leasePath := filepath.Join(t.TempDir(), "permit.json")
	if err := os.WriteFile(leasePath, permitJSON, 0600); err != nil {
		t.Fatal(err)
	}
	lease, err := validateRuntimeLeaseForManifest(leasePath, manifest, "dev-a", "llama.cpp", now.Add(time.Minute), pub)
	if err != nil {
		t.Fatalf("validateRuntimeLeaseForManifest: %v", err)
	}
	if lease.SchemaVersion != runtimeLeaseSchemaV1 || lease.Permit.PermitID != permit.PermitID {
		t.Fatalf("unexpected synthesized lease: %+v", lease)
	}
}

func TestRuntimeLeaseRejectsTrailingJSON(t *testing.T) {
	manifest := testRuntimePermitManifest(t)
	_, priv := generateRuntimePermitKey(t)
	now := time.Date(2026, 5, 26, 0, 0, 0, 0, time.UTC)
	permit, err := newRuntimePermitForManifest(manifest, "dev-a", "fake", "", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	permit, err = signRuntimePermit(permit, "rtp_test", priv)
	if err != nil {
		t.Fatal(err)
	}
	leasePath := filepath.Join(t.TempDir(), "lease.json")
	if err := writeRuntimeLeaseFile(leasePath, runtimeLeaseFileV1{
		SchemaVersion: runtimeLeaseSchemaV1,
		SavedAt:       now.Format(time.RFC3339),
		Permit:        permit,
	}); err != nil {
		t.Fatalf("writeRuntimeLeaseFile: %v", err)
	}
	f, err := os.OpenFile(leasePath, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"extra":true}`); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	_ = f.Close()
	if _, err := readRuntimeLeaseFile(leasePath); err == nil {
		t.Fatalf("readRuntimeLeaseFile accepted trailing JSON")
	}
}
