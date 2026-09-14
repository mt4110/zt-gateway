package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const runtimeLeaseSchemaV1 = "zt-runtime-lease-v1"

type runtimeLeaseFileV1 struct {
	SchemaVersion string          `json:"schema_version"`
	SavedAt       string          `json:"saved_at"`
	Permit        runtimePermitV1 `json:"permit"`
}

func writeRuntimeLeaseFile(path string, lease runtimeLeaseFileV1) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("lease path is required")
	}
	if strings.TrimSpace(lease.SchemaVersion) == "" {
		lease.SchemaVersion = runtimeLeaseSchemaV1
	}
	if strings.TrimSpace(lease.SavedAt) == "" {
		lease.SavedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if err := validateRuntimeLeaseShape(lease); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(lease)
}

func readRuntimeLeaseFile(path string) (runtimeLeaseFileV1, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return runtimeLeaseFileV1{}, err
	}
	var probe struct {
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return runtimeLeaseFileV1{}, err
	}
	if strings.TrimSpace(probe.SchemaVersion) == runtimePermitSchemaV1 {
		var permit runtimePermitV1
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&permit); err != nil {
			return runtimeLeaseFileV1{}, err
		}
		if err := rejectTrailingRuntimeLeaseJSON(dec); err != nil {
			return runtimeLeaseFileV1{}, err
		}
		lease := runtimeLeaseFromPermit(permit)
		if err := validateRuntimeLeaseShape(lease); err != nil {
			return runtimeLeaseFileV1{}, err
		}
		return lease, nil
	}
	var lease runtimeLeaseFileV1
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&lease); err != nil {
		return runtimeLeaseFileV1{}, err
	}
	if err := rejectTrailingRuntimeLeaseJSON(dec); err != nil {
		return runtimeLeaseFileV1{}, err
	}
	if err := validateRuntimeLeaseShape(lease); err != nil {
		return runtimeLeaseFileV1{}, err
	}
	return lease, nil
}

func rejectTrailingRuntimeLeaseJSON(dec *json.Decoder) error {
	var extra struct{}
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing JSON content is not allowed")
		}
		return err
	}
	return nil
}

func runtimeLeaseFromPermit(permit runtimePermitV1) runtimeLeaseFileV1 {
	savedAt := time.Now().UTC().Format(time.RFC3339)
	if notBefore, err := time.Parse(time.RFC3339, strings.TrimSpace(permit.Validity.NotBefore)); err == nil {
		savedAt = notBefore.UTC().Format(time.RFC3339)
	}
	return runtimeLeaseFileV1{
		SchemaVersion: runtimeLeaseSchemaV1,
		SavedAt:       savedAt,
		Permit:        permit,
	}
}

func validateRuntimeLeaseForManifest(path string, manifest modelCapsuleManifestV1, expectedDeviceID, expectedRuntimeName string, now time.Time, pub ed25519.PublicKey) (runtimeLeaseFileV1, error) {
	lease, err := readRuntimeLeaseFile(path)
	if err != nil {
		return runtimeLeaseFileV1{}, err
	}
	if err := validateRuntimePermitForManifest(lease.Permit, manifest, expectedDeviceID, expectedRuntimeName, now, pub); err != nil {
		return runtimeLeaseFileV1{}, err
	}
	return lease, nil
}

func validateRuntimeLeaseShape(lease runtimeLeaseFileV1) error {
	if strings.TrimSpace(lease.SchemaVersion) != runtimeLeaseSchemaV1 {
		return fmt.Errorf("invalid runtime lease schema_version: %q", lease.SchemaVersion)
	}
	if _, err := time.Parse(time.RFC3339, strings.TrimSpace(lease.SavedAt)); err != nil {
		return fmt.Errorf("lease saved_at must be RFC3339: %w", err)
	}
	return validateRuntimePermitShape(lease.Permit)
}
