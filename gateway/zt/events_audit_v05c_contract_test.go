package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditVerifyCLI_SuccessAndFailureContract(t *testing.T) {
	repoRoot := t.TempDir()
	spool := newEventSpool(repoRoot)
	spool.SetAutoSync(false)
	if err := spool.appendAuditEvent("/v1/events/verify", map[string]any{
		"event_id": "evt_audit_cli_contract",
		"result":   "verified",
	}); err != nil {
		t.Fatalf("appendAuditEvent: %v", err)
	}

	okOut := captureStdout(t, func() {
		code := runAuditCommand(repoRoot, []string{"verify", "--file", spool.auditPath()})
		if code != 0 {
			t.Fatalf("runAuditCommand(success) code=%d, want 0", code)
		}
	})
	if !strings.Contains(okOut, "[AUDIT] Verify target: "+spool.auditPath()) {
		t.Fatalf("success output missing verify target:\n%s", okOut)
	}
	if !strings.Contains(okOut, "[AUDIT] PASS: audit events contract verified") {
		t.Fatalf("success output missing PASS marker:\n%s", okOut)
	}

	missingPath := filepath.Join(repoRoot, ".zt-spool", "missing-events.jsonl")
	failOut := captureStdout(t, func() {
		code := runAuditCommand(repoRoot, []string{"verify", "--file", missingPath})
		if code != 1 {
			t.Fatalf("runAuditCommand(failure) code=%d, want 1", code)
		}
	})
	if !strings.Contains(failOut, "ZT_ERROR_CODE="+ztErrorCodeAuditVerifyFailed) {
		t.Fatalf("failure output missing ZT error code:\n%s", failOut)
	}
	if !strings.Contains(failOut, "[AUDIT] FAIL:") {
		t.Fatalf("failure output missing FAIL marker:\n%s", failOut)
	}
}

func TestAuditVerifyFailClosedContract_KeyMissing(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(10 + i)
	}
	t.Setenv("ZT_AUDIT_SIGNING_ED25519_PRIV_B64", base64.StdEncoding.EncodeToString(seed))

	repoRoot := t.TempDir()
	spool := newEventSpool(repoRoot)
	spool.SetAutoSync(false)
	if err := spool.appendAuditEvent("/v1/events/scan", map[string]any{
		"event_id": "evt_fail_closed_key_missing",
		"command":  "send",
		"result":   "allow",
	}); err != nil {
		t.Fatalf("appendAuditEvent: %v", err)
	}

	t.Setenv("ZT_AUDIT_SIGNING_ED25519_PRIV_B64", "")
	t.Setenv("ZT_AUDIT_SIGNING_ED25519_PUB_B64", "")
	t.Setenv("ZT_AUDIT_VERIFY_ED25519_PUBKEYS_B64", "")
	t.Setenv("ZT_AUDIT_VERIFY_REQUIRE_SIGNATURE", "1")
	if err := verifyAuditEventsFileFromEnv(spool.auditPath()); err == nil {
		t.Fatalf("verifyAuditEventsFileFromEnv returned nil, want error")
	} else if !strings.Contains(err.Error(), "public key is not configured") {
		t.Fatalf("error = %q, want contains %q", err.Error(), "public key is not configured")
	}
}

func TestAuditVerifyFailClosedContract_SignatureMissing(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(70 + i)
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)

	t.Setenv("ZT_AUDIT_SIGNING_ED25519_PRIV_B64", "")
	t.Setenv("ZT_AUDIT_SIGNING_ED25519_PUB_B64", base64.StdEncoding.EncodeToString(pub))
	t.Setenv("ZT_AUDIT_VERIFY_ED25519_PUBKEYS_B64", "")
	t.Setenv("ZT_AUDIT_VERIFY_REQUIRE_SIGNATURE", "1")

	repoRoot := t.TempDir()
	spool := newEventSpool(repoRoot)
	spool.SetAutoSync(false)
	if err := spool.appendAuditEvent("/v1/events/verify", map[string]any{
		"event_id": "evt_fail_closed_signature_missing",
		"result":   "verified",
	}); err != nil {
		t.Fatalf("appendAuditEvent: %v", err)
	}

	if err := verifyAuditEventsFileFromEnv(spool.auditPath()); err == nil {
		t.Fatalf("verifyAuditEventsFileFromEnv returned nil, want error")
	} else if !strings.Contains(err.Error(), "signature is required") {
		t.Fatalf("error = %q, want contains %q", err.Error(), "signature is required")
	}
}

func TestAuditVerifyKeyRotationContract_MultiPublicKeys(t *testing.T) {
	oldSeed := make([]byte, ed25519.SeedSize)
	newSeed := make([]byte, ed25519.SeedSize)
	for i := range oldSeed {
		oldSeed[i] = byte(20 + i)
		newSeed[i] = byte(140 + i)
	}
	oldPub := ed25519.NewKeyFromSeed(oldSeed).Public().(ed25519.PublicKey)
	newPub := ed25519.NewKeyFromSeed(newSeed).Public().(ed25519.PublicKey)

	repoRoot := t.TempDir()

	t.Setenv("ZT_AUDIT_SIGNING_ED25519_PRIV_B64", base64.StdEncoding.EncodeToString(oldSeed))
	spoolOld := newEventSpool(repoRoot)
	spoolOld.SetAutoSync(false)
	if err := spoolOld.appendAuditEvent("/v1/events/scan", map[string]any{
		"event_id": "evt_rotation_old_key",
		"command":  "send",
		"result":   "allow",
	}); err != nil {
		t.Fatalf("appendAuditEvent(old): %v", err)
	}

	t.Setenv("ZT_AUDIT_SIGNING_ED25519_PRIV_B64", base64.StdEncoding.EncodeToString(newSeed))
	spoolNew := newEventSpool(repoRoot)
	spoolNew.SetAutoSync(false)
	if err := spoolNew.appendAuditEvent("/v1/events/verify", map[string]any{
		"event_id": "evt_rotation_new_key",
		"result":   "verified",
	}); err != nil {
		t.Fatalf("appendAuditEvent(new): %v", err)
	}

	t.Setenv("ZT_AUDIT_SIGNING_ED25519_PRIV_B64", "")
	t.Setenv("ZT_AUDIT_SIGNING_ED25519_PUB_B64", "")
	t.Setenv("ZT_AUDIT_VERIFY_REQUIRE_SIGNATURE", "1")
	t.Setenv("ZT_AUDIT_VERIFY_ED25519_PUBKEYS_B64", base64.StdEncoding.EncodeToString(newPub))
	if err := verifyAuditEventsFileFromEnv(spoolOld.auditPath()); err == nil {
		t.Fatalf("verifyAuditEventsFileFromEnv(single key) returned nil, want error")
	}

	t.Setenv("ZT_AUDIT_VERIFY_ED25519_PUBKEYS_B64", strings.Join([]string{
		base64.StdEncoding.EncodeToString(newPub),
		base64.StdEncoding.EncodeToString(oldPub),
	}, ","))
	if err := verifyAuditEventsFileFromEnv(spoolOld.auditPath()); err != nil {
		t.Fatalf("verifyAuditEventsFileFromEnv(rotation keys): %v", err)
	}
}

func TestAuditVerifyLegacyV05AContract_RejectByDefault(t *testing.T) {
	path := writeLegacyV05AAuditLogContract(t)
	if err := verifyAuditEventsFile(path, auditVerifyOptions{}); err == nil {
		t.Fatalf("verifyAuditEventsFile returned nil, want error")
	} else if !strings.Contains(err.Error(), "legacy v0.5-A record requires compat mode") {
		t.Fatalf("error = %q, want contains %q", err.Error(), "legacy v0.5-A record requires compat mode")
	}
}

func TestAuditVerifyLegacyV05AContract_CompatMode(t *testing.T) {
	path := writeLegacyV05AAuditLogContract(t)

	if err := verifyAuditEventsFile(path, auditVerifyOptions{
		AllowLegacyV05A: true,
	}); err != nil {
		t.Fatalf("verifyAuditEventsFile(compat): %v", err)
	}

	if err := verifyAuditEventsFile(path, auditVerifyOptions{
		AllowLegacyV05A:  true,
		RequireSignature: true,
	}); err == nil {
		t.Fatalf("verifyAuditEventsFile(compat+require-signature) returned nil, want error")
	} else if !strings.Contains(err.Error(), "signature is required") {
		t.Fatalf("error = %q, want contains %q", err.Error(), "signature is required")
	}
}

func writeLegacyV05AAuditLogContract(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "events_v05a.jsonl")
	legacy := map[string]any{
		"event_id":       "evt_legacy_1",
		"event_type":     "verify",
		"timestamp":      "2026-02-24T00:00:00Z",
		"result":         "verified",
		"endpoint":       "/v1/events/verify",
		"payload_sha256": "abcd1234",
	}
	b, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		t.Fatalf("os.WriteFile(%s): %v", path, err)
	}
	return path
}
