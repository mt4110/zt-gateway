package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
)

func TestAuditEventsJSONL_SignatureContract(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	t.Setenv("ZT_AUDIT_SIGNING_ED25519_PRIV_B64", base64.StdEncoding.EncodeToString(seed))
	t.Setenv("ZT_AUDIT_SIGNING_KEY_ID", "audit-key-contract")

	repoRoot := t.TempDir()
	spool := newEventSpool(repoRoot)
	spool.SetAutoSync(false)

	if err := spool.appendAuditEvent("/v1/events/verify", map[string]any{
		"event_id": "evt_sig_1",
		"result":   "verified",
	}); err != nil {
		t.Fatalf("appendAuditEvent: %v", err)
	}

	records := readAuditEventRecordsContract(t, spool.auditPath())
	if len(records) != 1 {
		t.Fatalf("records len = %d, want 1", len(records))
	}
	record := records[0]
	if record.SignatureAlg != "Ed25519" {
		t.Fatalf("signature_alg = %q, want Ed25519", record.SignatureAlg)
	}
	if record.SignatureKeyID != "audit-key-contract" {
		t.Fatalf("signature_key_id = %q, want audit-key-contract", record.SignatureKeyID)
	}
	if strings.TrimSpace(record.Signature) == "" {
		t.Fatalf("signature is empty")
	}

	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if err := verifyAuditEventsFile(spool.auditPath(), auditVerifyOptions{
		RequireSignature: true,
		PublicKey:        pub,
	}); err != nil {
		t.Fatalf("verifyAuditEventsFile(require signature): %v", err)
	}
}

func TestAuditEventsJSONL_SignatureOptionalContract(t *testing.T) {
	t.Setenv("ZT_AUDIT_SIGNING_ED25519_PRIV_B64", "")
	t.Setenv("ZT_AUDIT_SIGNING_KEY_ID", "")

	repoRoot := t.TempDir()
	spool := newEventSpool(repoRoot)
	spool.SetAutoSync(false)

	if err := spool.appendAuditEvent("/v1/events/scan", map[string]any{
		"event_id": "evt_sig_optional_1",
		"command":  "send",
		"result":   "allow",
	}); err != nil {
		t.Fatalf("appendAuditEvent: %v", err)
	}

	records := readAuditEventRecordsContract(t, spool.auditPath())
	if len(records) != 1 {
		t.Fatalf("records len = %d, want 1", len(records))
	}
	if records[0].Signature != "" {
		t.Fatalf("signature = %q, want empty", records[0].Signature)
	}
	if err := verifyAuditEventsFile(spool.auditPath(), auditVerifyOptions{}); err != nil {
		t.Fatalf("verifyAuditEventsFile(no signature requirement): %v", err)
	}
}
