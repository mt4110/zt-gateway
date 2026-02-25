package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

type auditEventRecord struct {
	EventID          string          `json:"event_id"`
	EventType        string          `json:"event_type"`
	Timestamp        string          `json:"timestamp"`
	Result           string          `json:"result"`
	PolicyDecision   *policyDecision `json:"policy_decision,omitempty"`
	Endpoint         string          `json:"endpoint"`
	PayloadSHA256    string          `json:"payload_sha256"`
	ChainVersion     string          `json:"chain_version"`
	PrevRecordSHA256 string          `json:"prev_record_sha256,omitempty"`
	RecordSHA256     string          `json:"record_sha256"`
	SignatureAlg     string          `json:"signature_alg,omitempty"`
	SignatureKeyID   string          `json:"signature_key_id,omitempty"`
	Signature        string          `json:"signature,omitempty"`
}

type auditPayloadFields struct {
	EventID        string
	Result         string
	Command        string
	PolicyDecision *policyDecision
}

type auditRecordSigner struct {
	KeyID string
	Priv  ed25519.PrivateKey
}

type auditVerifyOptions struct {
	RequireSignature bool
	PublicKey        ed25519.PublicKey
	PublicKeys       []ed25519.PublicKey
	AllowLegacyV05A  bool
}

func (s *eventSpool) auditPath() string { return filepath.Join(s.cfg.SpoolDir, "events.jsonl") }

func (s *eventSpool) appendAuditEvent(endpoint string, payload any) error {
	if s == nil {
		return nil
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return s.withFileLock(5*time.Second, func() error {
		prevHash, err := readLastAuditRecordHash(s.auditPath())
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		record := newAuditEventRecord(endpoint, payloadJSON, now, prevHash)
		if s.auditSig != nil {
			if err := s.auditSig.sign(&record); err != nil {
				return err
			}
		}
		return appendJSONLine(s.auditPath(), record)
	})
}

func newAuditEventRecord(endpoint string, payloadJSON []byte, now time.Time, prevHash string) auditEventRecord {
	fields := parseAuditPayloadFields(payloadJSON)
	eventID := strings.TrimSpace(fields.EventID)
	if eventID == "" {
		eventID = fmt.Sprintf("audit_evt_%d", now.UnixNano())
	}
	result := strings.TrimSpace(fields.Result)
	if result == "" {
		result = "recorded"
	}
	if fields.PolicyDecision != nil && strings.TrimSpace(fields.PolicyDecision.Decision) != "" {
		result = strings.TrimSpace(fields.PolicyDecision.Decision)
	}
	eventType := resolveAuditEventType(endpoint, fields.Command)
	record := auditEventRecord{
		EventID:        eventID,
		EventType:      eventType,
		Timestamp:      now.Format(time.RFC3339Nano),
		Result:         result,
		PolicyDecision: fields.PolicyDecision,
		Endpoint:       strings.TrimSpace(endpoint),
		PayloadSHA256:  sha256HexBytes(payloadJSON),
		ChainVersion:   "v1",
	}
	record.PrevRecordSHA256 = strings.TrimSpace(prevHash)
	record.RecordSHA256 = calculateAuditRecordSHA256(record)
	return record
}

func calculateAuditRecordSHA256(record auditEventRecord) string {
	canonical := strings.Join([]string{
		"chain_version=" + strings.TrimSpace(record.ChainVersion),
		"event_id=" + strings.TrimSpace(record.EventID),
		"event_type=" + strings.TrimSpace(record.EventType),
		"timestamp=" + strings.TrimSpace(record.Timestamp),
		"result=" + strings.TrimSpace(record.Result),
		"policy_decision=" + canonicalPolicyDecisionForHash(record.PolicyDecision),
		"endpoint=" + strings.TrimSpace(record.Endpoint),
		"payload_sha256=" + strings.TrimSpace(record.PayloadSHA256),
		"prev_record_sha256=" + strings.TrimSpace(record.PrevRecordSHA256),
	}, "\n")
	return sha256HexBytes([]byte(canonical))
}

func readLastAuditRecordHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	defer f.Close()

	var lastLine []byte
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		lastLine = []byte(line)
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	if len(lastLine) == 0 {
		return "", nil
	}
	var rec auditEventRecord
	if err := json.Unmarshal(lastLine, &rec); err != nil {
		return "", fmt.Errorf("audit log last line is malformed JSON: %w", err)
	}
	if hash := strings.TrimSpace(rec.RecordSHA256); hash != "" {
		return hash, nil
	}
	return calculateAuditRecordSHA256(rec), nil
}

func loadAuditRecordSignerFromEnv() (*auditRecordSigner, error) {
	raw := strings.TrimSpace(os.Getenv("ZT_AUDIT_SIGNING_ED25519_PRIV_B64"))
	if raw == "" {
		return nil, nil
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	switch len(b) {
	case ed25519.SeedSize:
		b = ed25519.NewKeyFromSeed(b)
	case ed25519.PrivateKeySize:
	default:
		return nil, fmt.Errorf("expected %d-byte seed or %d-byte private key, got %d", ed25519.SeedSize, ed25519.PrivateKeySize, len(b))
	}
	keyID := strings.TrimSpace(os.Getenv("ZT_AUDIT_SIGNING_KEY_ID"))
	return &auditRecordSigner{KeyID: keyID, Priv: ed25519.PrivateKey(b)}, nil
}

func (s *auditRecordSigner) sign(record *auditEventRecord) error {
	if s == nil || record == nil {
		return nil
	}
	hash := strings.TrimSpace(record.RecordSHA256)
	if hash == "" {
		return fmt.Errorf("record_sha256 is empty")
	}
	record.SignatureAlg = "Ed25519"
	record.SignatureKeyID = s.KeyID
	record.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(s.Priv, []byte(hash)))
	return nil
}

func loadAuditVerifyPublicKeyFromEnv() (ed25519.PublicKey, error) {
	keys, err := loadAuditVerifyPublicKeysFromEnv()
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, nil
	}
	return keys[0], nil
}

func loadAuditVerifyPublicKeysFromEnv() ([]ed25519.PublicKey, error) {
	combined := make([]ed25519.PublicKey, 0, 4)

	listRaw := strings.TrimSpace(os.Getenv("ZT_AUDIT_VERIFY_ED25519_PUBKEYS_B64"))
	if listRaw != "" {
		tokens := strings.FieldsFunc(listRaw, func(r rune) bool {
			return r == ',' || r == ';' || r == '\n' || r == '\r' || r == '\t' || r == ' '
		})
		for i, token := range tokens {
			pub, err := decodeAuditPublicKeyB64(token)
			if err != nil {
				return nil, fmt.Errorf("ZT_AUDIT_VERIFY_ED25519_PUBKEYS_B64[%d]: %w", i, err)
			}
			combined = append(combined, pub)
		}
	}

	pubRaw := strings.TrimSpace(os.Getenv("ZT_AUDIT_SIGNING_ED25519_PUB_B64"))
	if pubRaw != "" {
		pub, err := decodeAuditPublicKeyB64(pubRaw)
		if err != nil {
			return nil, fmt.Errorf("ZT_AUDIT_SIGNING_ED25519_PUB_B64: %w", err)
		}
		combined = append(combined, pub)
	}

	privRaw := strings.TrimSpace(os.Getenv("ZT_AUDIT_SIGNING_ED25519_PRIV_B64"))
	if privRaw != "" {
		privPub, err := deriveAuditPublicKeyFromPrivateB64(privRaw)
		if err != nil {
			return nil, fmt.Errorf("ZT_AUDIT_SIGNING_ED25519_PRIV_B64: %w", err)
		}
		combined = append(combined, privPub)
	}
	return dedupeAuditPublicKeys(combined), nil
}

func decodeAuditPublicKeyB64(raw string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("expected %d-byte audit public key, got %d", ed25519.PublicKeySize, len(b))
	}
	return ed25519.PublicKey(b), nil
}

func deriveAuditPublicKeyFromPrivateB64(raw string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}
	switch len(b) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(b).Public().(ed25519.PublicKey), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(b).Public().(ed25519.PublicKey), nil
	default:
		return nil, fmt.Errorf("expected %d-byte seed or %d-byte private key, got %d", ed25519.SeedSize, ed25519.PrivateKeySize, len(b))
	}
}

func dedupeAuditPublicKeys(in []ed25519.PublicKey) []ed25519.PublicKey {
	if len(in) == 0 {
		return nil
	}
	out := make([]ed25519.PublicKey, 0, len(in))
	seen := map[string]struct{}{}
	for _, key := range in {
		if len(key) != ed25519.PublicKeySize {
			continue
		}
		fp := base64.StdEncoding.EncodeToString(key)
		if _, exists := seen[fp]; exists {
			continue
		}
		seen[fp] = struct{}{}
		out = append(out, key)
	}
	return out
}

func verifyAuditEventsFile(path string, opts auditVerifyOptions) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	verifyKeys := dedupeAuditPublicKeys(appendAuditPublicKeys(opts.PublicKeys, opts.PublicKey))
	scanner := bufio.NewScanner(f)
	expectedPrev := ""
	lineNo := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		lineNo++
		var rec auditEventRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			return fmt.Errorf("line %d: invalid audit JSON: %w", lineNo, err)
		}
		if isLegacyAuditRecordV05A(rec) {
			if !opts.AllowLegacyV05A {
				return fmt.Errorf("line %d: legacy v0.5-A record requires compat mode", lineNo)
			}
			if err := validateLegacyAuditRecordV05A(rec, lineNo, opts.RequireSignature); err != nil {
				return err
			}
			// Keep chain continuity for mixed v0.5-A -> v1 logs by deriving the same
			// fallback hash used by append-time predecessor lookup.
			expectedPrev = calculateAuditRecordSHA256(rec)
			continue
		}
		if strings.TrimSpace(rec.ChainVersion) == "" {
			return fmt.Errorf("line %d: chain_version is empty", lineNo)
		}
		if strings.TrimSpace(rec.RecordSHA256) == "" {
			return fmt.Errorf("line %d: record_sha256 is empty", lineNo)
		}
		if gotPrev := strings.TrimSpace(rec.PrevRecordSHA256); gotPrev != expectedPrev {
			return fmt.Errorf("line %d: prev_record_sha256 mismatch: got=%q want=%q", lineNo, gotPrev, expectedPrev)
		}
		wantHash := calculateAuditRecordSHA256(rec)
		if strings.TrimSpace(rec.RecordSHA256) != wantHash {
			return fmt.Errorf("line %d: record_sha256 mismatch", lineNo)
		}
		sig := strings.TrimSpace(rec.Signature)
		if opts.RequireSignature && sig == "" {
			return fmt.Errorf("line %d: signature is required", lineNo)
		}
		if sig != "" {
			if strings.TrimSpace(rec.SignatureAlg) != "Ed25519" {
				return fmt.Errorf("line %d: unsupported signature_alg %q", lineNo, rec.SignatureAlg)
			}
			if len(verifyKeys) == 0 {
				return fmt.Errorf("line %d: audit verify public key is not configured", lineNo)
			}
			sigBytes, err := base64.StdEncoding.DecodeString(sig)
			if err != nil {
				return fmt.Errorf("line %d: invalid signature encoding: %w", lineNo, err)
			}
			if !verifyAuditRecordSignatureAnyKey(verifyKeys, rec.RecordSHA256, sigBytes) {
				return fmt.Errorf("line %d: signature verification failed", lineNo)
			}
		}
		expectedPrev = rec.RecordSHA256
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

func verifyAuditEventsFileFromEnv(path string) error {
	keys, err := loadAuditVerifyPublicKeysFromEnv()
	if err != nil {
		return err
	}
	return verifyAuditEventsFile(path, auditVerifyOptions{
		RequireSignature: envBool("ZT_AUDIT_VERIFY_REQUIRE_SIGNATURE"),
		PublicKeys:       keys,
		AllowLegacyV05A:  envBool("ZT_AUDIT_VERIFY_ALLOW_LEGACY_V05A"),
	})
}

func appendAuditPublicKeys(keys []ed25519.PublicKey, key ed25519.PublicKey) []ed25519.PublicKey {
	if len(key) == 0 {
		return keys
	}
	return append(append([]ed25519.PublicKey(nil), keys...), key)
}

func verifyAuditRecordSignatureAnyKey(keys []ed25519.PublicKey, recordHash string, sig []byte) bool {
	for _, key := range keys {
		if ed25519.Verify(key, []byte(recordHash), sig) {
			return true
		}
	}
	return false
}

func isLegacyAuditRecordV05A(rec auditEventRecord) bool {
	return strings.TrimSpace(rec.ChainVersion) == "" && strings.TrimSpace(rec.RecordSHA256) == ""
}

func validateLegacyAuditRecordV05A(rec auditEventRecord, lineNo int, requireSignature bool) error {
	required := []struct {
		name  string
		value string
	}{
		{name: "event_id", value: rec.EventID},
		{name: "event_type", value: rec.EventType},
		{name: "timestamp", value: rec.Timestamp},
		{name: "result", value: rec.Result},
		{name: "endpoint", value: rec.Endpoint},
		{name: "payload_sha256", value: rec.PayloadSHA256},
	}
	for _, field := range required {
		if strings.TrimSpace(field.value) == "" {
			return fmt.Errorf("line %d: legacy record %s is empty", lineNo, field.name)
		}
	}
	if requireSignature {
		return fmt.Errorf("line %d: signature is required", lineNo)
	}
	return nil
}

func parseAuditPayloadFields(payloadJSON []byte) auditPayloadFields {
	var payload map[string]any
	if err := json.Unmarshal(payloadJSON, &payload); err != nil || payload == nil {
		return auditPayloadFields{}
	}
	var dec *policyDecision
	if m, ok := mapFromAnyMap(payload, "policy_decision"); ok {
		candidate := policyDecision{
			Decision:      stringFromAnyMap(m, "decision"),
			ReasonCode:    stringFromAnyMap(m, "reason_code"),
			ManifestID:    stringFromAnyMap(m, "manifest_id"),
			Profile:       stringFromAnyMap(m, "profile"),
			RuleHash:      stringFromAnyMap(m, "rule_hash"),
			ErrorClass:    stringFromAnyMap(m, "error_class"),
			ErrorCode:     stringFromAnyMap(m, "error_code"),
			Source:        stringFromAnyMap(m, "source"),
			MinGatewayVer: stringFromAnyMap(m, "min_gateway_version"),
		}
		n := normalizePolicyDecision(candidate)
		dec = &n
	}
	return auditPayloadFields{
		EventID:        stringFromAnyMap(payload, "event_id"),
		Result:         stringFromAnyMap(payload, "result"),
		Command:        stringFromAnyMap(payload, "command"),
		PolicyDecision: dec,
	}
}

func canonicalPolicyDecisionForHash(dec *policyDecision) string {
	if dec == nil {
		return ""
	}
	n := normalizePolicyDecision(*dec)
	return strings.Join([]string{
		n.Decision,
		n.ReasonCode,
		n.ManifestID,
		n.Profile,
		n.RuleHash,
		n.ErrorClass,
		n.ErrorCode,
		n.Source,
		n.MinGatewayVer,
	}, "|")
}

func resolveAuditEventType(endpoint, command string) string {
	if c := strings.TrimSpace(command); c != "" {
		return c
	}
	tail := path.Base(strings.TrimSpace(endpoint))
	if tail == "" || tail == "." || tail == "/" {
		return "unknown"
	}
	return tail
}

func stringFromAnyMap(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}

func mapFromAnyMap(m map[string]any, key string) (map[string]any, bool) {
	v, ok := m[key].(map[string]any)
	return v, ok
}
