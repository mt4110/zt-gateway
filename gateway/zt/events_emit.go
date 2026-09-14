package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func emitScanEventFromSecureScanJSON(command string, targetPath string, scanJSON []byte, decision policyDecision) {
	var m map[string]any
	if err := json.Unmarshal(scanJSON, &m); err != nil {
		return
	}
	if _, ok := m["target"]; !ok {
		m["target"] = targetPath
	}
	payload := map[string]any{
		"event_id":        fmt.Sprintf("evt_scan_%d", time.Now().UTC().UnixNano()),
		"occurred_at":     time.Now().UTC().Format(time.RFC3339Nano),
		"host_id":         hostID(),
		"tool_version":    ztVersion,
		"command":         command,
		"target_name":     filepath.Base(targetPath),
		"result":          stringField(m, "result"),
		"reason":          stringField(m, "reason"),
		"summary":         mapField(m, "summary"),
		"scanners":        sliceField(m, "scanners"),
		"policy":          mapField(m, "policy"),
		"provenance":      mapField(m, "provenance"),
		"rule_hash":       stringField(m, "rule_hash"),
		"policy_decision": normalizePolicyDecision(decision),
		"raw_scan":        m,
	}
	applyTeamBoundaryMetadata(payload)
	emitControlPlaneEvent("/v1/events/scan", payload)
}

func emitArtifactEvent(kind, artifactPath, inputPath, client string, ruleHash string, decision policyDecision, rebuildProvenance map[string]any) {
	sha := hashPathSHA256(artifactPath)
	if rebuildProvenance == nil {
		rebuildProvenance = map[string]any{}
	}
	payload := map[string]any{
		"event_id":           fmt.Sprintf("evt_art_%d", time.Now().UTC().UnixNano()),
		"occurred_at":        time.Now().UTC().Format(time.RFC3339Nano),
		"host_id":            hostID(),
		"tool_version":       ztVersion,
		"artifact_kind":      kind,
		"artifact_sha256":    sha,
		"file_name":          filepath.Base(inputPath),
		"sender_identity":    currentIdentity(),
		"recipient_name":     client,
		"signer_fingerprint": "",
		"policy_version":     "",
		"rule_hash":          ruleHash,
		"artifact_path":      artifactPath,
		"policy_decision":    normalizePolicyDecision(decision),
		"rebuild_provenance": rebuildProvenance,
	}
	applyTeamBoundaryMetadata(payload)
	emitControlPlaneEvent("/v1/events/artifact", payload)
}

func emitVerifyEvent(artifactPath string, ok bool, reason string, details string, decision policyDecision) {
	emitVerifyEventWithMeta(artifactPath, ok, reason, details, decision, nil)
}

func emitVerifyEventWithMeta(artifactPath string, ok bool, reason string, details string, decision policyDecision, meta map[string]any) {
	result := "failed"
	if ok {
		result = "verified"
	}
	decision = normalizePolicyDecision(decision)
	detailPayload := map[string]any{
		"path":    artifactPath,
		"message": details,
	}
	for k, v := range meta {
		if strings.TrimSpace(k) == "" {
			continue
		}
		detailPayload[k] = v
	}
	payload := map[string]any{
		"event_id":          fmt.Sprintf("evt_verify_%d", time.Now().UTC().UnixNano()),
		"occurred_at":       time.Now().UTC().Format(time.RFC3339Nano),
		"host_id":           hostID(),
		"tool_version":      ztVersion,
		"artifact_sha256":   hashPathSHA256(artifactPath),
		"artifact_kind":     artifactKindForPath(artifactPath),
		"verifier_identity": currentIdentity(),
		"result":            result,
		"reason":            reason,
		"policy_decision":   decision,
		"details":           detailPayload,
	}
	applyTeamBoundaryMetadata(payload)
	emitControlPlaneEvent("/v1/events/verify", payload)
}

func hashPathSHA256(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	h := sha256.New()
	if !info.IsDir() {
		f, err := os.Open(path)
		if err != nil {
			return ""
		}
		defer f.Close()
		if _, err := io.Copy(h, f); err != nil {
			return ""
		}
		return hex.EncodeToString(h.Sum(nil))
	}

	var files []string
	_ = filepath.Walk(path, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi == nil || fi.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(path, p)
		if err != nil {
			return nil
		}
		files = append(files, rel)
		return nil
	})
	sort.Strings(files)
	for _, rel := range files {
		_, _ = io.WriteString(h, rel+"\n")
		fp := filepath.Join(path, rel)
		f, err := os.Open(fp)
		if err != nil {
			continue
		}
		_, _ = io.Copy(h, f)
		f.Close()
		_, _ = io.WriteString(h, "\n")
	}
	return hex.EncodeToString(h.Sum(nil))
}

func sha256HexBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func loadEventEnvelopeSignerFromEnv() (*eventEnvelopeSigner, error) {
	raw := strings.TrimSpace(os.Getenv("ZT_EVENT_SIGNING_ED25519_PRIV_B64"))
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
	keyID := strings.TrimSpace(os.Getenv("ZT_EVENT_SIGNING_KEY_ID"))
	return &eventEnvelopeSigner{KeyID: keyID, Priv: ed25519.PrivateKey(b)}, nil
}

func (s *eventEnvelopeSigner) Wrap(endpoint string, payloadJSON []byte) ([]byte, error) {
	env := signedEventEnvelope{
		EnvelopeVersion: "zt-event-envelope-v1",
		Alg:             "Ed25519",
		KeyID:           s.KeyID,
		CreatedAt:       time.Now().UTC().Format(time.RFC3339Nano),
		Endpoint:        endpoint,
		PayloadSHA256:   sha256HexBytes(payloadJSON),
		Payload:         json.RawMessage(payloadJSON),
	}
	signingBytes, err := envelopeSigningBytes(env)
	if err != nil {
		return nil, err
	}
	env.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(s.Priv, signingBytes))
	return json.Marshal(env)
}

func envelopeSigningBytes(env signedEventEnvelope) ([]byte, error) {
	env.Signature = ""
	return json.Marshal(env)
}

func hostID() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "unknown-host"
}

func currentIdentity() string {
	u := strings.TrimSpace(os.Getenv("USER"))
	if u == "" {
		u = strings.TrimSpace(os.Getenv("USERNAME"))
	}
	if u == "" {
		return "unknown"
	}
	return u
}

func artifactKindForPath(p string) string {
	if stringsHasSuffixFold(p, ".spkg.tgz") {
		return "spkg.tgz"
	}
	if filepath.Base(p) == "artifact.zp" {
		return "artifact.zp"
	}
	if fi, err := os.Stat(p); err == nil && fi.IsDir() {
		return "artifact_dir"
	}
	return "unknown"
}

func stringField(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}

func mapField(m map[string]any, key string) map[string]any {
	v, _ := m[key].(map[string]any)
	if v == nil {
		return map[string]any{}
	}
	return v
}

func sliceField(m map[string]any, key string) []any {
	v, _ := m[key].([]any)
	if v == nil {
		return []any{}
	}
	return v
}
