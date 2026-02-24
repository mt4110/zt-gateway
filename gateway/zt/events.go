package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const ztVersion = "v0.1.0-dev"

var cpEvents *eventSpool

type controlPlaneConfig struct {
	BaseURL  string
	APIKey   string
	SpoolDir string
}

type eventSpool struct {
	cfg      controlPlaneConfig
	client   *http.Client
	signer   *eventEnvelopeSigner
	autoSync bool
}

type queuedEvent struct {
	QueueID     string          `json:"queue_id"`
	Endpoint    string          `json:"endpoint"`
	EnqueuedAt  string          `json:"enqueued_at"`
	Attempts    int             `json:"attempts"`
	NextRetryAt string          `json:"next_retry_at,omitempty"`
	LastError   string          `json:"last_error,omitempty"`
	Payload     json.RawMessage `json:"payload"`
}

type syncResult struct {
	Sent       int
	Remaining  int
	Skipped    int
	LastError  string
	Configured bool
}

type eventEnvelopeSigner struct {
	KeyID string
	Priv  ed25519.PrivateKey
}

type signedEventEnvelope struct {
	EnvelopeVersion string          `json:"envelope_version"`
	Alg             string          `json:"alg"`
	KeyID           string          `json:"key_id,omitempty"`
	CreatedAt       string          `json:"created_at"`
	Endpoint        string          `json:"endpoint"`
	PayloadSHA256   string          `json:"payload_sha256"`
	Payload         json.RawMessage `json:"payload"`
	Signature       string          `json:"signature"`
}

func newEventSpool(repoRoot string) *eventSpool {
	spoolDir := strings.TrimSpace(os.Getenv("ZT_EVENT_SPOOL_DIR"))
	if spoolDir == "" {
		spoolDir = filepath.Join(repoRoot, ".zt-spool")
	}
	cfg := controlPlaneConfig{
		BaseURL:  strings.TrimRight(strings.TrimSpace(os.Getenv("ZT_CONTROL_PLANE_URL")), "/"),
		APIKey:   strings.TrimSpace(os.Getenv("ZT_CONTROL_PLANE_API_KEY")),
		SpoolDir: spoolDir,
	}
	signer, err := loadEventEnvelopeSignerFromEnv()
	if err != nil {
		if !suppressStartupDiagnostics {
			fmt.Fprintf(os.Stderr, "[Events] WARN invalid event signing key: %v\n", err)
		}
	}
	return &eventSpool{
		cfg: cfg,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		signer:   signer,
		autoSync: true,
	}
}

func runSyncEvents(force bool) {
	if cpEvents == nil {
		fmt.Println("[SYNC] event spool is not initialized")
		os.Exit(1)
	}
	res, err := cpEvents.Sync(force)
	if err != nil {
		fmt.Printf("[SYNC] failed: %v\n", err)
		os.Exit(1)
	}
	if !res.Configured {
		fmt.Printf("[SYNC] no control-plane URL configured. pending=%d (spooled locally)\n", res.Remaining)
		return
	}
	fmt.Printf("[SYNC] sent=%d remaining=%d skipped=%d force=%t\n", res.Sent, res.Remaining, res.Skipped, force)
	if res.LastError != "" {
		fmt.Printf("[SYNC] last_error=%s\n", res.LastError)
	}
}

func emitControlPlaneEvent(endpoint string, payload any) {
	if cpEvents == nil {
		return
	}
	if err := cpEvents.Enqueue(endpoint, payload); err != nil {
		fmt.Fprintf(os.Stderr, "[Events] WARN enqueue failed (%s): %v\n", endpoint, err)
		return
	}
	if cpEvents.cfg.BaseURL != "" && cpEvents.autoSync {
		if _, err := cpEvents.Sync(false); err != nil {
			fmt.Fprintf(os.Stderr, "[Events] WARN sync failed: %v\n", err)
		}
	}
}

func (s *eventSpool) SetAutoSync(enabled bool) {
	if s == nil {
		return
	}
	s.autoSync = enabled
}

func (s *eventSpool) SetControlPlaneURL(url string) {
	if s == nil {
		return
	}
	s.cfg.BaseURL = strings.TrimRight(strings.TrimSpace(url), "/")
}

func (s *eventSpool) SetAPIKey(key string) {
	if s == nil {
		return
	}
	s.cfg.APIKey = strings.TrimSpace(key)
}

func (s *eventSpool) pendingPath() string { return filepath.Join(s.cfg.SpoolDir, "pending.jsonl") }
func (s *eventSpool) sentPath() string    { return filepath.Join(s.cfg.SpoolDir, "sent.jsonl") }
func (s *eventSpool) lockPath() string    { return filepath.Join(s.cfg.SpoolDir, ".lock") }

func (s *eventSpool) Enqueue(endpoint string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if s.signer != nil {
		body, err = s.signer.Wrap(endpoint, body)
		if err != nil {
			return err
		}
	}
	q := queuedEvent{
		QueueID:     fmt.Sprintf("q_%d", time.Now().UTC().UnixNano()),
		Endpoint:    endpoint,
		EnqueuedAt:  time.Now().UTC().Format(time.RFC3339Nano),
		Attempts:    0,
		NextRetryAt: time.Now().UTC().Format(time.RFC3339Nano),
		Payload:     body,
	}
	return s.withFileLock(5*time.Second, func() error {
		return appendJSONLine(s.pendingPath(), q)
	})
}

func (s *eventSpool) Sync(force bool) (syncResult, error) {
	res := syncResult{}
	err := s.withFileLock(15*time.Second, func() error {
		pending, err := readQueuedEvents(s.pendingPath())
		if err != nil {
			if os.IsNotExist(err) {
				res.Configured = s.cfg.BaseURL != ""
				return nil
			}
			return err
		}
		res.Remaining = len(pending)
		res.Configured = s.cfg.BaseURL != ""
		if len(pending) == 0 || s.cfg.BaseURL == "" {
			return nil
		}

		kept := make([]queuedEvent, 0, len(pending))
		for _, q := range pending {
			if !force && !readyForRetry(q, time.Now().UTC()) {
				res.Skipped++
				kept = append(kept, q)
				continue
			}
			if err := s.post(q); err != nil {
				q.Attempts++
				q.LastError = err.Error()
				q.NextRetryAt = nextRetryAt(q.Attempts, time.Now().UTC()).Format(time.RFC3339Nano)
				kept = append(kept, q)
				res.LastError = err.Error()
				continue
			}
			res.Sent++
			_ = appendJSONLine(s.sentPath(), map[string]any{
				"queue_id":       q.QueueID,
				"endpoint":       q.Endpoint,
				"sent_at":        time.Now().UTC().Format(time.RFC3339Nano),
				"payload_sha256": sha256HexBytes(q.Payload),
			})
		}
		if err := rewriteQueuedEvents(s.pendingPath(), kept); err != nil {
			return err
		}
		res.Remaining = len(kept)
		return nil
	})
	return res, err
}

func (s *eventSpool) post(q queuedEvent) error {
	url := s.cfg.BaseURL + q.Endpoint
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(q.Payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if s.cfg.APIKey != "" {
		req.Header.Set("X-API-Key", s.cfg.APIKey)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("http_%d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

func appendJSONLine(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	return enc.Encode(v)
}

func (s *eventSpool) withFileLock(timeout time.Duration, fn func() error) error {
	if err := os.MkdirAll(s.cfg.SpoolDir, 0o755); err != nil {
		return err
	}
	lockPath := s.lockPath()
	deadline := time.Now().Add(timeout)
	for {
		f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_, _ = fmt.Fprintf(f, "pid=%d\nacquired_at=%s\n", os.Getpid(), time.Now().UTC().Format(time.RFC3339Nano))
			_ = f.Close()
			defer os.Remove(lockPath)
			return fn()
		}
		if !os.IsExist(err) {
			return err
		}
		if fi, statErr := os.Stat(lockPath); statErr == nil {
			if time.Since(fi.ModTime()) > 30*time.Second {
				_ = os.Remove(lockPath)
				continue
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("spool lock timeout")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func readQueuedEvents(path string) ([]queuedEvent, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []queuedEvent
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var q queuedEvent
		if err := json.Unmarshal(line, &q); err != nil {
			continue
		}
		if q.Endpoint == "" || len(q.Payload) == 0 {
			continue
		}
		if strings.TrimSpace(q.NextRetryAt) == "" {
			q.NextRetryAt = q.EnqueuedAt
		}
		out = append(out, q)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func rewriteQueuedEvents(path string, items []queuedEvent) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	for _, q := range items {
		if err := enc.Encode(q); err != nil {
			f.Close()
			return err
		}
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func emitScanEventFromSecureScanJSON(command string, targetPath string, scanJSON []byte) {
	var m map[string]any
	if err := json.Unmarshal(scanJSON, &m); err != nil {
		return
	}
	if _, ok := m["target"]; !ok {
		m["target"] = targetPath
	}
	payload := map[string]any{
		"event_id":     fmt.Sprintf("evt_scan_%d", time.Now().UTC().UnixNano()),
		"occurred_at":  time.Now().UTC().Format(time.RFC3339Nano),
		"host_id":      hostID(),
		"tool_version": ztVersion,
		"command":      command,
		"target_name":  filepath.Base(targetPath),
		"result":       stringField(m, "result"),
		"reason":       stringField(m, "reason"),
		"summary":      mapField(m, "summary"),
		"scanners":     sliceField(m, "scanners"),
		"policy":       mapField(m, "policy"),
		"provenance":   mapField(m, "provenance"),
		"rule_hash":    stringField(m, "rule_hash"),
		"raw_scan":     m,
	}
	emitControlPlaneEvent("/v1/events/scan", payload)
}

func emitArtifactEvent(kind, artifactPath, inputPath, client string, ruleHash string) {
	sha := hashPathSHA256(artifactPath)
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
	}
	emitControlPlaneEvent("/v1/events/artifact", payload)
}

func emitVerifyEvent(artifactPath string, ok bool, reason string, details string) {
	result := "failed"
	if ok {
		result = "verified"
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
		"details": map[string]any{
			"path":    artifactPath,
			"message": details,
		},
	}
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

func readyForRetry(q queuedEvent, now time.Time) bool {
	if strings.TrimSpace(q.NextRetryAt) == "" {
		return true
	}
	t, err := time.Parse(time.RFC3339Nano, q.NextRetryAt)
	if err != nil {
		return true
	}
	return !now.Before(t)
}

func nextRetryAt(attempts int, now time.Time) time.Time {
	if attempts < 1 {
		attempts = 1
	}
	// 1s,2s,4s,... capped at 5m
	backoff := time.Second << minInt(attempts-1, 8) // cap growth at 256s
	if backoff > 5*time.Minute {
		backoff = 5 * time.Minute
	}
	// small deterministic spread from attempts to avoid thundering herd in repeated failures
	jitter := time.Duration((attempts%7)*100) * time.Millisecond
	return now.Add(backoff + jitter)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
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
