package main

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
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
