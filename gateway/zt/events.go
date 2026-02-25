package main

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
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
	auditSig *auditRecordSigner
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
	Sent           int
	Remaining      int
	Skipped        int
	LastError      string
	LastErrorClass string
	LastErrorCode  string
	Configured     bool
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
	auditSigner, auditSignerErr := loadAuditRecordSignerFromEnv()
	if auditSignerErr != nil {
		if !suppressStartupDiagnostics {
			fmt.Fprintf(os.Stderr, "[Events] WARN invalid audit signing key: %v\n", auditSignerErr)
		}
	}
	return &eventSpool{
		cfg: cfg,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		signer:   signer,
		auditSig: auditSigner,
		autoSync: true,
	}
}

func runSyncEvents(force bool) {
	runSyncEventsWithOptions(syncOptions{Force: force})
}

type syncCommandJSONResult struct {
	OK          bool     `json:"ok"`
	SchemaVer   int      `json:"schema_version"`
	GeneratedAt string   `json:"generated_at"`
	Command     string   `json:"command"`
	Argv        []string `json:"argv"`
	Force       bool     `json:"force"`
	Configured  bool     `json:"configured"`
	Sent        int      `json:"sent"`
	Remaining   int      `json:"remaining"`
	Skipped     int      `json:"skipped"`
	ErrorClass  string   `json:"error_class"`
	ErrorCode   string   `json:"error_code"`
	LastError   string   `json:"last_error,omitempty"`
	ExitCode    int      `json:"exit_code"`
}

func runSyncEventsWithOptions(opts syncOptions) {
	exitCode := runSyncEventsCommand(opts, append([]string(nil), os.Args...), os.Stdout)
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}

func runSyncEventsCommand(opts syncOptions, argv []string, out io.Writer) int {
	if out == nil {
		out = os.Stdout
	}
	result := syncCommandJSONResult{
		OK:          true,
		SchemaVer:   1,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Command:     "zt sync",
		Argv:        append([]string(nil), argv...),
		Force:       opts.Force,
		ErrorClass:  syncErrorClassNone,
		ErrorCode:   syncErrorCodeNone,
	}

	if cpEvents == nil {
		result.OK = false
		result.ExitCode = 1
		result.ErrorClass = syncErrorClassInternal
		result.ErrorCode = syncErrorCodeSyncNotInitialized
		result.LastError = "event spool is not initialized"
		if opts.JSON {
			emitSyncJSON(out, result)
		} else {
			fmt.Fprintln(out, "[SYNC] event spool is not initialized")
		}
		return result.ExitCode
	}

	res, err := cpEvents.Sync(opts.Force)
	result.Configured = res.Configured
	result.Sent = res.Sent
	result.Remaining = res.Remaining
	result.Skipped = res.Skipped
	result.LastError = res.LastError
	result.ErrorClass = normalizeSyncErrorClass(res.LastErrorClass)
	result.ErrorCode = normalizeSyncErrorCode(res.LastErrorCode)

	if err != nil {
		result.OK = false
		result.ExitCode = 1
		if result.LastError == "" {
			result.LastError = err.Error()
		}
		if result.ErrorClass == syncErrorClassNone || result.ErrorCode == syncErrorCodeNone {
			info := classifySyncError(err)
			result.ErrorClass = normalizeSyncErrorClass(info.Class)
			result.ErrorCode = normalizeSyncErrorCode(info.Code)
		}
		if opts.JSON {
			emitSyncJSON(out, result)
		} else if isControlPlaneFailClosedSyncError(err) {
			fmt.Fprintf(out, "[SYNC] fail-closed: %v\n", err)
			fmt.Fprintln(out, "[SYNC] Fix event signing config (key_id/allowed key) and retry with `zt sync --force`.")
		} else {
			fmt.Fprintf(out, "[SYNC] failed: %v\n", err)
		}
		return result.ExitCode
	}

	if opts.JSON {
		emitSyncJSON(out, result)
		return 0
	}
	if !res.Configured {
		fmt.Fprintf(out, "[SYNC] no control-plane URL configured. pending=%d (spooled locally)\n", res.Remaining)
		return 0
	}
	fmt.Fprintf(out, "[SYNC] sent=%d remaining=%d skipped=%d force=%t\n", res.Sent, res.Remaining, res.Skipped, opts.Force)
	if res.LastError != "" {
		fmt.Fprintf(out, "[SYNC] last_error=%s\n", res.LastError)
	}
	return 0
}

func emitSyncJSON(w io.Writer, v syncCommandJSONResult) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func emitControlPlaneEvent(endpoint string, payload any) {
	if cpEvents == nil {
		return
	}
	if err := cpEvents.Enqueue(endpoint, payload); err != nil {
		fmt.Fprintf(os.Stderr, "[Events] WARN enqueue failed (%s): %v\n", endpoint, err)
		return
	}
	if err := cpEvents.appendAuditEvent(endpoint, payload); err != nil {
		fmt.Fprintf(os.Stderr, "[Events] WARN audit append failed (%s): %v\n", endpoint, err)
	}
	if cpEvents.cfg.BaseURL != "" && cpEvents.autoSync {
		if _, err := cpEvents.Sync(false); err != nil {
			if isControlPlaneFailClosedSyncError(err) {
				fmt.Fprintf(os.Stderr, "[Events] FAIL-CLOSED sync rejected by control-plane: %v\n", err)
				fmt.Fprintln(os.Stderr, "[Events] Fix ZT_EVENT_SIGNING_KEY_ID / key registry mapping, then run `zt sync --force`.")
			} else {
				fmt.Fprintf(os.Stderr, "[Events] WARN sync failed: %v\n", err)
			}
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
