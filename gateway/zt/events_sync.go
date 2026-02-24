package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

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
