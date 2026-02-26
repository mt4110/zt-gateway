package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	relayAutoMaxBackoffCap = 2 * time.Minute
)

type relayAutoFileStability struct {
	Size        int64
	ModTimeUnix int64
	StableSince time.Time
}

type relayAutoRetryState struct {
	Attempts    int
	NextRetryAt time.Time
	LastError   string
}

type relayAutoDedupRecord struct {
	Key         string `json:"key"`
	Client      string `json:"client"`
	SHA256      string `json:"sha256"`
	SizeBytes   int64  `json:"size_bytes"`
	SourcePath  string `json:"source_path"`
	PacketPath  string `json:"packet_path"`
	CompletedAt string `json:"completed_at"`
}

type relayAutoDedupStore struct {
	Path string
	Seen map[string]relayAutoDedupRecord
}

func relayAutoDedupKey(client, sha256Hex string, size int64) string {
	return strings.TrimSpace(client) + ":" + strings.TrimSpace(sha256Hex) + ":" + strconv.FormatInt(size, 10)
}

func loadRelayAutoDedupStore(path string) (relayAutoDedupStore, error) {
	store := relayAutoDedupStore{
		Path: strings.TrimSpace(path),
		Seen: map[string]relayAutoDedupRecord{},
	}
	if store.Path == "" {
		return store, fmt.Errorf("empty dedup ledger path")
	}
	f, err := os.Open(store.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return store, nil
		}
		return store, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var rec relayAutoDedupRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		key := strings.TrimSpace(rec.Key)
		if key == "" {
			key = relayAutoDedupKey(rec.Client, rec.SHA256, rec.SizeBytes)
		}
		rec.Key = key
		if key != "" {
			store.Seen[key] = rec
		}
	}
	if err := sc.Err(); err != nil {
		return store, err
	}
	return store, nil
}

func appendRelayAutoDedupRecord(store *relayAutoDedupStore, rec relayAutoDedupRecord) error {
	if store == nil {
		return fmt.Errorf("nil dedup store")
	}
	if strings.TrimSpace(store.Path) == "" {
		return fmt.Errorf("empty dedup ledger path")
	}
	if strings.TrimSpace(rec.Key) == "" {
		rec.Key = relayAutoDedupKey(rec.Client, rec.SHA256, rec.SizeBytes)
	}
	if strings.TrimSpace(rec.Key) == "" {
		return fmt.Errorf("dedup record key is empty")
	}
	if err := os.MkdirAll(filepath.Dir(store.Path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(store.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}
	if store.Seen == nil {
		store.Seen = map[string]relayAutoDedupRecord{}
	}
	store.Seen[rec.Key] = rec
	return nil
}

func computeRelayAutoFileDigest(path string) (sha256Hex string, size int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func cleanupRelayAutoStateMaps(candidates []string, stabilities map[string]relayAutoFileStability, retries map[string]relayAutoRetryState) {
	live := make(map[string]struct{}, len(candidates))
	for _, c := range candidates {
		live[c] = struct{}{}
	}
	for k := range stabilities {
		if _, ok := live[k]; !ok {
			delete(stabilities, k)
		}
	}
	for k := range retries {
		if _, ok := live[k]; !ok {
			delete(retries, k)
		}
	}
}

func relayAutoFileReady(path string, now time.Time, stableWindow time.Duration, states map[string]relayAutoFileStability) (bool, string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, "stat_failed", err
	}
	if !info.Mode().IsRegular() {
		return false, "not_regular_file", nil
	}
	modUnix := info.ModTime().UTC().UnixNano()
	size := info.Size()
	prev, ok := states[path]
	if !ok {
		states[path] = relayAutoFileStability{
			Size:        size,
			ModTimeUnix: modUnix,
			StableSince: now.UTC(),
		}
		return false, "new_file_waiting_stable_window", nil
	}
	if prev.Size != size || prev.ModTimeUnix != modUnix {
		states[path] = relayAutoFileStability{
			Size:        size,
			ModTimeUnix: modUnix,
			StableSince: now.UTC(),
		}
		return false, "file_updated_waiting_stable_window", nil
	}
	if stableWindow <= 0 {
		return true, "stable", nil
	}
	if now.UTC().Sub(info.ModTime().UTC()) < stableWindow {
		return false, "recent_mtime_waiting_stable_window", nil
	}
	if now.UTC().Sub(prev.StableSince.UTC()) < stableWindow {
		return false, "stable_window_not_elapsed", nil
	}
	return true, "stable", nil
}

func relayAutoBackoffDelay(base time.Duration, attempts int) time.Duration {
	if base <= 0 {
		base = 1 * time.Second
	}
	if attempts < 1 {
		attempts = 1
	}
	delay := base
	for i := 1; i < attempts; i++ {
		if delay >= relayAutoMaxBackoffCap {
			return relayAutoMaxBackoffCap
		}
		delay *= 2
	}
	if delay > relayAutoMaxBackoffCap {
		return relayAutoMaxBackoffCap
	}
	return delay
}
