package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	localLockPathEnv = "ZT_LOCAL_LOCK_FILE"
)

type localOperationLock struct {
	Path       string `json:"path,omitempty"`
	Locked     bool   `json:"locked"`
	Reason     string `json:"reason,omitempty"`
	LockedAt   string `json:"locked_at,omitempty"`
	UnlockedAt string `json:"unlocked_at,omitempty"`
	UpdatedAt  string `json:"updated_at,omitempty"`
	UpdatedBy  string `json:"updated_by,omitempty"`
}

func defaultLocalLockPath(repoRoot string) string {
	return filepath.Join(repoRoot, ".zt-spool", "local-lock.json")
}

func resolveLocalLockPath(repoRoot string) string {
	if p := strings.TrimSpace(os.Getenv(localLockPathEnv)); p != "" {
		if abs, err := filepath.Abs(p); err == nil {
			return abs
		}
		return p
	}
	return defaultLocalLockPath(repoRoot)
}

func loadLocalOperationLock(repoRoot string) (localOperationLock, error) {
	path := resolveLocalLockPath(repoRoot)
	out := localOperationLock{Path: path}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return out, err
	}
	if len(data) == 0 {
		return out, nil
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return localOperationLock{Path: path}, fmt.Errorf("local lock file parse failed: %w", err)
	}
	out.Path = path
	return out, nil
}

func writeLocalOperationLock(repoRoot string, locked bool, reason string, actor string, now time.Time) (localOperationLock, error) {
	path := resolveLocalLockPath(repoRoot)
	current, err := loadLocalOperationLock(repoRoot)
	if err != nil {
		return localOperationLock{Path: path}, err
	}
	nowRFC3339 := now.UTC().Format(time.RFC3339)
	current.Path = path
	current.Locked = locked
	current.Reason = strings.TrimSpace(reason)
	if current.Reason == "" {
		if locked {
			current.Reason = "manual_lock"
		} else {
			current.Reason = "manual_unlock"
		}
	}
	current.UpdatedBy = strings.TrimSpace(actor)
	if current.UpdatedBy == "" {
		current.UpdatedBy = "local"
	}
	current.UpdatedAt = nowRFC3339
	if locked {
		current.LockedAt = nowRFC3339
		current.UnlockedAt = ""
	} else {
		current.UnlockedAt = nowRFC3339
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return current, err
	}
	payload := localOperationLock{
		Locked:     current.Locked,
		Reason:     current.Reason,
		LockedAt:   current.LockedAt,
		UnlockedAt: current.UnlockedAt,
		UpdatedAt:  current.UpdatedAt,
		UpdatedBy:  current.UpdatedBy,
	}
	b, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return current, err
	}
	b = append(b, '\n')
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return current, err
	}
	return current, nil
}

func ensureOperationUnlocked(repoRoot string, operation string) (localOperationLock, error) {
	lock, err := loadLocalOperationLock(repoRoot)
	if err != nil {
		return lock, fmt.Errorf("local lock state is invalid: %w", err)
	}
	if lock.Locked {
		reason := strings.TrimSpace(lock.Reason)
		if reason == "" {
			reason = "manual_lock"
		}
		return lock, fmt.Errorf("operation `%s` is blocked by local lock (reason=%s, locked_at=%s, file=%s)", strings.TrimSpace(operation), reason, strings.TrimSpace(lock.LockedAt), lock.Path)
	}
	return lock, nil
}
