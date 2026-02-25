package main

import (
	"fmt"
	"strings"
	"time"
)

type policyLoopHealth struct {
	Status     string
	Reason     string
	SyncError  string
	LastSyncAt string
	NextSyncAt string
}

func inspectPolicyLoopHealth(repoRoot, kind string) (policyLoopHealth, error) {
	store := newPolicyActivationStore(repoRoot)
	meta, err := readMetaOrDefault(store, kind)
	if err != nil {
		return policyLoopHealth{}, err
	}
	health := policyLoopHealth{
		Status:     "ok",
		Reason:     "never_synced",
		SyncError:  policySyncErrorCodeNone,
		LastSyncAt: strings.TrimSpace(meta.LastSuccess),
	}
	errCode := strings.TrimSpace(meta.LastError)
	if errCode != "" {
		health.SyncError = errCode
	}
	if t, parseErr := time.Parse(time.RFC3339, strings.TrimSpace(meta.LastFetchAt)); parseErr == nil {
		health.NextSyncAt = t.Add(policySyncInterval()).Format(time.RFC3339)
	}
	switch {
	case health.SyncError == "" || health.SyncError == policySyncErrorCodeNone:
		if health.LastSyncAt != "" {
			health.Status = "ok"
			health.Reason = "healthy"
		}
	case strings.Contains(health.SyncError, "stale"):
		health.Status = "warn"
		health.Reason = "stale"
	case strings.Contains(health.SyncError, "verify_failed"):
		health.Status = "fail"
		health.Reason = "verify_failed"
	case health.SyncError == policyErrorCodeGatewayVersionUnsupported:
		health.Status = "fail"
		health.Reason = "version_unsupported"
	default:
		health.Status = "warn"
		health.Reason = health.SyncError
	}
	return health, nil
}

func policyLoopHealthMessage(h policyLoopHealth) string {
	return fmt.Sprintf("reason=%s sync_error=%s last_sync_at=%s next_sync_at=%s",
		emptyIfBlank(h.Reason, "unknown"),
		emptyIfBlank(h.SyncError, policySyncErrorCodeNone),
		emptyIfBlank(h.LastSyncAt, "(none)"),
		emptyIfBlank(h.NextSyncAt, "(none)"),
	)
}
