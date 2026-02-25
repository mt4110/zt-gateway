package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	policySyncErrorCodeNone            = "none"
	policySyncErrorCodeTransportFailed = "policy_sync_transport_failed"
	policySyncErrorCodeHTTP5xx         = "policy_sync_http_5xx"
)

type policySyncConfig struct {
	BaseURL    string
	APIKey     string
	Profile    string
	Kind       string
	PollEvery  time.Duration
	VerifyAt   time.Time
	Store      *policyActivationStore
	StartNow   bool
	MaxBackoff time.Duration
}

type policySyncRunResult struct {
	Kind        string
	NotModified bool
	Activated   bool
	ManifestID  string
	ErrorCode   string
}

func defaultPolicySyncConfig(repoRoot string, kind string) policySyncConfig {
	store := newPolicyActivationStore(repoRoot)
	pollEvery := policySyncInterval()
	return policySyncConfig{
		BaseURL:   strings.TrimSpace(os.Getenv("ZT_CONTROL_PLANE_URL")),
		APIKey:    strings.TrimSpace(os.Getenv("ZT_CONTROL_PLANE_API_KEY")),
		Profile:   trustProfileInternal,
		Kind:      kind,
		PollEvery: pollEvery,
		Store:     store,
		StartNow:  true,
	}
}

func policySyncInterval() time.Duration {
	pollEvery := 5 * time.Minute
	if raw := strings.TrimSpace(os.Getenv("ZT_POLICY_SYNC_INTERVAL_SECONDS")); raw != "" {
		if n, err := time.ParseDuration(raw + "s"); err == nil && n > 0 {
			pollEvery = n
		}
	}
	return pollEvery
}

func runPolicySyncOnce(cfg policySyncConfig) (policySyncRunResult, error) {
	kind, err := normalizePolicyStateKind(cfg.Kind)
	if err != nil {
		return policySyncRunResult{ErrorCode: normalizePolicySyncErrorCode(err)}, err
	}
	if cfg.Store == nil {
		return policySyncRunResult{Kind: kind, ErrorCode: "policy_sync_store_required"}, fmt.Errorf("policy_sync_store_required")
	}
	profile, err := validateTrustProfile(cfg.Profile)
	if err != nil {
		return policySyncRunResult{Kind: kind, ErrorCode: "policy_sync_profile_invalid"}, err
	}
	baseURL := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if baseURL == "" {
		return policySyncRunResult{Kind: kind, ErrorCode: "policy_sync_control_plane_not_configured"}, fmt.Errorf("policy_sync_control_plane_not_configured")
	}
	meta, err := readMetaOrDefault(cfg.Store, kind)
	if err != nil {
		return policySyncRunResult{Kind: kind, ErrorCode: "policy_sync_meta_load_failed"}, err
	}
	now := time.Now().UTC()
	meta.LastFetchAt = now.Format(time.RFC3339)

	trustedKeys, keysetETag, err := resolvePolicyTrustedKeysForSync(baseURL, cfg.APIKey, meta.ETagKeyset, cfg.Store, cfg.VerifyAt)
	if err != nil {
		meta.LastError = normalizePolicySyncErrorCode(err)
		_ = cfg.Store.writeMeta(kind, meta)
		return policySyncRunResult{Kind: kind, ErrorCode: meta.LastError}, err
	}
	if strings.TrimSpace(keysetETag) != "" {
		meta.ETagKeyset = keysetETag
	}

	latest, err := fetchControlPlanePolicyLatest(baseURL, cfg.APIKey, kind, profile, meta.ETagLatest)
	if err != nil {
		meta.LastError = normalizePolicySyncErrorCode(err)
		_ = cfg.Store.writeMeta(kind, meta)
		return policySyncRunResult{Kind: kind, ErrorCode: meta.LastError}, err
	}
	if strings.TrimSpace(latest.ETag) != "" {
		meta.ETagLatest = latest.ETag
	}
	if resolvePolicyRolloutChannel() == "canary" && strings.EqualFold(strings.TrimSpace(latest.Bundle.RolloutChannel), "stable") {
		meta.LastError = "policy_rollout_not_eligible"
		meta.LastSuccess = now.Format(time.RFC3339)
		if writeErr := cfg.Store.writeMeta(kind, meta); writeErr != nil {
			return policySyncRunResult{Kind: kind, ErrorCode: "policy_sync_meta_write_failed"}, writeErr
		}
		return policySyncRunResult{
			Kind:        kind,
			NotModified: true,
			ManifestID:  strings.TrimSpace(latest.Bundle.ManifestID),
			ErrorCode:   "policy_rollout_not_eligible",
		}, nil
	}
	if latest.NotModified {
		meta.LastError = policySyncErrorCodeNone
		meta.LastSuccess = now.Format(time.RFC3339)
		if writeErr := cfg.Store.writeMeta(kind, meta); writeErr != nil {
			return policySyncRunResult{Kind: kind, ErrorCode: "policy_sync_meta_write_failed"}, writeErr
		}
		return policySyncRunResult{
			Kind:        kind,
			NotModified: true,
			ErrorCode:   policySyncErrorCodeNone,
		}, nil
	}

	active, activeExists, activeErr := readSignedPolicyBundleFileIfExists(cfg.Store.activePath(kind))
	if activeErr != nil {
		meta.LastError = "policy_sync_active_load_failed"
		_ = cfg.Store.writeMeta(kind, meta)
		return policySyncRunResult{Kind: kind, ErrorCode: meta.LastError}, activeErr
	}
	if activeExists && strings.TrimSpace(active.ManifestID) != "" && active.ManifestID == latest.Bundle.ManifestID {
		meta.LastError = policySyncErrorCodeNone
		meta.LastSuccess = now.Format(time.RFC3339)
		if writeErr := cfg.Store.writeMeta(kind, meta); writeErr != nil {
			return policySyncRunResult{Kind: kind, ErrorCode: "policy_sync_meta_write_failed"}, writeErr
		}
		return policySyncRunResult{
			Kind:        kind,
			NotModified: true,
			ManifestID:  active.ManifestID,
			ErrorCode:   policySyncErrorCodeNone,
		}, nil
	}

	if err := cfg.Store.stage(kind, latest.Bundle); err != nil {
		meta.LastError = "policy_sync_stage_failed"
		_ = cfg.Store.writeMeta(kind, meta)
		return policySyncRunResult{Kind: kind, ErrorCode: meta.LastError}, err
	}
	activateAt := cfg.VerifyAt
	if activateAt.IsZero() {
		activateAt = now
	}
	activateResult, err := cfg.Store.activateStaged(kind, trustedKeys, activateAt)
	if err != nil {
		meta.LastError = normalizePolicySyncErrorCode(err)
		_ = cfg.Store.writeMeta(kind, meta)
		return policySyncRunResult{Kind: kind, ErrorCode: meta.LastError}, err
	}
	meta.LastError = policySyncErrorCodeNone
	meta.LastSuccess = now.Format(time.RFC3339)
	if writeErr := cfg.Store.writeMeta(kind, meta); writeErr != nil {
		return policySyncRunResult{Kind: kind, ErrorCode: "policy_sync_meta_write_failed"}, writeErr
	}
	return policySyncRunResult{
		Kind:      kind,
		Activated: activateResult.Activated,
		ManifestID: func() string {
			if activateResult.ActiveManifestID != "" {
				return activateResult.ActiveManifestID
			}
			return latest.Bundle.ManifestID
		}(),
		ErrorCode: policySyncErrorCodeNone,
	}, nil
}

func runPolicySyncLoop(ctx context.Context, cfg policySyncConfig) error {
	interval := cfg.PollEvery
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	if cfg.StartNow {
		if _, err := runPolicySyncOnce(cfg); err != nil {
			return err
		}
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if _, err := runPolicySyncOnce(cfg); err != nil {
				return err
			}
		}
	}
}

func resolvePolicyTrustedKeysForSync(baseURL, apiKey, keysetETag string, store *policyActivationStore, verifyAt time.Time) (map[string]ed25519.PublicKey, string, error) {
	keysetFetch, err := fetchControlPlanePolicyTrustedKeysWithETag(baseURL, apiKey, keysetETag)
	if err != nil {
		return nil, "", err
	}
	if !keysetFetch.NotModified {
		if err := store.writeKeysetCache(keysetFetch.Keyset); err != nil {
			return nil, "", fmt.Errorf("policy_keyset.cache_write_failed:%w", err)
		}
		return keysetFetch.Keys, keysetFetch.ETag, nil
	}
	ks, err := store.readKeysetCache()
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, "", fmt.Errorf("policy_keyset.cache_load_failed:%w", err)
		}
		// If cache is missing while CP returns 304, recover by forcing one non-conditional read.
		fallback, fallbackErr := fetchControlPlanePolicyTrustedKeysWithETag(baseURL, apiKey, "")
		if fallbackErr != nil {
			return nil, "", fallbackErr
		}
		if fallback.NotModified {
			return nil, "", fmt.Errorf("policy_keyset.cache_missing_after_304")
		}
		if writeErr := store.writeKeysetCache(fallback.Keyset); writeErr != nil {
			return nil, "", fmt.Errorf("policy_keyset.cache_write_failed:%w", writeErr)
		}
		return fallback.Keys, fallback.ETag, nil
	}
	keys, decodeErr := decodePolicyKeysetTrustedKeysAt(ks, verifyAt)
	if decodeErr != nil {
		return nil, "", decodeErr
	}
	return keys, keysetFetch.ETag, nil
}

func normalizePolicySyncErrorCode(err error) string {
	if err == nil {
		return policySyncErrorCodeNone
	}
	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	if strings.Contains(msg, "transport_failed") {
		return policySyncErrorCodeTransportFailed
	}
	if strings.Contains(msg, ".http_5") || strings.Contains(msg, "http_5") {
		return policySyncErrorCodeHTTP5xx
	}
	if strings.Contains(msg, "policy_gateway_version_unsupported") {
		return "policy_gateway_version_unsupported"
	}
	if i := strings.Index(msg, ":"); i > 0 {
		return strings.TrimSpace(msg[:i])
	}
	if msg == "" {
		return "policy_sync_failed"
	}
	return msg
}
