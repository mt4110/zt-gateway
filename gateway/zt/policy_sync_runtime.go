package main

import (
	"fmt"
	"time"
)

func tryPolicySync(repoRoot, kind, profile string) {
	if cpEvents == nil {
		return
	}
	baseURL := cpEvents.cfg.BaseURL
	if baseURL == "" {
		return
	}
	cfg := policySyncConfig{
		BaseURL:  baseURL,
		APIKey:   cpEvents.cfg.APIKey,
		Profile:  profile,
		Kind:     kind,
		Store:    newPolicyActivationStore(repoRoot),
		VerifyAt: time.Now().UTC(),
	}
	result, err := runPolicySyncOnce(cfg)
	if err != nil {
		fmt.Printf("[Policy] WARN sync kind=%s failed: %v (error_code=%s)\n", kind, err, result.ErrorCode)
		return
	}
	if result.Activated {
		fmt.Printf("[Policy] synced kind=%s manifest_id=%s\n", kind, result.ManifestID)
	}
}
