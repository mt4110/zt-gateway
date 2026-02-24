package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

func nullableJSON(v any) any {
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return string(b)
}

func (s *server) isEventKeyRegistryEnabled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.eventKeyRegistryEnabled
}

func (s *server) setEventKeyRegistryEnabled(v bool) {
	s.mu.Lock()
	s.eventKeyRegistryEnabled = v
	s.mu.Unlock()
}

func publicEventKeyEntry(e eventKeyRegistryEntry) map[string]any {
	item := map[string]any{
		"key_id":         e.KeyID,
		"tenant_id":      e.TenantID,
		"alg":            e.Alg,
		"public_key_b64": e.PublicKeyB64,
	}
	if e.Enabled != nil {
		item["enabled"] = *e.Enabled
	} else {
		item["enabled"] = true
	}
	if e.UpdatedBy != "" {
		item["updated_by"] = e.UpdatedBy
	}
	if e.UpdateReason != "" {
		item["reason"] = e.UpdateReason
	}
	return item
}

func validateAdminEventKeyUpsert(req adminEventKeyUpsertRequest) error {
	if strings.TrimSpace(req.KeyID) == "" {
		return fmt.Errorf("key_id_required")
	}
	if strings.TrimSpace(req.PublicKeyB64) == "" {
		return fmt.Errorf("public_key_b64_required")
	}
	if req.Alg == "" {
		req.Alg = "Ed25519"
	}
	if !strings.EqualFold(req.Alg, "Ed25519") {
		return fmt.Errorf("unsupported_alg")
	}
	if _, err := parseEd25519PublicKeyB64(req.PublicKeyB64); err != nil {
		return fmt.Errorf("invalid_public_key_b64")
	}
	return nil
}

func nullIfEmpty(v string) any {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return v
}
