package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

func emitModelEvent(eventType string, manifest modelCapsuleManifestV1, info modelCapsuleArchiveInfo, result, reason string, details map[string]any) {
	if details == nil {
		details = map[string]any{}
	}
	details["capsule_sha256"] = info.CapsuleSHA256
	details["secure_pack_sha256"] = info.PayloadSHA256
	details["manifest_sha256"] = info.ManifestSHA256
	payload := map[string]any{
		"event_id":      fmt.Sprintf("evt_model_%d", time.Now().UTC().UnixNano()),
		"occurred_at":   time.Now().UTC().Format(time.RFC3339Nano),
		"host_id":       hostID(),
		"tool_version":  ztVersion,
		"event_type":    strings.TrimSpace(eventType),
		"tenant_id":     strings.TrimSpace(manifest.Distribution.TenantID),
		"client_id":     strings.TrimSpace(manifest.Distribution.ClientID),
		"model_id":      strings.TrimSpace(manifest.Model.ModelID),
		"capsule_id":    strings.TrimSpace(manifest.CapsuleID),
		"model_name":    strings.TrimSpace(manifest.Model.Name),
		"model_version": strings.TrimSpace(manifest.Model.Version),
		"model_format":  strings.TrimSpace(manifest.Model.Format),
		"capsule_name":  filepath.Base(info.Path),
		"result":        strings.TrimSpace(result),
		"reason":        strings.TrimSpace(reason),
		"shield_tier":   "audit_only",
		"details":       details,
	}
	applyTeamBoundaryMetadata(payload)
	emitControlPlaneEvent("/v1/models/runtime-events", payload)
}

func emitModelPassport(manifest modelCapsuleManifestV1) {
	emitControlPlaneEvent("/v1/models/passports", manifest)
}

func emitModelScanEvent(manifest modelCapsuleManifestV1, modelPath string, scanJSON []byte) {
	var raw map[string]any
	if err := json.Unmarshal(scanJSON, &raw); err != nil {
		raw = map[string]any{}
	}
	payload := map[string]any{
		"event_id":        fmt.Sprintf("evt_model_scan_%d", time.Now().UTC().UnixNano()),
		"occurred_at":     time.Now().UTC().Format(time.RFC3339Nano),
		"host_id":         hostID(),
		"tool_version":    ztVersion,
		"event_type":      "model_scan_completed",
		"tenant_id":       strings.TrimSpace(manifest.Distribution.TenantID),
		"client_id":       strings.TrimSpace(manifest.Distribution.ClientID),
		"model_id":        strings.TrimSpace(manifest.Model.ModelID),
		"capsule_id":      strings.TrimSpace(manifest.CapsuleID),
		"model_name":      strings.TrimSpace(manifest.Model.Name),
		"model_version":   strings.TrimSpace(manifest.Model.Version),
		"model_format":    strings.TrimSpace(manifest.Model.Format),
		"artifact_name":   filepath.Base(modelPath),
		"artifact_sha256": hashPathSHA256(modelPath),
		"result":          stringField(raw, "result"),
		"reason":          stringField(raw, "reason"),
		"details":         raw,
	}
	applyTeamBoundaryMetadata(payload)
	emitControlPlaneEvent("/v1/models/runtime-events", payload)
}
