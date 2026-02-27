package main

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	controlPlaneHAEnabledEnv             = "ZT_CP_HA_ENABLED"
	controlPlaneHARPOObjectiveSecondsEnv = "ZT_CP_HA_RPO_OBJECTIVE_SECONDS"
	controlPlaneHARTOObjectiveSecondsEnv = "ZT_CP_HA_RTO_OBJECTIVE_SECONDS"
)

type controlPlaneHAStatus struct {
	Enabled             bool   `json:"enabled"`
	Mode                string `json:"mode"`
	MeasurementReady    bool   `json:"measurement_ready"`
	MeasurementSource   string `json:"measurement_source,omitempty"`
	MeasuredAt          string `json:"measured_at,omitempty"`
	RPOObjectiveSeconds int64  `json:"rpo_objective_seconds"`
	RTOObjectiveSeconds int64  `json:"rto_objective_seconds"`
	RPOMeasuredSeconds  int64  `json:"rpo_measured_seconds"`
	RTOMeasuredSeconds  int64  `json:"rto_measured_seconds"`
	RPOMet              bool   `json:"rpo_met"`
	RTOMet              bool   `json:"rto_met"`
	Notes               string `json:"notes,omitempty"`
}

func (s *server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}
	now := time.Now().UTC()
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"time":   now.Format(time.RFC3339),
		"ha":     s.collectControlPlaneHAStatus(r.Context(), now),
	})
}

func (s *server) collectControlPlaneHAStatus(ctx context.Context, now time.Time) controlPlaneHAStatus {
	out := controlPlaneHAStatus{
		Enabled:             envBoolCP(controlPlaneHAEnabledEnv),
		Mode:                "single",
		MeasurementReady:    false,
		RPOObjectiveSeconds: parsePositiveInt64Env(controlPlaneHARPOObjectiveSecondsEnv, 60),
		RTOObjectiveSeconds: parsePositiveInt64Env(controlPlaneHARTOObjectiveSecondsEnv, 300),
		RPOMeasuredSeconds:  -1,
		RTOMeasuredSeconds:  -1,
	}
	if out.Enabled {
		out.Mode = "ha"
	}
	if s == nil || s.db == nil {
		out.Notes = "postgres_not_configured"
		return out
	}

	var latest sql.NullTime
	if err := s.db.QueryRowContext(ctx, `select max(received_at) from event_ingest`).Scan(&latest); err != nil {
		out.Notes = "ha_measurement_failed"
		return out
	}
	if !latest.Valid {
		out.Notes = "ha_measurement_no_data"
		return out
	}
	out.MeasurementReady = true
	out.MeasurementSource = "event_ingest"
	out.MeasuredAt = now.Format(time.RFC3339)
	out.RPOMeasuredSeconds = int64(now.Sub(latest.Time.UTC()).Seconds())

	var maxGapSec sql.NullFloat64
	if err := s.db.QueryRowContext(ctx, `
select max(extract(epoch from gap))
from (
  select received_at - lag(received_at) over (order by received_at) as gap
  from event_ingest
  where received_at >= $1
) g
where gap is not null
`, now.Add(-24*time.Hour)).Scan(&maxGapSec); err == nil && maxGapSec.Valid && maxGapSec.Float64 >= 0 {
		out.RTOMeasuredSeconds = int64(maxGapSec.Float64)
	} else {
		out.RTOMeasuredSeconds = 0
	}
	out.RPOMet = out.RPOMeasuredSeconds <= out.RPOObjectiveSeconds
	out.RTOMet = out.RTOMeasuredSeconds <= out.RTOObjectiveSeconds
	return out
}

func parsePositiveInt64Env(name string, fallback int64) int64 {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || v <= 0 {
		return fallback
	}
	return v
}

func (s *server) handleEventIngest(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
			return
		}
		if err := s.checkAPIKey(r); err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": err.Error()})
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "read_failed"})
			return
		}
		if len(strings.TrimSpace(string(body))) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "empty_body"})
			return
		}
		payload, envMeta, envJSON, err := s.decodeIncomingEvent(r.URL.Path, body)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		eventID, _ := payload["event_id"].(string)
		eventID = strings.TrimSpace(eventID)
		if eventID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "event_id_required"})
			return
		}
		payloadJSON, err := json.Marshal(payload)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "payload_json_encode_failed"})
			return
		}
		payloadSHA := sha256Hex(payloadJSON)

		now := time.Now().UTC()
		ingestID := newID("ing")
		record := map[string]any{
			"ingest_id":       ingestID,
			"kind":            kind,
			"event_id":        eventID,
			"received_at":     now.Format(time.RFC3339Nano),
			"remote_addr":     r.RemoteAddr,
			"user_agent":      r.UserAgent(),
			"raw_body_sha256": sha256Hex(body),
			"payload":         payload,
			"payload_sha256":  payloadSHA,
			"envelope": map[string]any{
				"present":          envMeta.Present,
				"verified":         envMeta.Verified,
				"tenant_id":        envMeta.TenantID,
				"key_id":           envMeta.KeyID,
				"alg":              envMeta.Alg,
				"envelope_version": envMeta.EnvelopeVersion,
				"endpoint":         envMeta.Endpoint,
			},
		}
		eventsPath := filepath.Join(s.dataDir, "events", kind+".jsonl")
		duplicate, duplicateIngestID, err := s.appendEventJSONLWithDedupe(eventsPath, record, eventID, payloadSHA)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "persist_failed"})
			return
		}
		if s.db != nil && !duplicate {
			if err := s.insertEventRecord(r.Context(), ingestID, kind, now, r, payload, body, envJSON, envMeta); err != nil {
				log.Printf("WARN postgres dual-write failed (kind=%s ingest_id=%s): %v", kind, ingestID, err)
			}
		}
		responseIngestID := ingestID
		if duplicate && duplicateIngestID != "" {
			responseIngestID = duplicateIngestID
		}

		writeJSON(w, http.StatusAccepted, map[string]any{
			"status":         "accepted",
			"event_id":       eventID,
			"ingest_id":      responseIngestID,
			"duplicate":      duplicate,
			"duplicate_rule": "event_id+payload_sha256",
			"endpoint":       r.URL.Path,
			"payload_sha256": payloadSHA,
			"accepted_at":    now.Format(time.RFC3339),
		})
	}
}

func (s *server) handlePolicyLatest(fileName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
			return
		}
		if s.policySigner == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "policy_signing_not_configured"})
			return
		}
		gatewayID := strings.TrimSpace(r.URL.Query().Get("gateway_id"))
		if gatewayID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "gateway_id_required"})
			return
		}
		channel, err := normalizePolicyRolloutChannel(r.URL.Query().Get("channel"))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_channel"})
			return
		}
		profile, err := normalizePolicyProfile(r.URL.Query().Get("profile"))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_profile"})
			return
		}
		path, err := policyPathForProfile(s.policyDir, fileName, profile)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_profile"})
			return
		}
		b, err := os.ReadFile(path)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "policy_not_found", "file": fileName})
			return
		}
		info, _ := os.Stat(path)
		version := ""
		effectiveAt := ""
		if info != nil {
			version = info.ModTime().UTC().Format("2006.01.02-150405Z")
			effectiveAt = info.ModTime().UTC().Format(time.RFC3339)
			w.Header().Set("Last-Modified", info.ModTime().UTC().Format(http.TimeFormat))
		}
		contentSHA := sha256Hex(b)
		minGateway := minimumGatewayVersion()
		policySet := policySetID(s.policySigner)
		freshnessSLOSec := policyFreshnessSLOSeconds(profile)
		baseBundle := policyBundle{
			ManifestID:        policyManifestID(fileName, profile, version, contentSHA),
			Profile:           profile,
			Version:           version,
			SHA256:            contentSHA,
			EffectiveAt:       effectiveAt,
			ExpiresAt:         policyExpiresAtRFC3339(info, s.policySigner.TTL),
			KeyID:             s.policySigner.KeyID,
			ContentTOML:       string(b),
			MinGatewayVersion: minGateway,
			DuplicateRule:     "manifest_id+profile+sha256",
			PolicySetID:       policySet,
			FreshnessSLOSec:   freshnessSLOSec,
		}
		rolloutID := policyRolloutID(baseBundle)
		canaryPercent, rolloutErr := policyCanaryPercent()
		if rolloutErr != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "policy_rollout_config_invalid"})
			return
		}
		resolvedChannel := "stable"
		if channel == "canary" && rolloutCanaryEligible(gatewayID, rolloutID, canaryPercent) {
			resolvedChannel = "canary"
		}
		rolloutRule := fmt.Sprintf("sha256(gateway_id+rollout_id)%%100<%d", canaryPercent)
		etagPayload, _ := json.Marshal(map[string]any{
			"manifest_id":           baseBundle.ManifestID,
			"sha256":                contentSHA,
			"version":               version,
			"min_gateway_version":   minGateway,
			"policy_set_id":         policySet,
			"freshness_slo_seconds": freshnessSLOSec,
			"rollout_id":            rolloutID,
			"rollout_channel":       resolvedChannel,
			"rollout_rule":          rolloutRule,
			"key_id":                s.policySigner.KeyID,
		})
		etag := fmt.Sprintf("\"sha256:%s\"", sha256Hex(etagPayload))
		w.Header().Set("ETag", etag)
		w.Header().Set("Cache-Control", "private, max-age=0, must-revalidate")
		if inm := strings.TrimSpace(r.Header.Get("If-None-Match")); inm != "" && inm == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		bundle, err := s.policySigner.Sign(baseBundle)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "policy_signing_failed"})
			return
		}
		bundle.RolloutID = rolloutID
		bundle.RolloutChannel = resolvedChannel
		bundle.RolloutRule = rolloutRule
		writeJSON(w, http.StatusOK, bundle)
	}
}

func (s *server) handlePolicyKeyset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}
	if s.policySigner == nil || len(s.policySigner.Priv) != ed25519.PrivateKeySize {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "policy_signing_not_configured"})
		return
	}
	pub := s.policySigner.Priv.Public().(ed25519.PublicKey)
	status := strings.TrimSpace(s.policySigner.KeyStatus)
	if status == "" {
		status = "active"
	}
	key := map[string]any{
		"key_id":         s.policySigner.KeyID,
		"alg":            "Ed25519",
		"public_key_b64": base64.StdEncoding.EncodeToString(pub),
		"status":         status,
	}
	validFrom := strings.TrimSpace(s.policySigner.KeyValidFrom)
	validTo := strings.TrimSpace(s.policySigner.KeyValidTo)
	if validFrom == "" {
		validFrom = time.Now().UTC().Format(time.RFC3339)
	}
	if validTo == "" {
		validTo = time.Now().UTC().Add(365 * 24 * time.Hour).Format(time.RFC3339)
	}
	key["valid_from"] = validFrom
	key["valid_to"] = validTo
	etagBody := map[string]any{
		"schema_version": "zt-policy-keyset-v1",
		"keys":           []any{key},
		"rotation_id":    policyKeyRotationID(s.policySigner),
		"active_key_id":  policyActiveKeyID(s.policySigner),
		"next_key_id":    policyNextKeyID(s.policySigner),
	}
	canonical, _ := json.Marshal(etagBody)
	etag := fmt.Sprintf("\"sha256:%s\"", sha256Hex(canonical))
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "private, max-age=0, must-revalidate")
	if inm := strings.TrimSpace(r.Header.Get("If-None-Match")); inm != "" && inm == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	generatedAt := strings.TrimSpace(s.policySigner.KeysetCreated)
	if generatedAt == "" {
		generatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	resp := map[string]any{
		"schema_version": "zt-policy-keyset-v1",
		"generated_at":   generatedAt,
		"keys":           []any{key},
		"rotation_id":    policyKeyRotationID(s.policySigner),
		"active_key_id":  policyActiveKeyID(s.policySigner),
	}
	if nextKeyID := policyNextKeyID(s.policySigner); nextKeyID != "" {
		resp["next_key_id"] = nextKeyID
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *server) handleRulesLatest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"composite_rule_hash": "",
		"components":          []any{},
		"updated_at":          "",
		"note":                "metadata endpoint stub for MVP; fill from rule bundle registry later",
	})
}
