package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (s *server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
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
		profile, err := normalizePolicyProfile(r.URL.Query().Get("profile"))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_profile"})
			return
		}
		path := policyPathForProfile(s.policyDir, fileName, profile)
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
		etag := fmt.Sprintf("\"sha256:%s\"", contentSHA)
		w.Header().Set("ETag", etag)
		w.Header().Set("Cache-Control", "private, max-age=0, must-revalidate")
		if inm := strings.TrimSpace(r.Header.Get("If-None-Match")); inm != "" && inm == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		bundle, err := s.policySigner.Sign(policyBundle{
			ManifestID:        policyManifestID(fileName, profile, version, contentSHA),
			Profile:           profile,
			Version:           version,
			SHA256:            contentSHA,
			EffectiveAt:       effectiveAt,
			ExpiresAt:         policyExpiresAtRFC3339(info, s.policySigner.TTL),
			KeyID:             s.policySigner.KeyID,
			ContentTOML:       string(b),
			MinGatewayVersion: minimumGatewayVersion(),
			DuplicateRule:     "manifest_id+profile+sha256",
		})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "policy_signing_failed"})
			return
		}
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
	key := map[string]any{
		"key_id":         s.policySigner.KeyID,
		"alg":            "Ed25519",
		"public_key_b64": base64.StdEncoding.EncodeToString(pub),
		"status":         "active",
	}
	resp := map[string]any{
		"schema_version": "zt-policy-keyset-v1",
		"generated_at":   time.Now().UTC().Format(time.RFC3339),
		"keys":           []any{key},
	}
	canonical, _ := json.Marshal(resp)
	etag := fmt.Sprintf("\"sha256:%s\"", sha256Hex(canonical))
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "private, max-age=0, must-revalidate")
	if inm := strings.TrimSpace(r.Header.Get("If-None-Match")); inm != "" && inm == etag {
		w.WriteHeader(http.StatusNotModified)
		return
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
