package main

import (
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

		now := time.Now().UTC()
		ingestID := newID("ing")
		record := map[string]any{
			"ingest_id":      ingestID,
			"kind":           kind,
			"received_at":    now.Format(time.RFC3339Nano),
			"remote_addr":    r.RemoteAddr,
			"user_agent":     r.UserAgent(),
			"payload":        payload,
			"payload_sha256": sha256Hex(body),
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
		if err := s.appendJSONL(filepath.Join(s.dataDir, "events", kind+".jsonl"), record); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "persist_failed"})
			return
		}
		if s.db != nil {
			if err := s.insertEventRecord(r.Context(), ingestID, kind, now, r, payload, body, envJSON, envMeta); err != nil {
				log.Printf("WARN postgres dual-write failed (kind=%s ingest_id=%s): %v", kind, ingestID, err)
			}
		}

		eventID, _ := payload["event_id"].(string)
		writeJSON(w, http.StatusAccepted, map[string]any{
			"status":    "accepted",
			"event_id":  eventID,
			"ingest_id": ingestID,
		})
	}
}

func (s *server) handlePolicyLatest(fileName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
			return
		}
		path := filepath.Join(s.policyDir, fileName)
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
		writeJSON(w, http.StatusOK, map[string]any{
			"version":      version,
			"sha256":       contentSHA,
			"content_toml": string(b),
			"effective_at": effectiveAt,
		})
	}
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
