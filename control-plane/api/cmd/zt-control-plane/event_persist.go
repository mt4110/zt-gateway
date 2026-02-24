package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func (s *server) insertEventRecord(ctx context.Context, ingestID, kind string, now time.Time, r *http.Request, payload map[string]any, rawBody, envelopeJSON []byte, meta envelopeMeta) error {
	if s.db == nil {
		return nil
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	var eventID string
	if v, _ := payload["event_id"].(string); v != "" {
		eventID = v
	}
	var envelopeDoc any
	if meta.Present {
		var env map[string]any
		if err := json.Unmarshal(envelopeJSON, &env); err == nil {
			envelopeDoc = env
		}
	}

	_, err = s.db.ExecContext(ctx, `
insert into event_ingest (
  ingest_id, kind, event_id, received_at, remote_addr, user_agent,
  raw_body_sha256, payload_sha256, payload_json, envelope_json,
  envelope_present, envelope_verified, envelope_tenant_id, envelope_key_id, envelope_alg
) values (
  $1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10::jsonb,$11,$12,$13,$14,$15
)
on conflict (ingest_id) do nothing
`,
		ingestID,
		kind,
		eventID,
		now,
		r.RemoteAddr,
		r.UserAgent(),
		sha256Hex(rawBody),
		sha256Hex(payloadJSON),
		string(payloadJSON),
		nullableJSON(envelopeDoc),
		meta.Present,
		meta.Verified,
		nullIfEmpty(meta.TenantID),
		nullIfEmpty(meta.KeyID),
		nullIfEmpty(meta.Alg),
	)
	return err
}

func (s *server) appendJSONL(path string, v any) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	return enc.Encode(v)
}
