package main

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	_ "github.com/jackc/pgx/v5/stdlib"
)

type eventSigningKeyState struct {
	KeyID        string
	TenantID     string
	Alg          string
	PublicKeyB64 string
	Enabled      bool
	Source       string
	CreatedAt    time.Time
	UpdatedAt    time.Time
	UpdatedBy    string
	UpdateReason string
}

func hasEventSigningKeys(ctx context.Context, db *sql.DB) (bool, error) {
	var n int64
	if err := db.QueryRowContext(ctx, `select count(*)::bigint from event_signing_keys where enabled = true`).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

func loadEventSigningKeyFromDB(ctx context.Context, db *sql.DB, keyID string) (eventKeyRegistryEntry, bool, error) {
	if strings.TrimSpace(keyID) == "" {
		return eventKeyRegistryEntry{}, false, nil
	}
	var e eventKeyRegistryEntry
	var enabled bool
	err := db.QueryRowContext(ctx, `
select key_id, coalesce(tenant_id,''), coalesce(alg,''), public_key_b64, enabled, coalesce(updated_by,''), coalesce(update_reason,'')
from event_signing_keys
where key_id = $1
`, keyID).Scan(&e.KeyID, &e.TenantID, &e.Alg, &e.PublicKeyB64, &enabled, &e.UpdatedBy, &e.UpdateReason)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return eventKeyRegistryEntry{}, false, nil
		}
		return eventKeyRegistryEntry{}, false, err
	}
	e.Enabled = &enabled
	pub, err := parseEd25519PublicKeyB64(e.PublicKeyB64)
	if err != nil {
		return eventKeyRegistryEntry{}, false, err
	}
	e.publicKey = pub
	return e, true, nil
}

func loadEventSigningKeyStateFromDB(ctx context.Context, db *sql.DB, keyID string) (eventSigningKeyState, bool, error) {
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		return eventSigningKeyState{}, false, nil
	}
	var s eventSigningKeyState
	err := db.QueryRowContext(ctx, `
select key_id, coalesce(tenant_id,''), coalesce(alg,''), public_key_b64, enabled, coalesce(source,''), created_at, updated_at, coalesce(updated_by,''), coalesce(update_reason,'')
from event_signing_keys
where key_id = $1
`, keyID).Scan(&s.KeyID, &s.TenantID, &s.Alg, &s.PublicKeyB64, &s.Enabled, &s.Source, &s.CreatedAt, &s.UpdatedAt, &s.UpdatedBy, &s.UpdateReason)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return eventSigningKeyState{}, false, nil
		}
		return eventSigningKeyState{}, false, err
	}
	return s, true, nil
}

func eventIngestFirstSeenAtByEnvelopeKey(ctx context.Context, db *sql.DB, keyID string) (time.Time, bool, error) {
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		return time.Time{}, false, nil
	}
	var v sql.NullTime
	if err := db.QueryRowContext(ctx, `
select min(received_at)
from event_ingest
where envelope_verified = true
  and envelope_key_id = $1
`, keyID).Scan(&v); err != nil {
		return time.Time{}, false, err
	}
	if !v.Valid {
		return time.Time{}, false, nil
	}
	return v.Time.UTC(), true, nil
}

func eventIngestLastSeenAtByEnvelopeKey(ctx context.Context, db *sql.DB, keyID string) (time.Time, bool, error) {
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		return time.Time{}, false, nil
	}
	var v sql.NullTime
	if err := db.QueryRowContext(ctx, `
select max(received_at)
from event_ingest
where envelope_verified = true
  and envelope_key_id = $1
`, keyID).Scan(&v); err != nil {
		return time.Time{}, false, err
	}
	if !v.Valid {
		return time.Time{}, false, nil
	}
	return v.Time.UTC(), true, nil
}

func appendEventSigningKeyAudit(ctx context.Context, db *sql.DB, rec eventSigningKeyAuditRecord) error {
	if db == nil {
		return nil
	}
	if strings.TrimSpace(rec.KeyID) == "" || strings.TrimSpace(rec.Action) == "" {
		return fmt.Errorf("invalid_audit_record")
	}
	var enabled any
	if rec.Enabled != nil {
		enabled = *rec.Enabled
	}
	_, err := db.ExecContext(ctx, `
insert into event_signing_key_audit (
  key_id, action, tenant_id, enabled, source, updated_by, update_reason, meta_json
) values (
  $1,$2,$3,$4,$5,$6,$7,$8::jsonb
)
`, rec.KeyID, nullIfEmpty(rec.Action), nullIfEmpty(rec.TenantID), enabled, nullIfEmpty(rec.Source), nullIfEmpty(rec.UpdatedBy), nullIfEmpty(rec.UpdateReason), nullableJSON(rec.Meta))
	return err
}

func loadEventKeyRegistryEntries(path string) ([]eventKeyRegistryEntry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Backward compatibility: try legacy JSON path if default TOML is absent.
			if strings.HasSuffix(path, ".toml") {
				legacy := strings.TrimSuffix(path, ".toml") + ".json"
				if lb, lerr := os.ReadFile(legacy); lerr == nil {
					var raw []eventKeyRegistryEntry
					if jerr := json.Unmarshal(lb, &raw); jerr != nil {
						return nil, jerr
					}
					return raw, nil
				}
			}
			return []eventKeyRegistryEntry{}, nil
		}
		return nil, err
	}

	trim := strings.TrimSpace(string(b))
	if strings.HasSuffix(strings.ToLower(path), ".json") {
		var raw []eventKeyRegistryEntry
		if err := json.Unmarshal(b, &raw); err != nil {
			return nil, err
		}
		return raw, nil
	}
	if strings.HasSuffix(strings.ToLower(path), ".toml") {
		var f eventKeyRegistryFile
		if err := toml.Unmarshal(b, &f); err != nil {
			return nil, err
		}
		return f.Keys, nil
	}
	if strings.HasPrefix(trim, "{") || (strings.HasPrefix(trim, "[") && !strings.HasPrefix(trim, "[[")) {
		var raw []eventKeyRegistryEntry
		if err := json.Unmarshal(b, &raw); err != nil {
			return nil, err
		}
		return raw, nil
	}

	var f eventKeyRegistryFile
	if err := toml.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	return f.Keys, nil
}

func parseEd25519PublicKeyB64(raw string) (ed25519.PublicKey, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty")
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("expected %d bytes, got %d", ed25519.PublicKeySize, len(b))
	}
	return ed25519.PublicKey(b), nil
}

func openPostgresFromEnv() (*sql.DB, error) {
	dsn := strings.TrimSpace(os.Getenv("ZT_CP_POSTGRES_DSN"))
	if dsn == "" {
		return nil, nil
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := ensurePostgresSchema(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func ensurePostgresSchema(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `
create table if not exists event_ingest (
  ingest_id text primary key,
  kind text not null,
  event_id text,
  received_at timestamptz not null,
  remote_addr text,
  user_agent text,
  raw_body_sha256 text not null,
  payload_sha256 text not null,
  payload_json jsonb not null,
  envelope_json jsonb,
  envelope_present boolean not null default false,
  envelope_verified boolean not null default false,
  envelope_tenant_id text,
  envelope_key_id text,
  envelope_alg text
);
create index if not exists idx_event_ingest_kind_received_at on event_ingest(kind, received_at desc);
create index if not exists idx_event_ingest_event_id on event_ingest(event_id);

create table if not exists event_signing_keys (
  key_id text primary key,
  tenant_id text,
  alg text not null default 'Ed25519',
  public_key_b64 text not null,
  enabled boolean not null default true,
  source text not null default 'manual',
  updated_by text,
  update_reason text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists idx_event_signing_keys_tenant_id on event_signing_keys(tenant_id);

create table if not exists event_signing_key_audit (
  audit_id bigserial primary key,
  key_id text not null,
  action text not null,
  tenant_id text,
  enabled boolean,
  source text,
  updated_by text,
  update_reason text,
  meta_json jsonb,
  occurred_at timestamptz not null default now()
);
create index if not exists idx_event_signing_key_audit_key_time on event_signing_key_audit(key_id, occurred_at desc);
create index if not exists idx_event_signing_key_audit_time on event_signing_key_audit(occurred_at desc);
`)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `
alter table event_ingest add column if not exists envelope_tenant_id text;
alter table event_ingest add column if not exists envelope_key_id text;
alter table event_ingest add column if not exists envelope_alg text;
alter table event_ingest add column if not exists envelope_present boolean not null default false;
alter table event_ingest add column if not exists envelope_verified boolean not null default false;
alter table event_ingest add column if not exists envelope_json jsonb;
alter table event_signing_keys add column if not exists tenant_id text;
alter table event_signing_keys add column if not exists alg text not null default 'Ed25519';
alter table event_signing_keys add column if not exists public_key_b64 text;
alter table event_signing_keys add column if not exists enabled boolean not null default true;
alter table event_signing_keys add column if not exists source text not null default 'manual';
alter table event_signing_keys add column if not exists updated_by text;
alter table event_signing_keys add column if not exists update_reason text;
alter table event_signing_keys add column if not exists created_at timestamptz not null default now();
alter table event_signing_keys add column if not exists updated_at timestamptz not null default now();
`)
	return err
}
