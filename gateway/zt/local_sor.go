package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const (
	localSORMasterKeyEnv       = "ZT_LOCAL_SOR_MASTER_KEY_B64"
	localSORDBPathEnv          = "ZT_LOCAL_SOR_DB_PATH"
	localSORAllowPlaintextEnv  = "ZT_LOCAL_SOR_ALLOW_PLAINTEXT_DEV"
	localSORDefaultDBPath      = ".zt-spool/local-sor.db"
	localSORMetaSchemaVersion  = "schema_version"
	localSORMetaEncryptionMode = "encryption_mode"
	localSORMetaKeyID          = "encryption_key_id"
	localSORSchemaVersion      = "v1"
)

type localSORStore struct {
	Path            string
	EncryptionOn    bool
	EncryptionKey   []byte
	EncryptionKeyID string
	db              *sql.DB
}

var localSOR *localSORStore

func initializeLocalSOR(repoRoot string) (*localSORStore, error) {
	if strings.TrimSpace(repoRoot) == "" {
		return nil, fmt.Errorf("repo root is required")
	}
	path := resolveLocalSORDBPath(repoRoot)
	key, encryptionOn, err := resolveLocalSOREncryptionKey()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(`pragma busy_timeout = 5000;`); err != nil {
		_ = db.Close()
		return nil, err
	}
	if _, err := db.Exec(`pragma journal_mode = wal;`); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := createLocalSORSchema(db); err != nil {
		_ = db.Close()
		return nil, err
	}

	store := &localSORStore{
		Path:         path,
		EncryptionOn: encryptionOn,
		db:           db,
	}
	if encryptionOn {
		store.EncryptionKey = append([]byte(nil), key...)
		store.EncryptionKeyID = localSOREncryptionKeyID(key)
	}
	if err := store.ensureMeta(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func resolveLocalSORDBPath(repoRoot string) string {
	if v := strings.TrimSpace(os.Getenv(localSORDBPathEnv)); v != "" {
		if filepath.IsAbs(v) {
			return v
		}
		return filepath.Join(repoRoot, v)
	}
	return filepath.Join(repoRoot, localSORDefaultDBPath)
}

func resolveLocalSOREncryptionKey() ([]byte, bool, error) {
	raw := strings.TrimSpace(os.Getenv(localSORMasterKeyEnv))
	if raw == "" {
		if envBool(localSORAllowPlaintextEnv) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("local SoR encryption key is required (%s); set %s=1 only for local dev", localSORMasterKeyEnv, localSORAllowPlaintextEnv)
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, false, fmt.Errorf("invalid %s: %w", localSORMasterKeyEnv, err)
	}
	if len(key) != 32 {
		return nil, false, fmt.Errorf("invalid %s length: got %d bytes, want 32", localSORMasterKeyEnv, len(key))
	}
	return key, true, nil
}

func localSOREncryptionKeyID(key []byte) string {
	h := sha256.Sum256(key)
	return hex.EncodeToString(h[:8])
}

func createLocalSORSchema(db *sql.DB) error {
	stmts := []string{
		`create table if not exists local_sor_meta (
  meta_key text primary key,
  meta_value text not null,
  updated_at text not null
);`,
		`create table if not exists local_sor_clients (
  client_id text not null,
  tenant_id text not null check (length(trim(tenant_id)) > 0),
  display_name text not null,
  status text not null,
  created_at text not null,
  updated_at text not null,
  primary key (tenant_id, client_id)
);`,
		`create table if not exists local_sor_assets (
  asset_id text primary key,
  tenant_id text not null check (length(trim(tenant_id)) > 0),
  client_id text not null,
  filename text not null,
  content_sha256 text not null,
  location_type text not null,
  location_ref text,
  created_at text not null,
  last_seen_at text not null,
  access_count integer not null default 0
);`,
		`create index if not exists idx_local_sor_assets_tenant_client on local_sor_assets(tenant_id, client_id, created_at desc);`,
		`create table if not exists local_sor_keys (
  key_id text primary key,
  tenant_id text not null check (length(trim(tenant_id)) > 0),
  client_id text not null,
  key_purpose text not null,
  status text not null,
  fingerprint text not null,
  created_at text not null,
  rotated_at text,
  revoked_at text,
  compromise_flag integer not null default 0
);`,
		`create index if not exists idx_local_sor_keys_tenant_client on local_sor_keys(tenant_id, client_id, created_at desc);`,
		`create table if not exists local_sor_exchanges (
  exchange_id text primary key,
  tenant_id text not null check (length(trim(tenant_id)) > 0),
  client_id text not null,
  asset_id text,
  direction text not null,
  result text not null,
  verify_result text,
  signer_fingerprint text,
  created_at text not null,
  details_ciphertext blob,
  details_nonce blob
);`,
		`create index if not exists idx_local_sor_exchanges_tenant_client on local_sor_exchanges(tenant_id, client_id, created_at desc);`,
		`create table if not exists local_sor_signature_holders (
  tenant_id text not null check (length(trim(tenant_id)) > 0),
  signature_id text not null,
  holder_count_estimated integer not null default 0,
  holder_count_confirmed integer not null default 0,
  updated_at text not null,
  primary key (tenant_id, signature_id)
);`,
		`create table if not exists local_sor_key_repair_jobs (
  job_id text primary key,
  tenant_id text not null check (length(trim(tenant_id)) > 0),
  key_id text not null,
  trigger text not null,
  state text not null,
  runbook_id text not null,
  started_at text not null,
  updated_at text not null,
  finished_at text,
  operator text,
  summary text,
  evidence_ref text
);`,
		`create index if not exists idx_local_sor_key_repair_jobs_tenant_state on local_sor_key_repair_jobs(tenant_id, state, updated_at desc);`,
		`create index if not exists idx_local_sor_key_repair_jobs_tenant_key on local_sor_key_repair_jobs(tenant_id, key_id, updated_at desc);`,
		`create table if not exists local_sor_incidents (
  incident_id text primary key,
  tenant_id text not null check (length(trim(tenant_id)) > 0),
  action text not null,
  reason text,
  approver text,
  expires_at text,
  actor text,
  recorded_at text not null,
  evidence_ref text
);`,
		`create index if not exists idx_local_sor_incidents_tenant_time on local_sor_incidents(tenant_id, recorded_at desc);`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

func (s *localSORStore) ensureMeta() error {
	if s == nil || s.db == nil {
		return fmt.Errorf("local sor is not initialized")
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if err := s.upsertMeta(localSORMetaSchemaVersion, localSORSchemaVersion, now); err != nil {
		return err
	}
	mode := "plaintext"
	if s.EncryptionOn {
		mode = "envelope"
	}
	if err := s.ensureMetaValue(localSORMetaEncryptionMode, mode, now); err != nil {
		return err
	}
	if s.EncryptionOn {
		if err := s.ensureMetaValue(localSORMetaKeyID, s.EncryptionKeyID, now); err != nil {
			return err
		}
	}
	return nil
}

func (s *localSORStore) ensureMetaValue(key, value, now string) error {
	current, ok, err := s.getMeta(key)
	if err != nil {
		return err
	}
	if ok {
		if strings.TrimSpace(current) != strings.TrimSpace(value) {
			return fmt.Errorf("local sor meta mismatch: %s=%q (existing=%q)", key, value, current)
		}
		return nil
	}
	return s.upsertMeta(key, value, now)
}

func (s *localSORStore) upsertMeta(key, value, updatedAt string) error {
	_, err := s.db.Exec(`
insert into local_sor_meta (meta_key, meta_value, updated_at)
values (?1, ?2, ?3)
on conflict(meta_key) do update set
  meta_value=excluded.meta_value,
  updated_at=excluded.updated_at
`, strings.TrimSpace(key), strings.TrimSpace(value), strings.TrimSpace(updatedAt))
	return err
}

func (s *localSORStore) getMeta(key string) (string, bool, error) {
	var value string
	err := s.db.QueryRow(`select meta_value from local_sor_meta where meta_key = ?1`, strings.TrimSpace(key)).Scan(&value)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", false, nil
		}
		return "", false, err
	}
	return value, true, nil
}

func validateLocalSORTenantID(tenantID string) error {
	if strings.TrimSpace(tenantID) == "" {
		return fmt.Errorf("tenant_id is required")
	}
	return nil
}

func closeLocalSOR() {
	if localSOR == nil || localSOR.db == nil {
		return
	}
	_ = localSOR.db.Close()
}
