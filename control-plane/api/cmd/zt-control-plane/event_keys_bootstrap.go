package main

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"zt-control-plane-api/internal/eventkeyspec"
)

func parseEd25519PublicKeyEnv(name string) (ed25519.PublicKey, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return nil, nil
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("expected %d-byte raw public key, got %d", ed25519.PublicKeySize, len(b))
	}
	return ed25519.PublicKey(b), nil
}

func loadEventKeyRegistry(cwd string) (map[string]eventKeyRegistryEntry, error) {
	path := strings.TrimSpace(os.Getenv("ZT_CP_EVENT_KEY_REGISTRY_FILE"))
	if path == "" {
		path = filepath.Join(cwd, "control-plane", "config", "event_key_registry.toml")
	}
	rawEntries, err := loadEventKeyRegistryEntries(path)
	if err != nil {
		return nil, err
	}
	out := make(map[string]eventKeyRegistryEntry, len(rawEntries))
	for _, e := range rawEntries {
		e.KeyID = strings.TrimSpace(e.KeyID)
		if e.KeyID == "" {
			return nil, fmt.Errorf("registry entry missing key_id")
		}
		if e.Alg == "" {
			e.Alg = "Ed25519"
		}
		pub, err := parseEd25519PublicKeyB64(e.PublicKeyB64)
		if err != nil {
			return nil, fmt.Errorf("registry key_id=%s invalid public key: %w", e.KeyID, err)
		}
		e.publicKey = pub
		out[e.KeyID] = e
	}
	return out, nil
}

func bootstrapEventKeyRegistry(ctx context.Context, db *sql.DB, entries map[string]eventKeyRegistryEntry) error {
	if db == nil || len(entries) == 0 {
		return nil
	}
	for _, e := range entries {
		enabled := true
		if e.Enabled != nil {
			enabled = *e.Enabled
		}
		_, err := db.ExecContext(ctx, `
insert into event_signing_keys (key_id, tenant_id, alg, public_key_b64, enabled, source, updated_by, update_reason)
values ($1,$2,$3,$4,$5,'bootstrap.toml','bootstrap','bootstrap.toml import')
on conflict (key_id) do update set
  tenant_id = excluded.tenant_id,
  alg = excluded.alg,
  public_key_b64 = excluded.public_key_b64,
  enabled = excluded.enabled,
  source = excluded.source,
  updated_by = excluded.updated_by,
  update_reason = excluded.update_reason,
  updated_at = now()
`,
			e.KeyID, e.TenantID, e.Alg, e.PublicKeyB64, enabled,
		)
		if err != nil {
			return err
		}
		enabledPtr := new(bool)
		*enabledPtr = enabled
		if err := appendEventSigningKeyAudit(ctx, db, eventSigningKeyAuditRecord{
			KeyID:        e.KeyID,
			Action:       string(eventkeyspec.AuditActionBootstrapUpsert),
			TenantID:     e.TenantID,
			Enabled:      enabledPtr,
			Source:       "bootstrap.toml",
			UpdatedBy:    "bootstrap",
			UpdateReason: "bootstrap.toml import",
		}); err != nil {
			log.Printf("WARN event_signing_key_audit append failed (key_id=%s action=%s): %v", e.KeyID, eventkeyspec.AuditActionBootstrapUpsert, err)
		}
	}
	return nil
}
