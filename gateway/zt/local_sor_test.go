package main

import (
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitializeLocalSOR_RequiresEncryptionKeyByDefault(t *testing.T) {
	repoRoot := t.TempDir()
	t.Setenv(localSORMasterKeyEnv, "")
	t.Setenv(localSORAllowPlaintextEnv, "")
	t.Setenv(localSORDBPathEnv, filepath.Join(repoRoot, ".zt-spool", "local-sor-test.db"))

	_, err := initializeLocalSOR(repoRoot)
	if err == nil {
		t.Fatalf("initializeLocalSOR error=nil, want required key error")
	}
	if !strings.Contains(err.Error(), localSORMasterKeyEnv) {
		t.Fatalf("error=%q, want contains %s", err.Error(), localSORMasterKeyEnv)
	}
}

func TestInitializeLocalSOR_AllowsPlaintextInDevMode(t *testing.T) {
	repoRoot := t.TempDir()
	path := filepath.Join(repoRoot, ".zt-spool", "local-sor-dev.db")
	t.Setenv(localSORMasterKeyEnv, "")
	t.Setenv(localSORAllowPlaintextEnv, "1")
	t.Setenv(localSORDBPathEnv, path)

	store, err := initializeLocalSOR(repoRoot)
	if err != nil {
		t.Fatalf("initializeLocalSOR: %v", err)
	}
	defer store.db.Close()

	if store.EncryptionOn {
		t.Fatalf("EncryptionOn=true, want false in dev plaintext mode")
	}
	if got := strings.TrimSpace(store.Path); got != path {
		t.Fatalf("store.Path=%q, want %q", got, path)
	}
	var n int
	if err := store.db.QueryRow(`select count(*) from sqlite_master where type='table' and name='local_sor_assets'`).Scan(&n); err != nil {
		t.Fatalf("schema query failed: %v", err)
	}
	if n != 1 {
		t.Fatalf("local_sor_assets table missing")
	}
}

func TestInitializeLocalSOR_KeyIDMustMatch(t *testing.T) {
	repoRoot := t.TempDir()
	path := filepath.Join(repoRoot, ".zt-spool", "local-sor-encrypted.db")
	t.Setenv(localSORAllowPlaintextEnv, "")
	t.Setenv(localSORDBPathEnv, path)

	t.Setenv(localSORMasterKeyEnv, base64.StdEncoding.EncodeToString(localSORTestKey(1)))
	store1, err := initializeLocalSOR(repoRoot)
	if err != nil {
		t.Fatalf("initializeLocalSOR(first): %v", err)
	}
	if strings.TrimSpace(store1.EncryptionKeyID) == "" {
		t.Fatalf("EncryptionKeyID is empty")
	}
	_ = store1.db.Close()

	t.Setenv(localSORMasterKeyEnv, base64.StdEncoding.EncodeToString(localSORTestKey(2)))
	_, err = initializeLocalSOR(repoRoot)
	if err == nil {
		t.Fatalf("initializeLocalSOR(second) error=nil, want key mismatch")
	}
	if !strings.Contains(err.Error(), localSORMetaKeyID) {
		t.Fatalf("error=%q, want contains %s", err.Error(), localSORMetaKeyID)
	}
}

func TestValidateLocalSORTenantID(t *testing.T) {
	if err := validateLocalSORTenantID("tenant-a"); err != nil {
		t.Fatalf("validateLocalSORTenantID(valid): %v", err)
	}
	if err := validateLocalSORTenantID("   "); err == nil {
		t.Fatalf("validateLocalSORTenantID(empty) error=nil, want failure")
	}
}

func TestLocalSORSchema_RejectsEmptyTenantID(t *testing.T) {
	repoRoot := t.TempDir()
	path := filepath.Join(repoRoot, ".zt-spool", "local-sor-tenant.db")
	t.Setenv(localSORAllowPlaintextEnv, "")
	t.Setenv(localSORDBPathEnv, path)
	t.Setenv(localSORMasterKeyEnv, base64.StdEncoding.EncodeToString(localSORTestKey(7)))

	store, err := initializeLocalSOR(repoRoot)
	if err != nil {
		t.Fatalf("initializeLocalSOR: %v", err)
	}
	defer store.db.Close()

	_, err = store.db.Exec(`
insert into local_sor_clients (client_id, tenant_id, display_name, status, created_at, updated_at)
values (?1, ?2, ?3, ?4, ?5, ?6)
`, "client-a", "   ", "Client A", "active", "2026-02-27T00:00:00Z", "2026-02-27T00:00:00Z")
	if err == nil {
		t.Fatalf("insert with empty tenant_id unexpectedly succeeded")
	}
}

func localSORTestKey(seed byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = seed + byte(i)
	}
	return out
}
