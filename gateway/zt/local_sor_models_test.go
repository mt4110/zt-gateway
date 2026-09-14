package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLocalSORModelInventoryRoundTrip(t *testing.T) {
	repoRoot := t.TempDir()
	dbPath := filepath.Join(repoRoot, ".zt-spool", "local-sor-models.db")
	t.Setenv(localSORAllowPlaintextEnv, "")
	t.Setenv(localSORDBPathEnv, dbPath)
	t.Setenv(localSORMasterKeyEnv, base64.StdEncoding.EncodeToString(localSORTestKey(9)))

	store, err := initializeLocalSOR(repoRoot)
	if err != nil {
		t.Fatalf("initializeLocalSOR: %v", err)
	}
	defer store.db.Close()

	modelPath := filepath.Join(repoRoot, "demo.gguf")
	if err := os.WriteFile(modelPath, []byte("GGUFdemo"), 0644); err != nil {
		t.Fatal(err)
	}
	manifest, err := buildModelCapsuleManifest(buildModelManifestInput{
		ModelPath: modelPath,
		Name:      "demo",
		Version:   "1",
		Format:    "gguf",
		ClientID:  "edge-a",
		TenantID:  "tenant-a",
		Profile:   trustProfileConfidential,
		CreatedAt: time.Date(2026, 5, 26, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("build manifest: %v", err)
	}
	info := modelCapsuleArchiveInfo{
		Path:           filepath.Join(repoRoot, "demo.zmc"),
		CapsuleSHA256:  strings64("a"),
		ManifestSHA256: strings64("b"),
		PolicySHA256:   strings64("c"),
		PayloadSHA256:  strings64("d"),
	}
	if err := store.upsertModelCapsule(manifest, info, "", time.Date(2026, 5, 26, 1, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("upsertModelCapsule: %v", err)
	}
	items, total, err := store.listModelAssets("tenant-a", "", 10, 0, false)
	if err != nil {
		t.Fatalf("listModelAssets: %v", err)
	}
	if total != 1 || len(items) != 1 {
		t.Fatalf("total=%d len=%d, want 1/1", total, len(items))
	}
	if items[0].ModelID != manifest.Model.ModelID || items[0].CapsuleID != manifest.CapsuleID {
		t.Fatalf("unexpected item: %+v", items[0])
	}
	metrics, err := store.collectModelInventoryMetrics("tenant-a", time.Date(2026, 5, 27, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("collectModelInventoryMetrics: %v", err)
	}
	if metrics.TotalModels != 1 || metrics.TotalCapsules != 1 {
		t.Fatalf("metrics=%+v, want one model and capsule", metrics)
	}

	tenantBManifest, err := buildModelCapsuleManifest(buildModelManifestInput{
		ModelPath: modelPath,
		Name:      "demo",
		Version:   "1",
		Format:    "gguf",
		ClientID:  "edge-b",
		TenantID:  "tenant-b",
		Profile:   trustProfileConfidential,
		CreatedAt: time.Date(2026, 5, 26, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("build tenant-b manifest: %v", err)
	}
	if tenantBManifest.Model.ModelID != manifest.Model.ModelID {
		t.Fatalf("test setup expected tenant-agnostic model_id, got %s vs %s", tenantBManifest.Model.ModelID, manifest.Model.ModelID)
	}
	if err := store.upsertModelCapsule(tenantBManifest, info, "", time.Date(2026, 5, 26, 2, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("upsert tenant-b capsule: %v", err)
	}
	tenantAItems, tenantATotal, err := store.listModelAssets("tenant-a", "", 10, 0, false)
	if err != nil {
		t.Fatalf("list tenant-a models: %v", err)
	}
	tenantBItems, tenantBTotal, err := store.listModelAssets("tenant-b", "", 10, 0, false)
	if err != nil {
		t.Fatalf("list tenant-b models: %v", err)
	}
	if tenantATotal != 1 || tenantBTotal != 1 || len(tenantAItems) != 1 || len(tenantBItems) != 1 {
		t.Fatalf("tenant totals = a:%d/%d b:%d/%d, want isolated 1/1 each", tenantATotal, len(tenantAItems), tenantBTotal, len(tenantBItems))
	}
	if tenantAItems[0].TenantID != "tenant-a" || tenantBItems[0].TenantID != "tenant-b" {
		t.Fatalf("tenant isolation failed: a=%+v b=%+v", tenantAItems[0], tenantBItems[0])
	}
}

func TestRuntimeSessionEventsStoreSessionIDAndPID(t *testing.T) {
	t.Setenv(localSORAllowPlaintextEnv, "1")
	store, err := initializeLocalSOR(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.db.Close()

	session := runtimeSessionRecord{
		SessionID:   "sess_test",
		TenantID:    "tenant-a",
		ModelID:     "mdl_demo",
		CapsuleID:   "zmc_demo",
		PermitID:    "permit_demo",
		DeviceID:    "dev-a",
		RuntimeName: "fake",
		PID:         12345,
		ShieldTier:  "audit_only",
		StartedAt:   "2026-05-28T00:00:00Z",
		Result:      "running",
	}
	if err := store.startRuntimeSession(session, map[string]any{"pid": session.PID}); err != nil {
		t.Fatalf("startRuntimeSession: %v", err)
	}
	if err := store.stopRuntimeSession(session.SessionID, session.TenantID, session.ModelID, session.CapsuleID, "2026-05-28T00:01:00Z", "completed", "runtime.child_completed", map[string]any{"pid": session.PID}); err != nil {
		t.Fatalf("stopRuntimeSession: %v", err)
	}

	var gotPID int
	if err := store.db.QueryRow(`select coalesce(pid, 0) from runtime_sessions where session_id = ?1`, session.SessionID).Scan(&gotPID); err != nil {
		t.Fatal(err)
	}
	if gotPID != session.PID {
		t.Fatalf("pid=%d, want %d", gotPID, session.PID)
	}

	rows, err := store.db.Query(`select coalesce(session_id, '') from model_events where event_type in ('runtime_started', 'runtime_stopped') order by occurred_at asc`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := 0
	for rows.Next() {
		var sessionID string
		if err := rows.Scan(&sessionID); err != nil {
			t.Fatal(err)
		}
		if sessionID != session.SessionID {
			t.Fatalf("event session_id=%q, want %q", sessionID, session.SessionID)
		}
		got++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if got != 2 {
		t.Fatalf("runtime event count=%d, want 2", got)
	}
}

func TestRecordModelVerifyRefreshesAssetStatusOnConflict(t *testing.T) {
	t.Setenv(localSORAllowPlaintextEnv, "1")
	repoRoot := t.TempDir()
	store, err := initializeLocalSOR(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer store.db.Close()

	modelPath := filepath.Join(repoRoot, "demo.gguf")
	if err := os.WriteFile(modelPath, []byte("GGUFdemo"), 0644); err != nil {
		t.Fatal(err)
	}
	manifest, err := buildModelCapsuleManifest(buildModelManifestInput{
		ModelPath: modelPath,
		Name:      "demo",
		Version:   "1",
		Format:    "gguf",
		ClientID:  "edge-a",
		TenantID:  "tenant-a",
		Profile:   trustProfileConfidential,
		CreatedAt: time.Date(2026, 5, 26, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	info := modelCapsuleArchiveInfo{
		Path:           filepath.Join(repoRoot, "demo.zmc"),
		CapsuleSHA256:  strings64("a"),
		ManifestSHA256: strings64("b"),
		PolicySHA256:   strings64("c"),
		PayloadSHA256:  strings64("d"),
	}
	if err := store.upsertModelCapsule(manifest, info, "", time.Date(2026, 5, 26, 1, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`update model_assets set status = 'revoked' where tenant_id = ?1 and model_id = ?2`, manifest.Distribution.TenantID, manifest.Model.ModelID); err != nil {
		t.Fatal(err)
	}
	if err := store.recordModelVerify(manifest, info, "", "verified", "model.verified", time.Date(2026, 5, 26, 2, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("recordModelVerify: %v", err)
	}
	var status string
	if err := store.db.QueryRow(`select status from model_assets where tenant_id = ?1 and model_id = ?2`, manifest.Distribution.TenantID, manifest.Model.ModelID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "active" {
		t.Fatalf("status=%q, want active", status)
	}
}

func strings64(ch string) string {
	out := ""
	for len(out) < 64 {
		out += ch
	}
	return out[:64]
}
