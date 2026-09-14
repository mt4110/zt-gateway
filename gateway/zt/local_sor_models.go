package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type localSORModelAssetRecord struct {
	ModelID           string `json:"model_id"`
	TenantID          string `json:"tenant_id"`
	Name              string `json:"name"`
	Version           string `json:"version"`
	Format            string `json:"format"`
	CapsuleID         string `json:"capsule_id,omitempty"`
	ArtifactSHA256    string `json:"artifact_sha256"`
	ManifestSHA256    string `json:"manifest_sha256"`
	DeclaredSizeBytes int64  `json:"declared_size_bytes"`
	CreatedAt         string `json:"created_at"`
	UpdatedAt         string `json:"updated_at"`
	LastSeenAt        string `json:"last_seen_at"`
	Status            string `json:"status"`
}

type localSORModelCapsuleRecord struct {
	CapsuleID               string `json:"capsule_id"`
	TenantID                string `json:"tenant_id"`
	ModelID                 string `json:"model_id"`
	CapsuleSHA256           string `json:"capsule_sha256"`
	SecurePackSHA256        string `json:"secure_pack_sha256"`
	PolicyHash              string `json:"policy_hash"`
	SignerFingerprint       string `json:"signer_fingerprint,omitempty"`
	CreatedAt               string `json:"created_at"`
	DistributionWatermarkID string `json:"distribution_watermark_id,omitempty"`
}

type localSORModelInventoryMetrics struct {
	TotalModels      int `json:"total_models"`
	ActiveModels     int `json:"active_models"`
	RevokedModels    int `json:"revoked_models"`
	TotalCapsules    int `json:"total_capsules"`
	ActiveSessions   int `json:"active_sessions"`
	RecentEventCount int `json:"recent_event_count"`
}

type runtimeSessionRecord struct {
	SessionID   string
	TenantID    string
	ModelID     string
	CapsuleID   string
	PermitID    string
	DeviceID    string
	RuntimeName string
	PID         int
	ShieldTier  string
	StartedAt   string
	EndedAt     string
	Result      string
}

func (s *localSORStore) upsertModelCapsule(manifest modelCapsuleManifestV1, info modelCapsuleArchiveInfo, signerFingerprint string, now time.Time) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("local sor is not initialized")
	}
	if err := validateModelCapsuleManifest(manifest); err != nil {
		return err
	}
	tenantID := strings.TrimSpace(manifest.Distribution.TenantID)
	if err := validateLocalSORTenantID(tenantID); err != nil {
		return err
	}
	modelID := strings.TrimSpace(manifest.Model.ModelID)
	capsuleID := strings.TrimSpace(manifest.CapsuleID)
	artifactSHA := ""
	if len(manifest.Artifacts) > 0 {
		artifactSHA = strings.TrimSpace(strings.ToLower(manifest.Artifacts[0].SHA256))
	}
	observedAt := now.UTC().Format(time.RFC3339)
	createdAt := strings.TrimSpace(manifest.Distribution.CreatedAt)
	if createdAt == "" {
		createdAt = observedAt
	}
	signerFingerprint = strings.TrimSpace(signerFingerprint)
	if fp, err := normalizePGPFingerprint(signerFingerprint); err == nil {
		signerFingerprint = fp
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(`
insert into model_assets (model_id, tenant_id, name, version, format, capsule_id, artifact_sha256, manifest_sha256, declared_size_bytes, created_at, updated_at, last_seen_at, status)
values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
on conflict(tenant_id, model_id) do update set
  name = excluded.name,
  version = excluded.version,
  format = excluded.format,
  capsule_id = excluded.capsule_id,
  artifact_sha256 = excluded.artifact_sha256,
  manifest_sha256 = excluded.manifest_sha256,
  declared_size_bytes = excluded.declared_size_bytes,
  updated_at = excluded.updated_at,
  last_seen_at = case
    when model_assets.last_seen_at > excluded.last_seen_at then model_assets.last_seen_at
    else excluded.last_seen_at
  end,
  status = excluded.status
`, modelID, tenantID, manifest.Model.Name, manifest.Model.Version, manifest.Model.Format, capsuleID, artifactSHA, info.ManifestSHA256, manifest.Model.DeclaredSizeBytes, createdAt, observedAt, observedAt, "active"); err != nil {
		return err
	}

	if _, err := tx.Exec(`
insert into model_capsules (capsule_id, tenant_id, model_id, capsule_sha256, secure_pack_sha256, policy_hash, signer_fingerprint, created_at, distribution_watermark_id)
values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
on conflict(capsule_id) do update set
  tenant_id = excluded.tenant_id,
  model_id = excluded.model_id,
  capsule_sha256 = excluded.capsule_sha256,
  secure_pack_sha256 = excluded.secure_pack_sha256,
  policy_hash = excluded.policy_hash,
  signer_fingerprint = excluded.signer_fingerprint,
  distribution_watermark_id = excluded.distribution_watermark_id
`, capsuleID, tenantID, modelID, info.CapsuleSHA256, info.PayloadSHA256, info.PolicySHA256, signerFingerprint, createdAt, manifest.Distribution.WatermarkID); err != nil {
		return err
	}

	if err := insertModelEventTx(tx, tenantID, modelID, capsuleID, "", "model_pack_completed", observedAt, "success", "", map[string]any{
		"capsule_sha256":     info.CapsuleSHA256,
		"secure_pack_sha256": info.PayloadSHA256,
		"manifest_sha256":    info.ManifestSHA256,
	}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *localSORStore) recordModelVerify(manifest modelCapsuleManifestV1, info modelCapsuleArchiveInfo, signerFingerprint, result, reasonCode string, now time.Time) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("local sor is not initialized")
	}
	tenantID := strings.TrimSpace(manifest.Distribution.TenantID)
	if err := validateLocalSORTenantID(tenantID); err != nil {
		return err
	}
	observedAt := now.UTC().Format(time.RFC3339)
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	artifactSHA := ""
	if len(manifest.Artifacts) > 0 {
		artifactSHA = strings.TrimSpace(strings.ToLower(manifest.Artifacts[0].SHA256))
	}
	createdAt := strings.TrimSpace(manifest.Distribution.CreatedAt)
	if createdAt == "" {
		createdAt = observedAt
	}
	if _, err := tx.Exec(`
insert into model_assets (model_id, tenant_id, name, version, format, capsule_id, artifact_sha256, manifest_sha256, declared_size_bytes, created_at, updated_at, last_seen_at, status)
values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
on conflict(tenant_id, model_id) do update set
  name = excluded.name,
  version = excluded.version,
  format = excluded.format,
  capsule_id = excluded.capsule_id,
  artifact_sha256 = excluded.artifact_sha256,
  manifest_sha256 = excluded.manifest_sha256,
  declared_size_bytes = excluded.declared_size_bytes,
  updated_at = excluded.updated_at,
  last_seen_at = case
    when model_assets.last_seen_at > excluded.last_seen_at then model_assets.last_seen_at
    else excluded.last_seen_at
  end,
  status = excluded.status
`, manifest.Model.ModelID, tenantID, manifest.Model.Name, manifest.Model.Version, manifest.Model.Format, manifest.CapsuleID, artifactSHA, info.ManifestSHA256, manifest.Model.DeclaredSizeBytes, createdAt, observedAt, observedAt, "active"); err != nil {
		return err
	}
	signerFingerprint = strings.TrimSpace(signerFingerprint)
	if fp, err := normalizePGPFingerprint(signerFingerprint); err == nil {
		signerFingerprint = fp
	}
	if _, err := tx.Exec(`
insert into model_capsules (capsule_id, tenant_id, model_id, capsule_sha256, secure_pack_sha256, policy_hash, signer_fingerprint, created_at, distribution_watermark_id)
values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
on conflict(capsule_id) do update set
  tenant_id = excluded.tenant_id,
  model_id = excluded.model_id,
  capsule_sha256 = excluded.capsule_sha256,
  secure_pack_sha256 = excluded.secure_pack_sha256,
  policy_hash = excluded.policy_hash,
  signer_fingerprint = excluded.signer_fingerprint,
  distribution_watermark_id = excluded.distribution_watermark_id
`, manifest.CapsuleID, tenantID, manifest.Model.ModelID, info.CapsuleSHA256, info.PayloadSHA256, info.PolicySHA256, signerFingerprint, createdAt, manifest.Distribution.WatermarkID); err != nil {
		return err
	}
	if err := insertModelEventTx(tx, tenantID, manifest.Model.ModelID, manifest.CapsuleID, "", "model_verify_completed", observedAt, result, reasonCode, map[string]any{
		"capsule_sha256":     info.CapsuleSHA256,
		"payload_sha256":     info.PayloadSHA256,
		"signer_fingerprint": strings.TrimSpace(signerFingerprint),
		"manifest_sha256":    info.ManifestSHA256,
		"policy_sha256":      info.PolicySHA256,
		"payload_size_bytes": info.PayloadSizeBytes,
	}); err != nil {
		return err
	}
	return tx.Commit()
}

func insertModelEventTx(tx *sql.Tx, tenantID, modelID, capsuleID, sessionID, eventType, occurredAt, result, reasonCode string, details map[string]any) error {
	if tx == nil {
		return fmt.Errorf("nil tx")
	}
	sessionID = strings.TrimSpace(sessionID)
	detailsJSON := "{}"
	if len(details) > 0 {
		b, err := json.Marshal(details)
		if err != nil {
			return fmt.Errorf("marshal model event details: %w", err)
		}
		detailsJSON = string(b)
	}
	payloadSHA := sha256HexBytes([]byte(detailsJSON))
	eventID := prefixedDigestID("evt_model", tenantID, modelID, capsuleID, sessionID, eventType, occurredAt, payloadSHA)
	_, err := tx.Exec(`
insert into model_events (event_id, tenant_id, model_id, capsule_id, session_id, event_type, occurred_at, result, reason_code, payload_sha256, details_json)
values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
on conflict(event_id) do nothing
`, eventID, tenantID, modelID, capsuleID, sessionID, eventType, occurredAt, strings.TrimSpace(result), strings.TrimSpace(reasonCode), payloadSHA, detailsJSON)
	return err
}

func (s *localSORStore) listModelAssets(tenantID, q string, limit, offset int, exportAll bool) ([]localSORModelAssetRecord, int, error) {
	if s == nil || s.db == nil {
		return nil, 0, fmt.Errorf("local sor is not initialized")
	}
	tenantID = strings.TrimSpace(tenantID)
	if err := validateLocalSORTenantID(tenantID); err != nil {
		return nil, 0, err
	}
	q = strings.TrimSpace(q)
	like := "%"
	if q != "" {
		like = "%" + q + "%"
	}
	limit, offset = normalizeLocalSORPaging(limit, offset, exportAll)

	var total int
	if err := s.db.QueryRow(`
select count(*) from model_assets
where tenant_id = ?1 and (?2 = '%' or model_id like ?2 or name like ?2 or version like ?2 or format like ?2)
`, tenantID, like).Scan(&total); err != nil {
		return nil, 0, err
	}

	query := `
select model_id, tenant_id, name, version, format, coalesce(capsule_id, ''), artifact_sha256, manifest_sha256, declared_size_bytes, created_at, updated_at, last_seen_at, status
from model_assets
where tenant_id = ?1 and (?2 = '%' or model_id like ?2 or name like ?2 or version like ?2 or format like ?2)
order by updated_at desc, name asc, version asc
`
	args := []any{tenantID, like}
	if !exportAll {
		query += `limit ?3 offset ?4`
		args = append(args, limit, offset)
	}
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	items := make([]localSORModelAssetRecord, 0)
	for rows.Next() {
		var item localSORModelAssetRecord
		if err := rows.Scan(
			&item.ModelID,
			&item.TenantID,
			&item.Name,
			&item.Version,
			&item.Format,
			&item.CapsuleID,
			&item.ArtifactSHA256,
			&item.ManifestSHA256,
			&item.DeclaredSizeBytes,
			&item.CreatedAt,
			&item.UpdatedAt,
			&item.LastSeenAt,
			&item.Status,
		); err != nil {
			return nil, 0, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (s *localSORStore) getModelAsset(tenantID, modelID string) (localSORModelAssetRecord, bool, error) {
	if s == nil || s.db == nil {
		return localSORModelAssetRecord{}, false, fmt.Errorf("local sor is not initialized")
	}
	tenantID = strings.TrimSpace(tenantID)
	modelID = strings.TrimSpace(modelID)
	if err := validateLocalSORTenantID(tenantID); err != nil {
		return localSORModelAssetRecord{}, false, err
	}
	if modelID == "" {
		return localSORModelAssetRecord{}, false, fmt.Errorf("model_id is required")
	}

	var item localSORModelAssetRecord
	err := s.db.QueryRow(`
select model_id, tenant_id, name, version, format, coalesce(capsule_id, ''), artifact_sha256, manifest_sha256, declared_size_bytes, created_at, updated_at, last_seen_at, status
from model_assets
where tenant_id = ?1 and model_id = ?2
`, tenantID, modelID).Scan(
		&item.ModelID,
		&item.TenantID,
		&item.Name,
		&item.Version,
		&item.Format,
		&item.CapsuleID,
		&item.ArtifactSHA256,
		&item.ManifestSHA256,
		&item.DeclaredSizeBytes,
		&item.CreatedAt,
		&item.UpdatedAt,
		&item.LastSeenAt,
		&item.Status,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return localSORModelAssetRecord{}, false, nil
		}
		return localSORModelAssetRecord{}, false, err
	}
	return item, true, nil
}

func (s *localSORStore) collectModelInventoryMetrics(tenantID string, now time.Time) (localSORModelInventoryMetrics, error) {
	if s == nil || s.db == nil {
		return localSORModelInventoryMetrics{}, fmt.Errorf("local sor is not initialized")
	}
	tenantID = strings.TrimSpace(tenantID)
	if err := validateLocalSORTenantID(tenantID); err != nil {
		return localSORModelInventoryMetrics{}, err
	}
	var out localSORModelInventoryMetrics
	if err := s.db.QueryRow(`
select
  count(*),
  coalesce(sum(case when lower(status) = 'active' then 1 else 0 end), 0),
  coalesce(sum(case when lower(status) = 'revoked' then 1 else 0 end), 0)
from model_assets
where tenant_id = ?1
`, tenantID).Scan(&out.TotalModels, &out.ActiveModels, &out.RevokedModels); err != nil {
		return localSORModelInventoryMetrics{}, err
	}
	if err := s.db.QueryRow(`select count(*) from model_capsules where tenant_id = ?1`, tenantID).Scan(&out.TotalCapsules); err != nil {
		return localSORModelInventoryMetrics{}, err
	}
	if err := s.db.QueryRow(`select count(*) from runtime_sessions where tenant_id = ?1 and (ended_at is null or ended_at = '')`, tenantID).Scan(&out.ActiveSessions); err != nil {
		return localSORModelInventoryMetrics{}, err
	}
	since := now.UTC().Add(-24 * time.Hour).Format(time.RFC3339)
	if err := s.db.QueryRow(`select count(*) from model_events where tenant_id = ?1 and occurred_at >= ?2`, tenantID, since).Scan(&out.RecentEventCount); err != nil {
		return localSORModelInventoryMetrics{}, err
	}
	return out, nil
}

func (s *localSORStore) startRuntimeSession(session runtimeSessionRecord, details map[string]any) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("local sor is not initialized")
	}
	if err := validateLocalSORTenantID(session.TenantID); err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`
insert into runtime_sessions (session_id, tenant_id, model_id, capsule_id, permit_id, device_id, runtime_name, pid, shield_tier, started_at, result)
values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
on conflict(session_id) do update set
  pid = excluded.pid,
  result = excluded.result
`, session.SessionID, session.TenantID, session.ModelID, session.CapsuleID, session.PermitID, session.DeviceID, session.RuntimeName, session.PID, session.ShieldTier, session.StartedAt, session.Result); err != nil {
		return err
	}
	if err := insertModelEventTx(tx, session.TenantID, session.ModelID, session.CapsuleID, session.SessionID, "runtime_started", session.StartedAt, session.Result, "", details); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *localSORStore) stopRuntimeSession(sessionID, tenantID, modelID, capsuleID, endedAt, result, reasonCode string, details map[string]any) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("local sor is not initialized")
	}
	if err := validateLocalSORTenantID(tenantID); err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`
update runtime_sessions
set ended_at = ?1,
    result = ?2
where session_id = ?3 and tenant_id = ?4
`, endedAt, result, sessionID, tenantID); err != nil {
		return err
	}
	if err := insertModelEventTx(tx, tenantID, modelID, capsuleID, sessionID, "runtime_stopped", endedAt, result, reasonCode, details); err != nil {
		return err
	}
	return tx.Commit()
}
