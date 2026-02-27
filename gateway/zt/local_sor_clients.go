package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

type localSORClientSummary struct {
	ClientID          string
	TenantID          string
	DisplayName       string
	Status            string
	CreatedAt         string
	UpdatedAt         string
	AssetCount        int
	LastSeenAt        string
	FileExchangeCount int
}

type localSORAssetRecord struct {
	AssetID       string
	TenantID      string
	ClientID      string
	Filename      string
	ContentSHA256 string
	LocationType  string
	LocationRef   string
	CreatedAt     string
	LastSeenAt    string
	AccessCount   int
}

func (s *localSORStore) ingestVerificationReceipt(tenantID string, receipt verificationReceipt, now time.Time) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("local sor is not initialized")
	}
	tenantID = strings.TrimSpace(tenantID)
	if err := validateLocalSORTenantID(tenantID); err != nil {
		return err
	}
	clientID := strings.TrimSpace(receipt.Provenance.Client)
	if clientID == "" {
		clientID = "unknown"
	}
	displayName := clientID
	status := "active"

	observedAt := normalizeLocalSORTime(receipt.VerifiedAt, now)
	assetSHA := strings.TrimSpace(strings.ToLower(receipt.Artifact.SHA256))
	artifactPath := strings.TrimSpace(receipt.Artifact.Path)
	assetID := localSORAssetID(tenantID, assetSHA, artifactPath, clientID)
	filename := strings.TrimSpace(artifactPath)
	if filename == "" {
		filename = strings.TrimSpace(receipt.ReceiptID) + ".artifact"
	}
	locationType := "local_path"
	if strings.HasPrefix(strings.ToLower(artifactPath), "http://") || strings.HasPrefix(strings.ToLower(artifactPath), "https://") {
		locationType = "url"
	}
	locationRef := artifactPath
	if locationRef == "" {
		locationRef = "unknown"
	}
	exchangeID := strings.TrimSpace(receipt.ReceiptID)
	if exchangeID == "" {
		exchangeID = "exchange_" + localSORAssetID(tenantID, assetSHA, artifactPath, receipt.VerifiedAt)
	}
	verifyResult := strings.TrimSpace(receipt.Verification.PolicyResult)
	if verifyResult == "" {
		verifyResult = "unknown"
	}
	signerFingerprint := strings.TrimSpace(receipt.Provenance.KeyFingerprint)
	if fp, err := normalizePGPFingerprint(signerFingerprint); err == nil {
		signerFingerprint = fp
	}
	result := "verified"
	if receipt.Verification.TamperDetected || !receipt.Verification.SignatureValid {
		result = "failed"
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if _, err := tx.Exec(`
insert into local_sor_clients (client_id, tenant_id, display_name, status, created_at, updated_at)
values (?1, ?2, ?3, ?4, ?5, ?6)
on conflict(tenant_id, client_id) do update set
  display_name = excluded.display_name,
  status = excluded.status,
  updated_at = excluded.updated_at
`, clientID, tenantID, displayName, status, observedAt, observedAt); err != nil {
		return err
	}

	if _, err := tx.Exec(`
insert into local_sor_assets (asset_id, tenant_id, client_id, filename, content_sha256, location_type, location_ref, created_at, last_seen_at, access_count)
values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1)
on conflict(asset_id) do update set
  tenant_id = excluded.tenant_id,
  client_id = excluded.client_id,
  filename = excluded.filename,
  content_sha256 = excluded.content_sha256,
  location_type = excluded.location_type,
  location_ref = excluded.location_ref,
  last_seen_at = case
    when local_sor_assets.last_seen_at > excluded.last_seen_at then local_sor_assets.last_seen_at
    else excluded.last_seen_at
  end,
  access_count = local_sor_assets.access_count + 1
`, assetID, tenantID, clientID, filename, assetSHA, locationType, locationRef, observedAt, observedAt); err != nil {
		return err
	}

	if _, err := tx.Exec(`
insert into local_sor_exchanges (exchange_id, tenant_id, client_id, asset_id, direction, result, verify_result, signer_fingerprint, created_at)
values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
on conflict(exchange_id) do nothing
`, exchangeID, tenantID, clientID, assetID, "verify", result, verifyResult, signerFingerprint, observedAt); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	if err := s.observeVerificationKey(tenantID, receipt, now); err != nil {
		return err
	}
	if err := s.observeSignatureHolderFromReceipt(tenantID, receipt, now); err != nil {
		return err
	}
	return nil
}

func (s *localSORStore) listClients(tenantID, q, sortBy string, limit, offset int, exportAll bool) ([]localSORClientSummary, int, error) {
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
select count(*) from local_sor_clients
where tenant_id = ?1 and (?2 = '%' or client_id like ?2 or display_name like ?2)
`, tenantID, like).Scan(&total); err != nil {
		return nil, 0, err
	}

	orderBy := "c.created_at desc, c.client_id asc"
	switch strings.ToLower(strings.TrimSpace(sortBy)) {
	case "created_at_asc":
		orderBy = "c.created_at asc, c.client_id asc"
	case "last_seen_desc":
		orderBy = "coalesce(a.last_seen_at,'') desc, c.client_id asc"
	case "last_seen_asc":
		orderBy = "coalesce(a.last_seen_at,'') asc, c.client_id asc"
	}

	baseQuery := `
select
  c.client_id,
  c.tenant_id,
  c.display_name,
  c.status,
  c.created_at,
  c.updated_at,
  coalesce(a.asset_count, 0),
  coalesce(a.last_seen_at, ''),
  coalesce(e.exchange_count, 0)
from local_sor_clients c
left join (
  select tenant_id, client_id, count(*) as asset_count, max(last_seen_at) as last_seen_at
  from local_sor_assets
  where tenant_id = ?1
  group by tenant_id, client_id
) a on a.tenant_id = c.tenant_id and a.client_id = c.client_id
left join (
  select tenant_id, client_id, count(*) as exchange_count
  from local_sor_exchanges
  where tenant_id = ?1
  group by tenant_id, client_id
) e on e.tenant_id = c.tenant_id and e.client_id = c.client_id
where c.tenant_id = ?1 and (?2 = '%' or c.client_id like ?2 or c.display_name like ?2)
order by ` + orderBy + `
`
	args := []any{tenantID, like}
	if !exportAll {
		baseQuery += "limit ?3 offset ?4"
		args = append(args, limit, offset)
	}

	rows, err := s.db.Query(baseQuery, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	items := make([]localSORClientSummary, 0)
	for rows.Next() {
		var item localSORClientSummary
		if err := rows.Scan(
			&item.ClientID,
			&item.TenantID,
			&item.DisplayName,
			&item.Status,
			&item.CreatedAt,
			&item.UpdatedAt,
			&item.AssetCount,
			&item.LastSeenAt,
			&item.FileExchangeCount,
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

func (s *localSORStore) getClient(tenantID, clientID string) (localSORClientSummary, bool, error) {
	if s == nil || s.db == nil {
		return localSORClientSummary{}, false, fmt.Errorf("local sor is not initialized")
	}
	tenantID = strings.TrimSpace(tenantID)
	clientID = strings.TrimSpace(clientID)
	if err := validateLocalSORTenantID(tenantID); err != nil {
		return localSORClientSummary{}, false, err
	}
	if clientID == "" {
		return localSORClientSummary{}, false, fmt.Errorf("client_id is required")
	}

	var item localSORClientSummary
	err := s.db.QueryRow(`
select
  c.client_id,
  c.tenant_id,
  c.display_name,
  c.status,
  c.created_at,
  c.updated_at,
  coalesce((select count(*) from local_sor_assets a where a.tenant_id = c.tenant_id and a.client_id = c.client_id), 0),
  coalesce((select max(a.last_seen_at) from local_sor_assets a where a.tenant_id = c.tenant_id and a.client_id = c.client_id), ''),
  coalesce((select count(*) from local_sor_exchanges e where e.tenant_id = c.tenant_id and e.client_id = c.client_id), 0)
from local_sor_clients c
where c.tenant_id = ?1 and c.client_id = ?2
`, tenantID, clientID).Scan(
		&item.ClientID,
		&item.TenantID,
		&item.DisplayName,
		&item.Status,
		&item.CreatedAt,
		&item.UpdatedAt,
		&item.AssetCount,
		&item.LastSeenAt,
		&item.FileExchangeCount,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return localSORClientSummary{}, false, nil
		}
		return localSORClientSummary{}, false, err
	}
	return item, true, nil
}

func (s *localSORStore) listClientAssets(tenantID, clientID, q, sortBy string, limit, offset int, exportAll bool) ([]localSORAssetRecord, int, error) {
	if s == nil || s.db == nil {
		return nil, 0, fmt.Errorf("local sor is not initialized")
	}
	tenantID = strings.TrimSpace(tenantID)
	clientID = strings.TrimSpace(clientID)
	if err := validateLocalSORTenantID(tenantID); err != nil {
		return nil, 0, err
	}
	if clientID == "" {
		return nil, 0, fmt.Errorf("client_id is required")
	}
	q = strings.TrimSpace(q)
	like := "%"
	if q != "" {
		like = "%" + q + "%"
	}
	limit, offset = normalizeLocalSORPaging(limit, offset, exportAll)

	var total int
	if err := s.db.QueryRow(`
select count(*) from local_sor_assets
where tenant_id = ?1 and client_id = ?2 and (?3 = '%' or filename like ?3 or content_sha256 like ?3 or coalesce(location_ref,'') like ?3)
`, tenantID, clientID, like).Scan(&total); err != nil {
		return nil, 0, err
	}

	orderBy := "last_seen_at desc, created_at desc, asset_id asc"
	switch strings.ToLower(strings.TrimSpace(sortBy)) {
	case "created_at_desc":
		orderBy = "created_at desc, asset_id asc"
	case "created_at_asc":
		orderBy = "created_at asc, asset_id asc"
	case "last_seen_asc":
		orderBy = "last_seen_at asc, asset_id asc"
	}
	query := `
select asset_id, tenant_id, client_id, filename, content_sha256, location_type, coalesce(location_ref,''), created_at, last_seen_at, access_count
from local_sor_assets
where tenant_id = ?1 and client_id = ?2 and (?3 = '%' or filename like ?3 or content_sha256 like ?3 or coalesce(location_ref,'') like ?3)
order by ` + orderBy + `
`
	args := []any{tenantID, clientID, like}
	if !exportAll {
		query += "limit ?4 offset ?5"
		args = append(args, limit, offset)
	}
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	items := make([]localSORAssetRecord, 0)
	for rows.Next() {
		var item localSORAssetRecord
		if err := rows.Scan(
			&item.AssetID,
			&item.TenantID,
			&item.ClientID,
			&item.Filename,
			&item.ContentSHA256,
			&item.LocationType,
			&item.LocationRef,
			&item.CreatedAt,
			&item.LastSeenAt,
			&item.AccessCount,
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

func localSORAssetID(parts ...string) string {
	h := sha256.New()
	for _, part := range parts {
		v := strings.TrimSpace(part)
		if v == "" {
			continue
		}
		_, _ = h.Write([]byte(v))
		_, _ = h.Write([]byte("|"))
	}
	sum := h.Sum(nil)
	return "asset_" + hex.EncodeToString(sum[:16])
}

func normalizeLocalSORTime(raw string, fallback time.Time) string {
	raw = strings.TrimSpace(raw)
	if raw != "" {
		if ts, err := time.Parse(time.RFC3339Nano, raw); err == nil {
			return ts.UTC().Format(time.RFC3339)
		}
		if ts, err := time.Parse(time.RFC3339, raw); err == nil {
			return ts.UTC().Format(time.RFC3339)
		}
	}
	return fallback.UTC().Format(time.RFC3339)
}
