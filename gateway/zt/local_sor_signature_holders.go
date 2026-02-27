package main

import (
	"fmt"
	"strings"
	"time"
)

type localSORSignatureHolderRecord struct {
	SignatureID          string `json:"signature_id"`
	TenantID             string `json:"tenant_id"`
	HolderCountEstimated int    `json:"holder_count_estimated"`
	HolderCountConfirmed int    `json:"holder_count_confirmed"`
	EventCount           int    `json:"event_count"`
	LastSeenAt           string `json:"last_seen_at"`
	ClientEventCount     int    `json:"client_event_count,omitempty"`
}

func (s *localSORStore) observeSignatureHolderFromReceipt(tenantID string, receipt verificationReceipt, now time.Time) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("local sor is not initialized")
	}
	tenantID = strings.TrimSpace(tenantID)
	if err := validateLocalSORTenantID(tenantID); err != nil {
		return err
	}
	signatureID := strings.TrimSpace(receipt.Provenance.KeyFingerprint)
	if signatureID == "" {
		return nil
	}
	if fp, err := normalizePGPFingerprint(signatureID); err == nil {
		signatureID = fp
	}
	updatedAt := normalizeLocalSORTime(receipt.VerifiedAt, now)
	return s.refreshSignatureHolder(tenantID, signatureID, updatedAt)
}

func (s *localSORStore) refreshSignatureHolder(tenantID, signatureID, updatedAt string) error {
	signatureID = strings.TrimSpace(signatureID)
	if signatureID == "" {
		return nil
	}
	var estimated, confirmed int
	if err := s.db.QueryRow(`
select
  count(distinct client_id),
  count(distinct case
    when lower(coalesce(verify_result,'')) like '%pass%'
    then client_id end)
from local_sor_exchanges
where tenant_id = ?1
  and lower(coalesce(direction,'')) = 'verify'
  and signer_fingerprint = ?2
`, tenantID, signatureID).Scan(&estimated, &confirmed); err != nil {
		return err
	}
	if _, err := s.db.Exec(`
insert into local_sor_signature_holders (tenant_id, signature_id, holder_count_estimated, holder_count_confirmed, updated_at)
values (?1, ?2, ?3, ?4, ?5)
on conflict(tenant_id, signature_id) do update set
  holder_count_estimated = excluded.holder_count_estimated,
  holder_count_confirmed = excluded.holder_count_confirmed,
  updated_at = excluded.updated_at
`, tenantID, signatureID, estimated, confirmed, strings.TrimSpace(updatedAt)); err != nil {
		return err
	}
	return nil
}

func (s *localSORStore) listSignatureHolders(tenantID, q, sortBy string, limit, offset int, exportAll bool) ([]localSORSignatureHolderRecord, int, error) {
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

	var total int
	if err := s.db.QueryRow(`
select count(*) from local_sor_signature_holders
where tenant_id = ?1 and (?2 = '%' or signature_id like ?2)
`, tenantID, like).Scan(&total); err != nil {
		return nil, 0, err
	}

	orderBy := "sh.updated_at desc, sh.signature_id asc"
	switch strings.ToLower(strings.TrimSpace(sortBy)) {
	case "updated_at_asc":
		orderBy = "sh.updated_at asc, sh.signature_id asc"
	case "holder_desc":
		orderBy = "sh.holder_count_estimated desc, sh.signature_id asc"
	case "holder_asc":
		orderBy = "sh.holder_count_estimated asc, sh.signature_id asc"
	case "event_desc":
		orderBy = "coalesce(ev.event_count, 0) desc, sh.signature_id asc"
	case "event_asc":
		orderBy = "coalesce(ev.event_count, 0) asc, sh.signature_id asc"
	}

	query := `
select
  sh.signature_id,
  sh.tenant_id,
  sh.holder_count_estimated,
  sh.holder_count_confirmed,
  coalesce(ev.event_count, 0),
  sh.updated_at,
  0
from local_sor_signature_holders sh
left join (
  select signer_fingerprint as signature_id, count(*) as event_count
  from local_sor_exchanges
  where tenant_id = ?1 and lower(coalesce(direction,'')) = 'verify' and trim(coalesce(signer_fingerprint,'')) <> ''
  group by signer_fingerprint
) ev on ev.signature_id = sh.signature_id
where sh.tenant_id = ?1 and (?2 = '%' or sh.signature_id like ?2)
order by ` + orderBy + `
`
	args := []any{tenantID, like}
	if !exportAll {
		query += "limit ?3 offset ?4"
		args = append(args, limit, offset)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	items := make([]localSORSignatureHolderRecord, 0, limit)
	for rows.Next() {
		var item localSORSignatureHolderRecord
		if err := rows.Scan(
			&item.SignatureID,
			&item.TenantID,
			&item.HolderCountEstimated,
			&item.HolderCountConfirmed,
			&item.EventCount,
			&item.LastSeenAt,
			&item.ClientEventCount,
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

func (s *localSORStore) listClientSignatureHolders(tenantID, clientID, q, sortBy string, limit, offset int, exportAll bool) ([]localSORSignatureHolderRecord, int, error) {
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

	var total int
	if err := s.db.QueryRow(`
select count(*) from (
  select signer_fingerprint as signature_id
  from local_sor_exchanges
  where tenant_id = ?1 and client_id = ?2 and lower(coalesce(direction,'')) = 'verify' and trim(coalesce(signer_fingerprint,'')) <> ''
  group by signer_fingerprint
) x
where (?3 = '%' or signature_id like ?3)
`, tenantID, clientID, like).Scan(&total); err != nil {
		return nil, 0, err
	}

	orderBy := "coalesce(sh.updated_at, c.client_last_seen_at) desc, c.signature_id asc"
	switch strings.ToLower(strings.TrimSpace(sortBy)) {
	case "updated_at_asc":
		orderBy = "coalesce(sh.updated_at, c.client_last_seen_at) asc, c.signature_id asc"
	case "holder_desc":
		orderBy = "coalesce(sh.holder_count_estimated, g.estimated_holders, 0) desc, c.signature_id asc"
	case "holder_asc":
		orderBy = "coalesce(sh.holder_count_estimated, g.estimated_holders, 0) asc, c.signature_id asc"
	case "event_desc":
		orderBy = "coalesce(g.event_count, 0) desc, c.signature_id asc"
	case "event_asc":
		orderBy = "coalesce(g.event_count, 0) asc, c.signature_id asc"
	}

	query := `
with c as (
  select
    signer_fingerprint as signature_id,
    count(*) as client_event_count,
    max(created_at) as client_last_seen_at
  from local_sor_exchanges
  where tenant_id = ?1 and client_id = ?2 and lower(coalesce(direction,'')) = 'verify' and trim(coalesce(signer_fingerprint,'')) <> ''
  group by signer_fingerprint
),
g as (
  select
    signer_fingerprint as signature_id,
    count(*) as event_count,
    count(distinct client_id) as estimated_holders,
    count(distinct case
      when lower(coalesce(result,'')) = 'verified'
        or lower(coalesce(verify_result,'')) like '%pass%'
      then client_id end) as confirmed_holders
  from local_sor_exchanges
  where tenant_id = ?1 and lower(coalesce(direction,'')) = 'verify' and trim(coalesce(signer_fingerprint,'')) <> ''
  group by signer_fingerprint
)
select
  c.signature_id,
  ?1 as tenant_id,
  coalesce(sh.holder_count_estimated, g.estimated_holders, 0),
  coalesce(sh.holder_count_confirmed, g.confirmed_holders, 0),
  coalesce(g.event_count, 0),
  coalesce(sh.updated_at, c.client_last_seen_at, ''),
  coalesce(c.client_event_count, 0)
from c
left join g on g.signature_id = c.signature_id
left join local_sor_signature_holders sh on sh.tenant_id = ?1 and sh.signature_id = c.signature_id
where (?3 = '%' or c.signature_id like ?3)
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

	items := make([]localSORSignatureHolderRecord, 0, limit)
	for rows.Next() {
		var item localSORSignatureHolderRecord
		if err := rows.Scan(
			&item.SignatureID,
			&item.TenantID,
			&item.HolderCountEstimated,
			&item.HolderCountConfirmed,
			&item.EventCount,
			&item.LastSeenAt,
			&item.ClientEventCount,
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
