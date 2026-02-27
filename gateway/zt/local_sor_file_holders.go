package main

import (
	"fmt"
	"strings"
	"time"
)

type localSORFileHolderRecord struct {
	TenantID          string   `json:"tenant_id"`
	ContentSHA256     string   `json:"content_sha256"`
	FilenameSample    string   `json:"filename_sample"`
	AssetCount        int      `json:"asset_count"`
	HolderClientCount int      `json:"holder_client_count"`
	HolderClients     []string `json:"holder_clients"`
	SignatureCount    int      `json:"signature_count"`
	ExchangeCount     int      `json:"exchange_count"`
	LastSeenAt        string   `json:"last_seen_at"`
}

func (s *localSORStore) listFileHolders(tenantID, q, sortBy string, limit, offset int, exportAll bool) ([]localSORFileHolderRecord, int, error) {
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
select count(*) from (
  select 1
  from local_sor_assets a
  where a.tenant_id = ?1
    and (?2 = '%' or a.filename like ?2 or a.content_sha256 like ?2 or coalesce(a.location_ref,'') like ?2)
  group by a.tenant_id, a.content_sha256
) x
`, tenantID, like).Scan(&total); err != nil {
		return nil, 0, err
	}

	orderBy := "max(a.last_seen_at) desc, a.content_sha256 asc"
	switch strings.ToLower(strings.TrimSpace(sortBy)) {
	case "last_seen_asc":
		orderBy = "max(a.last_seen_at) asc, a.content_sha256 asc"
	case "holder_desc":
		orderBy = "count(distinct a.client_id) desc, a.content_sha256 asc"
	case "holder_asc":
		orderBy = "count(distinct a.client_id) asc, a.content_sha256 asc"
	case "exchange_desc":
		orderBy = "count(e.exchange_id) desc, a.content_sha256 asc"
	case "exchange_asc":
		orderBy = "count(e.exchange_id) asc, a.content_sha256 asc"
	}

	query := `
select
  a.tenant_id,
  a.content_sha256,
  min(a.filename) as filename_sample,
  count(distinct a.asset_id) as asset_count,
  count(distinct a.client_id) as holder_client_count,
  coalesce(group_concat(distinct a.client_id), '') as holder_clients_csv,
  count(distinct case when trim(coalesce(e.signer_fingerprint,'')) <> '' then e.signer_fingerprint end) as signature_count,
  count(e.exchange_id) as exchange_count,
  coalesce(max(a.last_seen_at), '') as last_seen_at
from local_sor_assets a
left join local_sor_exchanges e
  on e.tenant_id = a.tenant_id
 and e.asset_id = a.asset_id
 and lower(coalesce(e.direction,'')) = 'verify'
where a.tenant_id = ?1
  and (?2 = '%' or a.filename like ?2 or a.content_sha256 like ?2 or coalesce(a.location_ref,'') like ?2)
group by a.tenant_id, a.content_sha256
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

	items := make([]localSORFileHolderRecord, 0)
	now := time.Now().UTC()
	for rows.Next() {
		var item localSORFileHolderRecord
		var holderCSV string
		if err := rows.Scan(
			&item.TenantID,
			&item.ContentSHA256,
			&item.FilenameSample,
			&item.AssetCount,
			&item.HolderClientCount,
			&holderCSV,
			&item.SignatureCount,
			&item.ExchangeCount,
			&item.LastSeenAt,
		); err != nil {
			return nil, 0, err
		}
		item.HolderClients = splitDashboardCSV(holderCSV)
		item.LastSeenAt = normalizeLocalSORTime(item.LastSeenAt, now)
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func splitDashboardCSV(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, ok := seen[part]; ok {
			continue
		}
		seen[part] = struct{}{}
		out = append(out, part)
	}
	return out
}
