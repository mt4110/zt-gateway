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

type localSORFileHolderTimelinePoint struct {
	BucketStart   string `json:"bucket_start"`
	HolderCount   int    `json:"holder_count"`
	Delta         int    `json:"delta"`
	Added         int    `json:"added"`
	Removed       int    `json:"removed"`
	ExchangeCount int    `json:"exchange_count"`
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

func (s *localSORStore) fileHolderTimeline(tenantID, contentSHA256 string, windowDays int, now time.Time) ([]localSORFileHolderTimelinePoint, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("local sor is not initialized")
	}
	tenantID = strings.TrimSpace(tenantID)
	if err := validateLocalSORTenantID(tenantID); err != nil {
		return nil, err
	}
	contentSHA256 = strings.TrimSpace(contentSHA256)
	if contentSHA256 == "" {
		return nil, fmt.Errorf("content_sha256 is required")
	}
	if windowDays <= 0 {
		windowDays = 30
	}
	if windowDays > 400 {
		windowDays = 400
	}

	type holderInterval struct {
		firstSeen time.Time
		lastSeen  time.Time
	}
	intervals := make([]holderInterval, 0)
	rows, err := s.db.Query(`
select
  min(created_at) as first_seen,
  max(last_seen_at) as last_seen
from local_sor_assets
where tenant_id = ?1 and content_sha256 = ?2
group by client_id
`, tenantID, contentSHA256)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var firstSeenRaw, lastSeenRaw string
		if err := rows.Scan(&firstSeenRaw, &lastSeenRaw); err != nil {
			return nil, err
		}
		firstSeen, ok := parseLocalSORTimestamp(firstSeenRaw)
		if !ok {
			continue
		}
		lastSeen, ok := parseLocalSORTimestamp(lastSeenRaw)
		if !ok {
			lastSeen = firstSeen
		}
		if lastSeen.Before(firstSeen) {
			lastSeen = firstSeen
		}
		intervals = append(intervals, holderInterval{
			firstSeen: firstSeen.UTC(),
			lastSeen:  lastSeen.UTC(),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	start := now.UTC().Truncate(24*time.Hour).AddDate(0, 0, -(windowDays - 1))
	exchangeByDay := map[string]int{}
	exRows, err := s.db.Query(`
select
  substr(e.created_at, 1, 10) as bucket_day,
  count(*)
from local_sor_exchanges e
join local_sor_assets a
  on a.asset_id = e.asset_id
 and a.tenant_id = e.tenant_id
where e.tenant_id = ?1
  and a.content_sha256 = ?2
  and lower(coalesce(e.direction,'')) = 'verify'
  and e.created_at >= ?3
group by bucket_day
`, tenantID, contentSHA256, start.Format(time.RFC3339))
	if err != nil {
		return nil, err
	}
	defer exRows.Close()
	for exRows.Next() {
		var day string
		var count int
		if err := exRows.Scan(&day, &count); err != nil {
			return nil, err
		}
		exchangeByDay[strings.TrimSpace(day)] = count
	}
	if err := exRows.Err(); err != nil {
		return nil, err
	}

	out := make([]localSORFileHolderTimelinePoint, 0, windowDays)
	prev := 0
	for i := 0; i < windowDays; i++ {
		dayStart := start.AddDate(0, 0, i)
		dayEndExclusive := dayStart.Add(24 * time.Hour)
		count := 0
		for _, iv := range intervals {
			if iv.firstSeen.Before(dayEndExclusive) && !iv.lastSeen.Before(dayStart) {
				count++
			}
		}
		delta := count - prev
		point := localSORFileHolderTimelinePoint{
			BucketStart:   dayStart.Format(time.RFC3339),
			HolderCount:   count,
			Delta:         delta,
			Added:         maxInt(delta, 0),
			Removed:       maxInt(-delta, 0),
			ExchangeCount: exchangeByDay[dayStart.Format("2006-01-02")],
		}
		out = append(out, point)
		prev = count
	}
	return out, nil
}

func parseLocalSORTimestamp(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	if ts, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return ts, true
	}
	if ts, err := time.Parse(time.RFC3339, raw); err == nil {
		return ts, true
	}
	return time.Time{}, false
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
