package main

import (
	"fmt"
	"strings"
)

type localSORExchangeMetrics struct {
	ExchangeTotal int
	SendCount     int
	ReceiveCount  int
	VerifyCount   int
	VerifyPass    int
	VerifyFail    int
}

func (s *localSORStore) collectExchangeMetrics(tenantID string) (localSORExchangeMetrics, error) {
	if s == nil || s.db == nil {
		return localSORExchangeMetrics{}, fmt.Errorf("local sor is not initialized")
	}
	tenantID = strings.TrimSpace(tenantID)
	if err := validateLocalSORTenantID(tenantID); err != nil {
		return localSORExchangeMetrics{}, err
	}

	var out localSORExchangeMetrics
	if err := s.db.QueryRow(`
select
  count(*) as exchange_total,
  coalesce(sum(case
    when lower(coalesce(direction,'')) in ('send','outbound','tx') then 1
    else 0
  end), 0) as send_count,
  coalesce(sum(case
    when lower(coalesce(direction,'')) in ('receive','recv','inbound','rx') then 1
    else 0
  end), 0) as receive_count,
  coalesce(sum(case
    when lower(coalesce(direction,'')) = 'verify' then 1
    else 0
  end), 0) as verify_count,
  coalesce(sum(case
    when lower(coalesce(direction,'')) = 'verify'
      and (
        lower(coalesce(result,'')) = 'verified'
        or lower(coalesce(verify_result,'')) like '%pass%'
      ) then 1
    else 0
  end), 0) as verify_pass,
  coalesce(sum(case
    when lower(coalesce(direction,'')) = 'verify'
      and (
        lower(coalesce(result,'')) = 'failed'
        or lower(coalesce(verify_result,'')) like '%fail%'
        or lower(coalesce(verify_result,'')) like '%deny%'
      ) then 1
    else 0
  end), 0) as verify_fail
from local_sor_exchanges
where tenant_id = ?1
`, tenantID).Scan(
		&out.ExchangeTotal,
		&out.SendCount,
		&out.ReceiveCount,
		&out.VerifyCount,
		&out.VerifyPass,
		&out.VerifyFail,
	); err != nil {
		return localSORExchangeMetrics{}, err
	}
	return out, nil
}
