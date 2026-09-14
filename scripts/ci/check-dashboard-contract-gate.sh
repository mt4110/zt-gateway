#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

echo "[dashboard-gate] running gateway dashboard contracts"
go test ./gateway/zt -count=1 -run 'CollectDashboardSnapshot|CollectDashboardIncidentStatus|DispatchDashboardAlerts|CollectDashboardControlPlaneStatus'

echo "[dashboard-gate] running control-plane dashboard contracts"
go test ./control-plane/api/cmd/zt-control-plane -count=1 -run 'Dashboard(Activity|Timeseries|Drilldown).*Contract'

echo "[dashboard-gate] ok"
