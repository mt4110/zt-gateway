#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

echo "[v0.9.7-dashboard-safety-gate] running dashboard alert-dispatch safety contracts"
go test ./gateway/zt -count=1 -run 'CollectDashboardSnapshot_AlertDispatch(UnsafeConfigSignal|AllowHostsConfigured_NoUnsafeSignal)'

echo "[v0.9.7-dashboard-safety-gate] ok"
