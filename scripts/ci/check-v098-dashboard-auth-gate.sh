#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

echo "[v0.9.8-dashboard-auth-gate] running dashboard mutation auth contracts"
go test ./gateway/zt -count=1 -run 'V098'

echo "[v0.9.8-dashboard-auth-gate] ok"
