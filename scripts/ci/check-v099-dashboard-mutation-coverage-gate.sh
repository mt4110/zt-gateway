#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

echo "[v0.9.9-dashboard-mutation-coverage-gate] running dashboard mutation auth coverage contracts"
go test ./gateway/zt -count=1 -run 'V099'

echo "[v0.9.9-dashboard-mutation-coverage-gate] ok"
