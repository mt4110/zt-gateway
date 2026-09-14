#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

echo "[sync-observability-gate] running gateway sync observability contracts (v0.6.0MAX)"
go test ./gateway/zt -count=1 -run 'SyncCLIJSONContract_(BacklogVisibilityContract|AckIntegrityMismatchContract)'

echo "[sync-observability-gate] ok"
