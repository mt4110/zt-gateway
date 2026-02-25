#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

echo "[contract-gate] running control-plane ingest envelope contract tests (v0.5d-1)"
go test ./control-plane/api/cmd/zt-control-plane -count=1 -run 'EventIngestEnvelope.*Contract'

echo "[contract-gate] running control-plane admin event-keys contract tests (v0.5d-2/v0.5d-3)"
go test ./control-plane/api/cmd/zt-control-plane -count=1 -run 'AdminEventKeys.*Contract'

echo "[contract-gate] control-plane ok"
