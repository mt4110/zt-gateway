#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

echo "[contract-gate] running zt contract tests"
go test ./gateway/zt -count=1 -run 'Contract|JSONContract|E2EContract'

echo "[contract-gate] running zt audit trail contract tests (v0.5-A)"
go test ./gateway/zt -count=1 -run 'Audit.*Contract'

echo "[contract-gate] ok"
