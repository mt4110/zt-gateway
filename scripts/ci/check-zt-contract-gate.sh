#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

echo "[contract-gate] running zt contract tests"
go test ./gateway/zt -count=1 -run 'Contract|JSONContract|E2EContract'

echo "[contract-gate] ok"
