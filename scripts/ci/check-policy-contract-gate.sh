#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

echo "[policy-contract-gate] running gateway policy contract tests (v0.5f)"
go test ./gateway/zt -count=1 -run 'Policy.*Contract'

echo "[policy-contract-gate] running control-plane policy contract tests (v0.5f)"
go test ./control-plane/api/cmd/zt-control-plane -count=1 -run 'Policy(Bundle|Keyset).*Contract'

echo "[policy-contract-gate] ok"
