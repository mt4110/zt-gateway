#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

echo "[policy-set-gate] running gateway policy set/freshness contracts (v0.6.0MAX)"
go test ./gateway/zt -count=1 -run 'PolicyStatus.*(SetConsistency|FreshnessSLO).*Contract'

echo "[policy-set-gate] running control-plane policy contracts (v0.6.0MAX)"
go test ./control-plane/api/cmd/zt-control-plane -count=1 -run 'Policy(Bundle|Keyset).*Contract'

echo "[policy-set-gate] ok"
