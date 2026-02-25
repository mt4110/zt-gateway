#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

echo "[policy-rollout-gate] running gateway rollout/sync contracts (v0.5g)"
go test ./gateway/zt -count=1 -run 'Policy(SyncLoopContract|BundleVersionContract|KeysetContract|RotateFetchDecisionSyncAuditReceipt_E2EContract)'

echo "[policy-rollout-gate] running control-plane signing/keyset contracts (v0.5g)"
go test ./control-plane/api/cmd/zt-control-plane -count=1 -run 'Policy(Bundle|Keyset|Rollout).*Contract'

echo "[policy-rollout-gate] ok"
