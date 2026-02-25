#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

echo "[1/13] go test ./gateway/zt"
go test ./gateway/zt -count=1

echo "[2/13] zt contract gate"
bash ./scripts/ci/check-zt-contract-gate.sh

echo "[3/13] control-plane contract gate"
bash ./scripts/ci/check-control-plane-contract-gate.sh

echo "[4/13] policy contract gate"
bash ./scripts/ci/check-policy-contract-gate.sh

echo "[5/13] policy rollout gate"
bash ./scripts/ci/check-policy-rollout-gate.sh

echo "[6/13] policy set gate"
bash ./scripts/ci/check-policy-set-gate.sh

echo "[7/13] sync observability gate"
bash ./scripts/ci/check-sync-observability-gate.sh

echo "[8/13] OpenAPI contract gate"
bash ./scripts/ci/check-openapi-contract-gate.sh

echo "[9/13] v0.7.0 core gate"
bash ./scripts/ci/check-v070-core-gate.sh

echo "[10/13] go test ./tools/secure-pack/internal/workflows"
go test ./tools/secure-pack/internal/workflows -count=1

echo "[11/13] fixture supply-chain gate"
bash ./scripts/ci/check-zt-setup-json-gate.sh

echo "[12/13] actual repo supply-chain gate"
if [[ "${SKIP_ACTUAL_GATE:-0}" == "1" ]]; then
  echo "skipped (SKIP_ACTUAL_GATE=1)"
else
  bash ./scripts/ci/check-zt-setup-json-actual-gate.sh
fi

echo "[13/13] git status summary (manual review before commit/push)"
git status --short

echo
echo "[OK] Pre-push readiness checks completed."
echo "Review git diff / git status, then commit and push."
