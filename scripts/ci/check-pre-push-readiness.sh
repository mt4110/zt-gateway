#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

echo "[1/7] go test ./gateway/zt"
go test ./gateway/zt -count=1

echo "[2/7] zt contract gate"
bash ./scripts/ci/check-zt-contract-gate.sh

echo "[3/7] control-plane contract gate"
bash ./scripts/ci/check-control-plane-contract-gate.sh

echo "[4/7] go test ./tools/secure-pack/internal/workflows"
go test ./tools/secure-pack/internal/workflows -count=1

echo "[5/7] fixture supply-chain gate"
bash ./scripts/ci/check-zt-setup-json-gate.sh

echo "[6/7] actual repo supply-chain gate"
if [[ "${SKIP_ACTUAL_GATE:-0}" == "1" ]]; then
  echo "skipped (SKIP_ACTUAL_GATE=1)"
else
  bash ./scripts/ci/check-zt-setup-json-actual-gate.sh
fi

echo "[7/7] git status summary (manual review before commit/push)"
git status --short

echo
echo "[OK] Pre-push readiness checks completed."
echo "Review git diff / git status, then commit and push."
