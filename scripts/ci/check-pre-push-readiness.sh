#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

echo "[1/8] go test ./gateway/zt"
go test ./gateway/zt -count=1

echo "[2/8] zt contract gate"
bash ./scripts/ci/check-zt-contract-gate.sh

echo "[3/8] control-plane contract gate"
bash ./scripts/ci/check-control-plane-contract-gate.sh

echo "[4/8] policy contract gate"
bash ./scripts/ci/check-policy-contract-gate.sh

echo "[5/8] go test ./tools/secure-pack/internal/workflows"
go test ./tools/secure-pack/internal/workflows -count=1

echo "[6/8] fixture supply-chain gate"
bash ./scripts/ci/check-zt-setup-json-gate.sh

echo "[7/8] actual repo supply-chain gate"
if [[ "${SKIP_ACTUAL_GATE:-0}" == "1" ]]; then
  echo "skipped (SKIP_ACTUAL_GATE=1)"
else
  bash ./scripts/ci/check-zt-setup-json-actual-gate.sh
fi

echo "[8/8] git status summary (manual review before commit/push)"
git status --short

echo
echo "[OK] Pre-push readiness checks completed."
echo "Review git diff / git status, then commit and push."
