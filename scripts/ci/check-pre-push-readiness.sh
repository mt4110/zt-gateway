#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

echo "[1/15] go test ./gateway/zt"
go test ./gateway/zt -count=1

echo "[2/15] zt contract gate"
bash ./scripts/ci/check-zt-contract-gate.sh

echo "[3/15] control-plane contract gate"
bash ./scripts/ci/check-control-plane-contract-gate.sh

echo "[4/15] policy contract gate"
bash ./scripts/ci/check-policy-contract-gate.sh

echo "[5/15] policy rollout gate"
bash ./scripts/ci/check-policy-rollout-gate.sh

echo "[6/15] policy set gate"
bash ./scripts/ci/check-policy-set-gate.sh

echo "[7/15] sync observability gate"
bash ./scripts/ci/check-sync-observability-gate.sh

echo "[8/15] OpenAPI contract gate"
bash ./scripts/ci/check-openapi-contract-gate.sh

echo "[9/15] v0.7.0 core gate"
bash ./scripts/ci/check-v070-core-gate.sh

echo "[10/15] v0.8.0 core gate"
bash ./scripts/ci/check-v080-core-gate.sh

echo "[11/15] v0.9.0 core gate"
bash ./scripts/ci/check-v090-core-gate.sh

echo "[12/15] go test ./tools/secure-pack/internal/workflows"
go test ./tools/secure-pack/internal/workflows -count=1

echo "[13/15] fixture supply-chain gate"
bash ./scripts/ci/check-zt-setup-json-gate.sh

echo "[14/15] actual repo supply-chain gate"
if [[ "${SKIP_ACTUAL_GATE:-0}" == "1" ]]; then
  echo "skipped (SKIP_ACTUAL_GATE=1)"
else
  if [[ "${ZT_PREPUSH_AUTO_EXPECTED_PIN_BOOTSTRAP:-0}" == "1" ]] && \
     [[ -z "${ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS:-}" ]] && \
     [[ -z "${ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS_EXPECTED:-}" ]] && \
     [[ -f "./tools/secure-pack/ROOT_PUBKEY.asc" ]] && \
     command -v gpg >/dev/null 2>&1; then
    resolved_fpr="$(gpg --show-keys --with-colons ./tools/secure-pack/ROOT_PUBKEY.asc | awk -F: '/^fpr:/ {print $10; exit}')"
    resolved_fpr="$(printf '%s' "${resolved_fpr}" | tr '[:lower:]' '[:upper:]' | tr -cd '0-9A-F')"
    if [[ ${#resolved_fpr} -eq 40 ]]; then
      export ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS_EXPECTED="${resolved_fpr}"
      echo "[pre-push] local expected-pin bootstrap enabled (ZT_PREPUSH_AUTO_EXPECTED_PIN_BOOTSTRAP=1)"
      echo "[pre-push] exported ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS_EXPECTED from ROOT_PUBKEY.asc"
    else
      echo "[pre-push] WARN could not resolve valid ROOT_PUBKEY fingerprint for auto bootstrap"
    fi
  fi
  bash ./scripts/ci/check-zt-setup-json-actual-gate.sh
fi

echo "[15/15] git status summary (manual review before commit/push)"
git status --short

echo
echo "[OK] Pre-push readiness checks completed."
echo "Review git diff / git status, then commit and push."
