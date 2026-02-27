#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

has_rg=0
if command -v rg >/dev/null 2>&1; then
  has_rg=1
fi

search_pattern() {
  local pattern="$1"
  shift
  if [[ "${has_rg}" -eq 1 ]]; then
    rg -n "${pattern}" "$@"
    return $?
  fi
  grep -n -E "${pattern}" "$@"
}

echo "[v1.3-operations-gap-closure-gate] running degraded-scan and file-type contracts"
go test ./gateway/zt -count=1 -run 'ParseSendArgs_AllowDegradedScan|EnforceFileTypeConsistency_(AllowsExtendedTextExtensions|BlocksExeRenamedYAML)'

echo "[v1.3-operations-gap-closure-gate] running secure-pack send config flag contracts"
go test ./tools/secure-pack/cmd/secure-pack -count=1 -run 'BuildSendConfig|ResolveSendPath'

echo "[v1.3-operations-gap-closure-gate] checking operational docs for legacy artifact.zp command usage"
legacy_targets=(
  "README.md"
  "docs/OPERATIONS.md"
  "docs/SECURE_PACK_SMOKETEST.md"
  "docs/SECURE_PACK_KEY_ROTATION_RUNBOOK.md"
  "docs/V1_SALES_OPERATIONS_PACK.md"
  "tools/secure-pack/README.md"
  "tools/secure-pack/README_EN.md"
)
legacy_command_pattern='(zt verify.*(\./artifact\.zp|<artifact\.zp>)|secure-pack (receive|verify).*(\./artifact\.zp|<artifact\.zp>))'
if search_pattern "${legacy_command_pattern}" "${legacy_targets[@]}" >/dev/null; then
  echo "found legacy artifact.zp command usage in operational docs" >&2
  search_pattern "${legacy_command_pattern}" "${legacy_targets[@]}" >&2
  exit 1
fi

echo "[v1.3-operations-gap-closure-gate] checking root/signer pin bootstrap standardization references"
search_pattern 'ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS_EXPECTED|bootstrap-ci-root-pin-expected.sh|bootstrap-ci-trust-pins.sh' README.md docs/OPERATIONS.md >/dev/null
search_pattern 'ZT_SECURE_PACK_SIGNER_FINGERPRINTS_EXPECTED|bootstrap-ci-signer-pin-expected.sh|bootstrap-ci-trust-pins.sh' README.md docs/OPERATIONS.md >/dev/null

echo "[v1.3-operations-gap-closure-gate] ok"
