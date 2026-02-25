#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/dev/run-secure-pack-smoketest.sh [--client <name>] [--diagnose-only]

Diagnose secure-pack tools.lock pin mismatch (gpg/tar) before running local smoke.
If pins match, runs:
  ./test/integration.sh --client <name>

Options:
  --client <name>    Client name passed to integration.sh (default: local-smoketest)
  --diagnose-only    Only print pin comparison and exit (3 on mismatch)
  -h, --help         Show this help
EOF
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TOOLS_LOCK="${REPO_ROOT}/tools/secure-pack/tools.lock"

CLIENT_NAME="local-smoketest"
DIAGNOSE_ONLY="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --client)
      CLIENT_NAME="${2:-}"
      if [[ -z "${CLIENT_NAME}" ]]; then
        echo "[FAIL] --client requires a value" >&2
        exit 2
      fi
      shift 2
      ;;
    --diagnose-only)
      DIAGNOSE_ONLY="1"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[FAIL] Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ ! -f "${TOOLS_LOCK}" ]]; then
  echo "[FAIL] tools.lock not found: ${TOOLS_LOCK}" >&2
  exit 1
fi

for cmd in awk head tr; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "[FAIL] Required command not found: ${cmd}" >&2
    exit 1
  fi
done

if ! command -v gpg >/dev/null 2>&1; then
  echo "[FAIL] gpg is required but not found in PATH" >&2
  exit 1
fi

if ! command -v tar >/dev/null 2>&1; then
  echo "[FAIL] tar is required but not found in PATH" >&2
  exit 1
fi

sha256_file() {
  local path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${path}" | awk '{print $1}'
    return
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${path}" | awk '{print $1}'
    return
  fi
  echo "[FAIL] sha256sum or shasum is required" >&2
  exit 1
}

tools_lock_value() {
  local key="$1"
  awk -F= -v want="${key}" '
    $1 == want {
      v = substr($0, index($0, "=") + 1)
      gsub(/^"/, "", v)
      gsub(/"$/, "", v)
      print v
      exit
    }
  ' "${TOOLS_LOCK}"
}

expected_gpg_sha="$(tools_lock_value gpg_sha256)"
expected_gpg_ver="$(tools_lock_value gpg_version)"
expected_tar_sha="$(tools_lock_value tar_sha256)"
expected_tar_ver="$(tools_lock_value tar_version)"

for v in expected_gpg_sha expected_gpg_ver expected_tar_sha expected_tar_ver; do
  if [[ -z "${!v:-}" ]]; then
    echo "[FAIL] Failed to parse ${v} from ${TOOLS_LOCK}" >&2
    exit 1
  fi
done

gpg_path="$(command -v gpg)"
tar_path="$(command -v tar)"
actual_gpg_sha="$(sha256_file "${gpg_path}")"
actual_tar_sha="$(sha256_file "${tar_path}")"
actual_gpg_ver="$(gpg --version | head -n 1 | tr -d '\r')"
actual_tar_ver="$(tar --version | head -n 1 | tr -d '\r')"

print_cmp() {
  local name="$1"
  local field="$2"
  local expected="$3"
  local actual="$4"
  if [[ "${expected}" == "${actual}" ]]; then
    echo "[OK] ${name} ${field} matched"
  else
    echo "[MISMATCH] ${name} ${field}"
    echo "  expected: ${expected}"
    echo "  actual:   ${actual}"
    return 1
  fi
}

echo "[INFO] tools.lock: ${TOOLS_LOCK}"
echo "[INFO] gpg path:   ${gpg_path}"
echo "[INFO] tar path:   ${tar_path}"

mismatch=0
print_cmp "gpg" "version" "${expected_gpg_ver}" "${actual_gpg_ver}" || mismatch=1
print_cmp "gpg" "sha256"  "${expected_gpg_sha}" "${actual_gpg_sha}" || mismatch=1
print_cmp "tar" "version" "${expected_tar_ver}" "${actual_tar_ver}" || mismatch=1
print_cmp "tar" "sha256"  "${expected_tar_sha}" "${actual_tar_sha}" || mismatch=1

if [[ "${mismatch}" -ne 0 ]]; then
  cat <<'EOF'
[FAIL] secure-pack tools.lock pin mismatch detected.

Standard policy:
  - Treat tools/secure-pack/tools.lock as CI canonical
  - Do not relax pin verification
  - Prefer running local smoke in Ubuntu/Linux CI-equivalent environment

References:
  - docs/SECURE_PACK_LOCAL_EXECUTION_POLICY.md
  - docs/SECURE_PACK_SMOKETEST.md
  - docs/OPERATIONS.md (Linux tools.lock regeneration procedure)
EOF
  exit 3
fi

echo "[OK] tools.lock pin check matched current PATH tools (gpg/tar)"

if [[ "${DIAGNOSE_ONLY}" = "1" ]]; then
  exit 0
fi

if ! command -v nix >/dev/null 2>&1; then
  echo "[FAIL] nix is required to run ./test/integration.sh (it calls 'nix run .#zt ...')." >&2
  exit 1
fi

cd "${REPO_ROOT}"
echo "[RUN] ./test/integration.sh --client ${CLIENT_NAME}"
exec ./test/integration.sh --client "${CLIENT_NAME}"

