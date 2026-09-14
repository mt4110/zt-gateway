#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
root_pubkey_path="${repo_root}/tools/secure-pack/ROOT_PUBKEY.asc"

var_name="ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS_EXPECTED"
repo=""
expected_pins_raw=""
trust_local_root_key=0
dry_run=0
print_env=0

usage() {
  cat <<USAGE
Usage: $(basename "$0") [options]

Bootstrap/update GitHub Actions repository variable for secure-pack root fingerprint pins.

Options:
  --repo <owner/repo>            Target repository (default: detect from git remote origin)
  --var-name <name>              Variable name (default: ${var_name})
  --expected-pins <FPR[,FPR...]> Approved pin list (recommended; can include old+new during rotation)
  --trust-local-root-key         One-trust mode: use ROOT_PUBKEY.asc fingerprint directly
  --print-env                    Print shell export for local use and exit (no gh required)
  --dry-run                      Print resolved values without updating GitHub variable
  -h, --help                     Show help

Examples:
  # Zero-trust寄り: 事前に承認済み pin を明示して登録
  $(basename "$0") --expected-pins "OLD_FPR_40HEX,NEW_FPR_40HEX"

  # One-trust: ローカルの ROOT_PUBKEY.asc をそのまま expected pin として登録
  $(basename "$0") --trust-local-root-key
USAGE
}

normalize_fpr() {
  printf '%s' "${1:-}" | tr '[:lower:]' '[:upper:]' | tr -cd '0-9A-F'
}

normalize_pin_list() {
  local raw normalized token
  raw="$(printf '%s' "${1:-}" | tr ',\n\r\t' '    ')"
  local -a out=()
  local seen=""
  for token in ${raw}; do
    normalized="$(normalize_fpr "${token}")"
    if [[ -z "${normalized}" ]]; then
      continue
    fi
    if [[ ${#normalized} -ne 40 ]]; then
      echo "invalid fingerprint length (want 40 hex): ${token}" >&2
      exit 1
    fi
    if [[ ",${seen}," == *",${normalized},"* ]]; then
      continue
    fi
    out+=("${normalized}")
    seen+="${normalized},"
  done
  if [[ ${#out[@]} -eq 0 ]]; then
    echo "no valid fingerprint pins found" >&2
    exit 1
  fi
  local IFS=,
  printf '%s' "${out[*]}"
}

contains_fpr() {
  local needle list token
  needle="$(normalize_fpr "${1:-}")"
  list="$(normalize_pin_list "${2:-}")"
  IFS=',' read -r -a pins <<< "${list}"
  for token in "${pins[@]}"; do
    if [[ "${token}" == "${needle}" ]]; then
      return 0
    fi
  done
  return 1
}

detect_repo_from_origin() {
  local origin
  origin="$(git -C "${repo_root}" config --get remote.origin.url || true)"
  if [[ -z "${origin}" ]]; then
    return 1
  fi
  local parsed
  parsed="$(printf '%s' "${origin}" | sed -E 's#^git@[^:]+:##; s#^https?://[^/]+/##; s#\.git$##')"
  if [[ "${parsed}" != */* ]]; then
    return 1
  fi
  printf '%s' "${parsed}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo)
      repo="${2:-}"
      shift 2
      ;;
    --var-name)
      var_name="${2:-}"
      shift 2
      ;;
    --expected-pins)
      expected_pins_raw="${2:-}"
      shift 2
      ;;
    --trust-local-root-key)
      trust_local_root_key=1
      shift
      ;;
    --dry-run)
      dry_run=1
      shift
      ;;
    --print-env)
      print_env=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ ! -f "${root_pubkey_path}" ]]; then
  echo "missing ROOT_PUBKEY.asc: ${root_pubkey_path}" >&2
  exit 1
fi

if ! command -v gpg >/dev/null 2>&1; then
  echo "gpg is required" >&2
  exit 1
fi

resolved_fpr="$(gpg --show-keys --with-colons "${root_pubkey_path}" | awk -F: '/^fpr:/ {print $10; exit}')"
resolved_fpr="$(normalize_fpr "${resolved_fpr}")"
if [[ ${#resolved_fpr} -ne 40 ]]; then
  echo "failed to resolve valid fingerprint from ${root_pubkey_path}" >&2
  exit 1
fi

if [[ -n "${expected_pins_raw}" ]]; then
  expected_pins="$(normalize_pin_list "${expected_pins_raw}")"
  if ! contains_fpr "${resolved_fpr}" "${expected_pins}"; then
    echo "resolved ROOT_PUBKEY fingerprint is not included in --expected-pins" >&2
    echo "resolved_fingerprint=${resolved_fpr}" >&2
    echo "expected_pins=${expected_pins}" >&2
    exit 1
  fi
elif [[ ${trust_local_root_key} -eq 1 ]]; then
  expected_pins="${resolved_fpr}"
else
  echo "either --expected-pins (recommended) or --trust-local-root-key is required" >&2
  exit 1
fi

if [[ ${print_env} -eq 1 ]]; then
  echo "export ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS_EXPECTED=\"${expected_pins}\""
  exit 0
fi

if [[ -z "${repo}" ]]; then
  repo="$(detect_repo_from_origin || true)"
fi

if [[ ${dry_run} -eq 1 ]]; then
  echo "[dry-run] repo=${repo}"
  echo "[dry-run] var_name=${var_name}"
  echo "[dry-run] resolved_fingerprint=${resolved_fpr}"
  echo "[dry-run] value=${expected_pins}"
  exit 0
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "gh CLI is required" >&2
  exit 1
fi
if [[ -z "${repo}" ]]; then
  repo="$(detect_repo_from_origin || true)"
fi
if [[ -z "${repo}" ]]; then
  echo "could not detect --repo from git remote origin; pass --repo <owner/repo>" >&2
  exit 1
fi

gh variable set "${var_name}" --repo "${repo}" --body "${expected_pins}"

echo "[OK] Updated repo variable"
echo "  repo=${repo}"
echo "  variable=${var_name}"
echo "  value=${expected_pins}"
echo
if [[ ${trust_local_root_key} -eq 1 ]]; then
  echo "[WARN] one-trust mode used (--trust-local-root-key)."
  echo "       For stricter operation, use --expected-pins from an out-of-band approved value."
fi
echo "Next: run CI gate without manual export"
echo "  bash ./scripts/ci/check-zt-setup-json-actual-gate.sh"
