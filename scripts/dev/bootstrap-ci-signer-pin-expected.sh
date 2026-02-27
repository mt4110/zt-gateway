#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
allowlist_path="${repo_root}/tools/secure-pack/SIGNERS_ALLOWLIST.txt"

var_name="ZT_SECURE_PACK_SIGNER_FINGERPRINTS_EXPECTED"
repo=""
expected_pins_raw=""
trust_local_allowlist=0
dry_run=0
print_env=0

usage() {
  cat <<USAGE
Usage: $(basename "$0") [options]

Bootstrap/update GitHub Actions repository variable for secure-pack signer fingerprint pins.

Options:
  --repo <owner/repo>            Target repository (default: detect from git remote origin)
  --var-name <name>              Variable name (default: ${var_name})
  --expected-pins <FPR[,FPR...]> Approved signer pin list (recommended)
  --trust-local-allowlist        One-trust mode: resolve from tools/secure-pack/SIGNERS_ALLOWLIST.txt
  --print-env                    Print shell export for local use and exit (no gh required)
  --dry-run                      Print resolved values without updating GitHub variable
  -h, --help                     Show help

Examples:
  $(basename "$0") --expected-pins "FPR1,FPR2"
  $(basename "$0") --trust-local-allowlist
USAGE
}

normalize_fpr() {
  printf '%s' "${1:-}" | tr '[:lower:]' '[:upper:]' | tr -cd '0-9A-F'
}

normalize_pin_list() {
  local raw normalized token
  raw="$(printf '%s' "${1:-}" | tr ',;\n\r\t' '      ')"
  local -a out=()
  local seen=""
  for token in ${raw}; do
    normalized="$(normalize_fpr "${token}")"
    if [[ -z "${normalized}" ]]; then
      continue
    fi
    if [[ ${#normalized} -ne 40 && ${#normalized} -ne 64 ]]; then
      echo "invalid fingerprint length (want 40 or 64 hex): ${token}" >&2
      exit 1
    fi
    if [[ ",${seen}," == *",${normalized},"* ]]; then
      continue
    fi
    out+=("${normalized}")
    seen+="${normalized},"
  done
  if [[ ${#out[@]} -eq 0 ]]; then
    echo "no valid signer fingerprint pins found" >&2
    exit 1
  fi
  local IFS=,
  printf '%s' "${out[*]}"
}

resolve_allowlist_pins() {
  if [[ ! -f "${allowlist_path}" ]]; then
    echo "missing signer allowlist: ${allowlist_path}" >&2
    exit 1
  fi
  awk '
    {
      line=$0
      sub(/#.*/, "", line)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
      if (line != "") print line
    }
  ' "${allowlist_path}" | tr '\n' ','
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
    --trust-local-allowlist)
      trust_local_allowlist=1
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

if [[ -n "${expected_pins_raw}" ]]; then
  expected_pins="$(normalize_pin_list "${expected_pins_raw}")"
elif [[ ${trust_local_allowlist} -eq 1 ]]; then
  expected_pins="$(normalize_pin_list "$(resolve_allowlist_pins)")"
else
  echo "either --expected-pins (recommended) or --trust-local-allowlist is required" >&2
  exit 1
fi

if [[ ${print_env} -eq 1 ]]; then
  echo "export ZT_SECURE_PACK_SIGNER_FINGERPRINTS_EXPECTED=\"${expected_pins}\""
  exit 0
fi

if [[ -z "${repo}" ]]; then
  repo="$(detect_repo_from_origin || true)"
fi

if [[ ${dry_run} -eq 1 ]]; then
  echo "[dry-run] repo=${repo}"
  echo "[dry-run] var_name=${var_name}"
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
if [[ ${trust_local_allowlist} -eq 1 ]]; then
  echo "[WARN] one-trust mode used (--trust-local-allowlist)."
  echo "       For stricter operation, use --expected-pins from an approved out-of-band source."
fi
echo "Next: run actual gate with strict mode"
echo "  ZT_ACTUAL_GATE_STRICT=1 bash ./scripts/ci/check-zt-setup-json-actual-gate.sh"

