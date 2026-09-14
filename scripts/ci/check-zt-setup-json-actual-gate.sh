#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tools_dir="${repo_root}/tools/secure-pack"

bootstrap_local_sor_key_b64() {
  local scope="${1:-actual}"
  python3 - "${scope}" <<'PY'
import base64
import hashlib
import sys

scope = (sys.argv[1] if len(sys.argv) > 1 else "actual").strip() or "actual"
seed = ("zt-local-sor-gate-key:" + scope).encode("utf-8")
print(base64.b64encode(hashlib.sha256(seed).digest()).decode("ascii"))
PY
}

required_files=(
  "${tools_dir}/tools.lock"
  "${tools_dir}/tools.lock.sig"
  "${tools_dir}/ROOT_PUBKEY.asc"
)

normalize_fpr() {
  printf '%s' "${1:-}" | tr '[:lower:]' '[:upper:]' | tr -cd '0-9A-F'
}

normalize_signer_pins() {
  local raw token normalized
  raw="$(printf '%s' "${1:-}" | tr ',;\n\r\t' '      ')"
  local -a out=()
  local seen=""
  for token in ${raw}; do
    normalized="$(normalize_fpr "${token}")"
    if [[ -z "${normalized}" ]]; then
      continue
    fi
    if [[ ${#normalized} -ne 40 && ${#normalized} -ne 64 ]]; then
      echo "invalid signer fingerprint length (want 40 or 64 hex): ${token}" >&2
      return 1
    fi
    if [[ ",${seen}," == *",${normalized},"* ]]; then
      continue
    fi
    out+=("${normalized}")
    seen+="${normalized},"
  done
  if [[ ${#out[@]} -eq 0 ]]; then
    return 1
  fi
  local IFS=,
  printf '%s' "${out[*]}"
}

resolve_signer_pins_from_allowlist() {
  local allowlist_path="${repo_root}/tools/secure-pack/SIGNERS_ALLOWLIST.txt"
  if [[ ! -f "${allowlist_path}" ]]; then
    return 1
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

resolve_root_fpr_from_key() {
  gpg --show-keys --with-colons "${tools_dir}/ROOT_PUBKEY.asc" | awk -F: '/^fpr:/ {print $10; exit}'
}

contains_fpr() {
  local needle normalized
  needle="$(normalize_fpr "${1:-}")"
  if [[ -z "${needle}" ]]; then
    return 1
  fi
  local raw="${2:-}"
  raw="$(printf '%s' "${raw}" | tr ',\n\r\t' '    ')"
  for token in ${raw}; do
    normalized="$(normalize_fpr "${token}")"
    if [[ "${normalized}" == "${needle}" ]]; then
      return 0
    fi
  done
  return 1
}

missing=()
for f in "${required_files[@]}"; do
  if [[ ! -f "${f}" ]]; then
    missing+=("$(basename "${f}")")
  fi
done

if [[ ${#missing[@]} -gt 0 ]]; then
  echo "zt setup --json actual repo gate skipped: missing supply-chain files in tools/secure-pack (${missing[*]})"
  echo "gate_ok=skipped"
  exit 0
fi

if [[ -z "${ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS:-}" ]]; then
  expected_pins="${ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS_EXPECTED:-}"
  if [[ -n "${expected_pins}" ]]; then
    if ! command -v gpg >/dev/null 2>&1; then
      echo "zt setup --json actual repo gate failed: gpg is required to resolve ROOT_PUBKEY.asc fingerprint for expected-pin bootstrap" >&2
      echo "gate_ok=false" >&2
      exit 1
    fi
    resolved_fpr="$(resolve_root_fpr_from_key)"
    if [[ -z "${resolved_fpr}" ]]; then
      echo "zt setup --json actual repo gate failed: could not resolve fingerprint from ROOT_PUBKEY.asc" >&2
      echo "gate_ok=false" >&2
      exit 1
    fi
    if ! contains_fpr "${resolved_fpr}" "${expected_pins}"; then
      echo "zt setup --json actual repo gate failed: ROOT_PUBKEY.asc fingerprint does not match ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS_EXPECTED" >&2
      echo "resolved_fingerprint=$(normalize_fpr "${resolved_fpr}")" >&2
      echo "expected_pins=${expected_pins}" >&2
      echo "gate_ok=false" >&2
      exit 1
    fi
    export ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS="${expected_pins}"
    echo "[actual-gate] pin bootstrap source=ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS_EXPECTED (matched ROOT_PUBKEY.asc)"
  elif [[ "${ZT_SECURE_PACK_ALLOW_LOCAL_PIN_BOOTSTRAP:-0}" == "1" ]]; then
    if ! command -v gpg >/dev/null 2>&1; then
      echo "zt setup --json actual repo gate failed: gpg is required when ZT_SECURE_PACK_ALLOW_LOCAL_PIN_BOOTSTRAP=1" >&2
      echo "gate_ok=false" >&2
      exit 1
    fi
    resolved_fpr="$(resolve_root_fpr_from_key)"
    if [[ -z "${resolved_fpr}" ]]; then
      echo "zt setup --json actual repo gate failed: could not resolve fingerprint from ROOT_PUBKEY.asc" >&2
      echo "gate_ok=false" >&2
      exit 1
    fi
    export ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS="$(normalize_fpr "${resolved_fpr}")"
    echo "[actual-gate] WARN local pin bootstrap enabled (ZT_SECURE_PACK_ALLOW_LOCAL_PIN_BOOTSTRAP=1). Prefer expected-pin bootstrap for zero-trust CI."
  else
    echo "zt setup --json actual repo gate failed: ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS is required when tools/secure-pack supply-chain files exist" >&2
    echo "Hint: set ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS_EXPECTED in CI and let this gate verify+bootstrap it, or export ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS directly." >&2
    echo "gate_ok=false" >&2
    exit 1
  fi
fi

if [[ -z "${ZT_SECURE_PACK_SIGNER_FINGERPRINTS:-}" ]]; then
  expected_signer_pins="${ZT_SECURE_PACK_SIGNER_FINGERPRINTS_EXPECTED:-}"
  if [[ -n "${expected_signer_pins}" ]]; then
    normalized_signer_pins="$(normalize_signer_pins "${expected_signer_pins}")" || {
      echo "zt setup --json actual repo gate failed: invalid ZT_SECURE_PACK_SIGNER_FINGERPRINTS_EXPECTED format" >&2
      echo "gate_ok=false" >&2
      exit 1
    }
    export ZT_SECURE_PACK_SIGNER_FINGERPRINTS="${normalized_signer_pins}"
    echo "[actual-gate] signer pin bootstrap source=ZT_SECURE_PACK_SIGNER_FINGERPRINTS_EXPECTED"
  elif [[ "${ZT_SECURE_PACK_ALLOW_LOCAL_SIGNER_PIN_BOOTSTRAP:-0}" == "1" ]]; then
    resolved_signer_raw="$(resolve_signer_pins_from_allowlist || true)"
    if [[ -z "${resolved_signer_raw}" ]]; then
      echo "zt setup --json actual repo gate failed: could not resolve signer pins from tools/secure-pack/SIGNERS_ALLOWLIST.txt" >&2
      echo "gate_ok=false" >&2
      exit 1
    fi
    normalized_signer_pins="$(normalize_signer_pins "${resolved_signer_raw}")" || {
      echo "zt setup --json actual repo gate failed: invalid signer pins in local allowlist" >&2
      echo "gate_ok=false" >&2
      exit 1
    }
    export ZT_SECURE_PACK_SIGNER_FINGERPRINTS="${normalized_signer_pins}"
    echo "[actual-gate] WARN local signer pin bootstrap enabled (ZT_SECURE_PACK_ALLOW_LOCAL_SIGNER_PIN_BOOTSTRAP=1). Prefer expected signer pin bootstrap for zero-trust CI."
  fi
fi

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "${tmp_dir}"
}
trap cleanup EXIT

zt_bin="${tmp_dir}/zt-bin"
json_out="${tmp_dir}/zt-setup.json"
zt_bin_override="${ZT_BIN:-}"

if [[ -n "${zt_bin_override}" ]]; then
  if [[ ! -x "${zt_bin_override}" ]]; then
    echo "ZT_BIN is set but not executable: ${zt_bin_override}" >&2
    echo "gate_ok=false" >&2
    exit 1
  fi
  zt_bin="${zt_bin_override}"
else
  (
    cd "${repo_root}"
    go build -o "${zt_bin}" ./gateway/zt
  )
fi

(
  cd "${repo_root}"
  # Local SoR is scoped to gate-only temporary DB so setup gate does not depend on
  # existing workspace DB state or external shell env key provisioning.
  local_sor_key="${ZT_LOCAL_SOR_MASTER_KEY_B64:-}"
  if [[ -z "${local_sor_key}" && -z "${ZT_LOCAL_SOR_ALLOW_PLAINTEXT_DEV:-}" ]]; then
    local_sor_key="$(bootstrap_local_sor_key_b64 "actual")"
  fi
  local_sor_db_path="${tmp_dir}/local-sor-gate.db"
  export ZT_LOCAL_SOR_MASTER_KEY_B64="${local_sor_key}"
  export ZT_LOCAL_SOR_DB_PATH="${local_sor_db_path}"
  "${zt_bin}" setup --json > "${json_out}" || true
)

if [[ ! -s "${json_out}" ]]; then
  echo "zt setup --json actual repo gate failed: no JSON output captured" >&2
  echo "gate_ok=false" >&2
  exit 1
fi

python3 - "${json_out}" <<'PY'
import json, sys
import os

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)

checks = {c.get("name"): c.get("status") for c in data.get("checks", [])}
required = [
    "secure_pack_supply_chain_files",
    "secure_pack_root_pubkey_fingerprint",
    "secure_pack_tools_lock_signature",
]
bad = [(name, checks.get(name)) for name in required if checks.get(name) != "ok"]
resolved = data.get("resolved") or {}
pin_match_count = int(resolved.get("pin_match_count") or 0)
actual_fpr = resolved.get("actual_root_fingerprint")
pin_source = resolved.get("pin_source")
profile = resolved.get("profile")

gate_errors = []
if bad:
    gate_errors.append(
        "required checks not ok: " + ", ".join(f"{k}={v}" for k, v in bad)
    )
if pin_match_count < 1:
    gate_errors.append(
        "resolved.pin_match_count < 1 "
        f"(pin_match_count={pin_match_count}, actual_root_fingerprint={actual_fpr}, pin_source={pin_source})"
    )
if profile != "internal":
    gate_errors.append(f"resolved.profile={profile!r} (want 'internal')")

strict = os.getenv("ZT_ACTUAL_GATE_STRICT", "").strip().lower() in {"1", "true", "yes", "on"}
if strict:
    if data.get("ok") is not True:
        gate_errors.append(
            f"strict mode: setup_ok={data.get('ok')} error_code={data.get('error_code')}"
        )
    strict_checks = [
        "secure_pack_root_pubkey_fingerprint",
        "team_boundary_signer_pin_consistency",
    ]
    for name in strict_checks:
        status = checks.get(name)
        if status != "ok":
            gate_errors.append(f"strict mode: {name}={status} (want ok)")

if gate_errors:
    print("zt setup --json actual repo gate FAILED")
    print("gate_ok=false")
    for err in gate_errors:
        print(f"gate_error={err}")
    print(
        f"setup_ok={data.get('ok')} error_code={data.get('error_code')} (informational)"
    )
    print(f"actual_root_fingerprint={actual_fpr}")
    print(f"pin_source={pin_source}")
    print(f"pin_match_count={pin_match_count}")
    print(f"profile={profile}")
    raise SystemExit(1)

print("zt setup --json actual repo gate OK")
print("gate_ok=true")
print(f"setup_ok={data.get('ok')} error_code={data.get('error_code')} (informational)")
print(f"actual_root_fingerprint={actual_fpr}")
print(f"pin_source={pin_source}")
print(f"pin_match_count={pin_match_count}")
print(f"profile={profile}")
PY
