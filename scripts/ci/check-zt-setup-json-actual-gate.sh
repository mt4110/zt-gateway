#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tools_dir="${repo_root}/tools/secure-pack"

required_files=(
  "${tools_dir}/tools.lock"
  "${tools_dir}/tools.lock.sig"
  "${tools_dir}/ROOT_PUBKEY.asc"
)

missing=()
for f in "${required_files[@]}"; do
  if [[ ! -f "${f}" ]]; then
    missing+=("$(basename "${f}")")
  fi
done

if [[ ${#missing[@]} -gt 0 ]]; then
  echo "zt setup --json actual repo gate skipped: missing supply-chain files in tools/secure-pack (${missing[*]})"
  exit 0
fi

if [[ -z "${ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS:-}" ]]; then
  echo "zt setup --json actual repo gate failed: ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS is required when tools/secure-pack supply-chain files exist" >&2
  exit 1
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
  "${zt_bin}" setup --json > "${json_out}" || true
)

if [[ ! -s "${json_out}" ]]; then
  echo "zt setup --json actual repo gate failed: no JSON output captured" >&2
  exit 1
fi

python3 - "${json_out}" <<'PY'
import json, sys

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

if bad:
    raise SystemExit("zt setup actual repo gate failed checks: " + ", ".join(f"{k}={v}" for k, v in bad))
if pin_match_count < 1:
    raise SystemExit(
        "zt setup actual repo gate failed: resolved.pin_match_count < 1 "
        f"(pin_match_count={pin_match_count}, actual_root_fingerprint={actual_fpr}, pin_source={pin_source})"
    )
if profile != "internal":
    raise SystemExit(f"zt setup actual repo gate failed: resolved.profile={profile!r} (want 'internal')")

print("zt setup --json actual repo gate OK")
print(f"setup_ok={data.get('ok')} error_code={data.get('error_code')}")
print(f"actual_root_fingerprint={actual_fpr}")
print(f"pin_source={pin_source}")
print(f"pin_match_count={pin_match_count}")
print(f"profile={profile}")
PY
