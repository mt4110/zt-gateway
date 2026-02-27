#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fixture_dir="${repo_root}/testdata/secure-pack-supplychain"
tmp_repo="$(mktemp -d)"

bootstrap_local_sor_key_b64() {
  local scope="${1:-fixture}"
  python3 - "${scope}" <<'PY'
import base64
import hashlib
import sys

scope = (sys.argv[1] if len(sys.argv) > 1 else "fixture").strip() or "fixture"
seed = ("zt-local-sor-gate-key:" + scope).encode("utf-8")
print(base64.b64encode(hashlib.sha256(seed).digest()).decode("ascii"))
PY
}

cleanup() {
  rm -rf "${tmp_repo}"
}
trap cleanup EXIT

mkdir -p "${tmp_repo}/policy" "${tmp_repo}/tools/secure-pack" "${tmp_repo}/gateway/zt"
cp "${fixture_dir}/tools.lock" "${tmp_repo}/tools/secure-pack/tools.lock"
cp "${fixture_dir}/tools.lock.sig" "${tmp_repo}/tools/secure-pack/tools.lock.sig"
cp "${fixture_dir}/ROOT_PUBKEY.asc" "${tmp_repo}/tools/secure-pack/ROOT_PUBKEY.asc"

cat > "${tmp_repo}/policy/policy.toml" <<'EOF'
[policy]
name = "ci-fixture"
EOF

cat > "${tmp_repo}/policy/extension_policy.toml" <<'EOF'
scan_only_extensions = [".txt"]
scan_rebuild_extensions = [".jpg", ".jpeg", ".png"]
deny_extensions = [".exe", ".zip", ".7z", ".rar", ".tar", ".gz", ".tgz"]
max_size_mb = 50
EOF

cat > "${tmp_repo}/policy/scan_policy.toml" <<'EOF'
required_scanners = ["ClamAV"]
require_clamav_db = true
EOF

fpr="$(tr -d '\r\n' < "${fixture_dir}/FINGERPRINT.txt")"
json_out="${tmp_repo}/zt-setup.json"
zt_bin="${tmp_repo}/zt-bin"
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

local_sor_key="${ZT_LOCAL_SOR_MASTER_KEY_B64:-}"
if [[ -z "${local_sor_key}" && -z "${ZT_LOCAL_SOR_ALLOW_PLAINTEXT_DEV:-}" ]]; then
  local_sor_key="$(bootstrap_local_sor_key_b64 "fixture")"
fi
local_sor_db_path="${tmp_repo}/.zt-spool/local-sor-gate.db"

(
  cd "${tmp_repo}"
  # Fixture gate is policy/supply-chain focused; provide signer pins explicitly so
  # setup's fail-closed verify-pin readiness check remains green in CI.
  # Local SoR is scoped to gate-only temporary DB to avoid environment coupling.
  ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS="${fpr}" \
  ZT_SECURE_PACK_SIGNER_FINGERPRINTS="${fpr}" \
  ZT_LOCAL_SOR_MASTER_KEY_B64="${local_sor_key}" \
  ZT_LOCAL_SOR_DB_PATH="${local_sor_db_path}" \
  "${zt_bin}" setup --json > "${json_out}"
)

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
profile = resolved.get("profile")
if not data.get("ok"):
    raise SystemExit(f"zt setup fixture gate failed: ok=false error_code={data.get('error_code')}")
if bad:
    raise SystemExit("zt setup fixture gate failed checks: " + ", ".join(f"{k}={v}" for k, v in bad))
if profile != "internal":
    raise SystemExit(f"zt setup fixture gate failed: resolved.profile={profile!r} (want 'internal')")
print("zt setup --json fixture gate OK")
PY
