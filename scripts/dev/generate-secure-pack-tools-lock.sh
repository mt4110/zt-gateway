#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/dev/generate-secure-pack-tools-lock.sh --root-key <gpg_uid_or_fpr> [--tools-dir <dir>]

Generate and sign secure-pack supply-chain artifacts on Linux/Ubuntu:
  - tools.lock
  - tools.lock.sig
  - ROOT_PUBKEY.asc

Requirements:
  - Linux (Ubuntu runner/host recommended)
  - gpg
  - tar
  - sha256sum
  - GPG private key for the root signer imported in GNUPGHOME

Options:
  --root-key <ref>   GPG user ID / email / fingerprint used for export and signing (required)
  --tools-dir <dir>  Output directory (default: tools/secure-pack)
  -h, --help         Show this help
EOF
}

root_key_ref=""
tools_dir="tools/secure-pack"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --root-key)
      root_key_ref="${2:-}"
      shift 2
      ;;
    --tools-dir)
      tools_dir="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "${root_key_ref}" ]]; then
  echo "--root-key is required" >&2
  usage >&2
  exit 1
fi

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "This script is intended to be run on Linux/Ubuntu to generate CI-compatible tar pins." >&2
  echo "Current OS: $(uname -s)" >&2
  exit 1
fi

for cmd in gpg tar sha256sum awk head tr; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "Required command not found: ${cmd}" >&2
    exit 1
  fi
done

mkdir -p "${tools_dir}"

gpg_path="$(command -v gpg)"
tar_path="$(command -v tar)"

gpg_sha="$(sha256sum "${gpg_path}" | awk '{print $1}')"
tar_sha="$(sha256sum "${tar_path}" | awk '{print $1}')"
gpg_ver="$(gpg --version | head -n 1 | tr -d '\r')"
tar_ver="$(tar --version | head -n 1 | tr -d '\r')"

tmp_lock="$(mktemp)"
cleanup() {
  rm -f "${tmp_lock}"
}
trap cleanup EXIT

cat > "${tmp_lock}" <<EOF
gpg_sha256="${gpg_sha}"
gpg_version="${gpg_ver}"
tar_sha256="${tar_sha}"
tar_version="${tar_ver}"
EOF

mv "${tmp_lock}" "${tools_dir}/tools.lock"
gpg --batch --yes --armor --export "${root_key_ref}" > "${tools_dir}/ROOT_PUBKEY.asc"
gpg --batch --yes --armor --detach-sign -u "${root_key_ref}" -o "${tools_dir}/tools.lock.sig" "${tools_dir}/tools.lock"

root_fpr="$(gpg --with-colons --list-keys "${root_key_ref}" | awk -F: '/^fpr:/ {print $10; exit}')"
if [[ -z "${root_fpr}" ]]; then
  echo "Failed to resolve root key fingerprint for: ${root_key_ref}" >&2
  exit 1
fi

echo "[OK] Generated Linux/Ubuntu secure-pack supply-chain artifacts in ${tools_dir}"
echo "  tools.lock      ($(wc -c < "${tools_dir}/tools.lock" | tr -d ' ') bytes)"
echo "  tools.lock.sig  ($(wc -c < "${tools_dir}/tools.lock.sig" | tr -d ' ') bytes)"
echo "  ROOT_PUBKEY.asc ($(wc -c < "${tools_dir}/ROOT_PUBKEY.asc" | tr -d ' ') bytes)"
echo "  root_fingerprint=${root_fpr}"
echo "  gpg_path=${gpg_path}"
echo "  tar_path=${tar_path}"
echo
echo "Next:"
echo "  1. Update GitHub Actions Variable (recommended):"
echo "     bash ./scripts/dev/bootstrap-ci-root-pin-expected.sh --expected-pins \"${root_fpr}\""
echo "  2. Run: bash ./scripts/ci/check-zt-setup-json-actual-gate.sh"
echo "  3. Run: bash ./scripts/ci/check-pre-push-readiness.sh"
