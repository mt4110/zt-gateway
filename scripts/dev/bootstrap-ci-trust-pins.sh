#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

root_expected_pins=""
signer_expected_pins=""
root_trust_local=0
signer_trust_local=0

usage() {
  cat <<'USAGE'
Usage:
  bootstrap-ci-trust-pins.sh [options]

Options:
  --root-expected-pins "<OLD,NEW>"      Set ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS_EXPECTED
  --signer-expected-pins "<OLD,NEW>"    Set ZT_SECURE_PACK_SIGNER_FINGERPRINTS_EXPECTED
  --root-trust-local-key                One-trust mode for root key (resolve from ROOT_PUBKEY.asc)
  --signer-trust-local-allowlist        One-trust mode for signer pins (resolve from SIGNERS_ALLOWLIST.txt)
  -h, --help                            Show this help

At least one root option and one signer option are required.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --root-expected-pins)
      root_expected_pins="${2:-}"
      shift 2
      ;;
    --signer-expected-pins)
      signer_expected_pins="${2:-}"
      shift 2
      ;;
    --root-trust-local-key)
      root_trust_local=1
      shift
      ;;
    --signer-trust-local-allowlist)
      signer_trust_local=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "${root_expected_pins}" && ${root_trust_local} -eq 0 ]]; then
  echo "root pin mode is required (--root-expected-pins or --root-trust-local-key)" >&2
  exit 2
fi
if [[ -z "${signer_expected_pins}" && ${signer_trust_local} -eq 0 ]]; then
  echo "signer pin mode is required (--signer-expected-pins or --signer-trust-local-allowlist)" >&2
  exit 2
fi

root_cmd=(bash "${repo_root}/scripts/dev/bootstrap-ci-root-pin-expected.sh")
if [[ -n "${root_expected_pins}" ]]; then
  root_cmd+=(--expected-pins "${root_expected_pins}")
else
  root_cmd+=(--trust-local-root-key)
fi

signer_cmd=(bash "${repo_root}/scripts/dev/bootstrap-ci-signer-pin-expected.sh")
if [[ -n "${signer_expected_pins}" ]]; then
  signer_cmd+=(--expected-pins "${signer_expected_pins}")
else
  signer_cmd+=(--trust-local-allowlist)
fi

echo "[trust-pins] bootstrapping root expected pins"
"${root_cmd[@]}"
echo "[trust-pins] bootstrapping signer expected pins"
"${signer_cmd[@]}"
echo "[trust-pins] done"
