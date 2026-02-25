#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/dev/run-secure-pack-smoketest-ubuntu-docker.sh [--client <name>] [--diagnose-only] [--image <ubuntu-image>] [--platform <docker-platform>]

Run secure-pack local smoketest in Ubuntu/Linux (Docker), aligned with CI-canonical tools.lock pins.

Options:
  --client <name>    Client name (default: local-smoketest)
  --diagnose-only    Run pin diagnosis only
  --image <name>     Docker image (default: ubuntu:24.04)
  --platform <name>  Docker platform (default: linux/amd64; CI-equivalent)
  -h, --help         Show this help
EOF
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

CLIENT_NAME="local-smoketest"
DIAGNOSE_ONLY="0"
IMAGE="ubuntu:24.04"
PLATFORM="linux/amd64"
NIX_STORE_VOLUME="zt_gateway_nix_store"

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
    --image)
      IMAGE="${2:-}"
      if [[ -z "${IMAGE}" ]]; then
        echo "[FAIL] --image requires a value" >&2
        exit 2
      fi
      shift 2
      ;;
    --platform)
      PLATFORM="${2:-}"
      if [[ -z "${PLATFORM}" ]]; then
        echo "[FAIL] --platform requires a value" >&2
        exit 2
      fi
      shift 2
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

if ! command -v docker >/dev/null 2>&1; then
  echo "[FAIL] docker is required but not found in PATH" >&2
  exit 1
fi

docker run --rm \
  --platform "${PLATFORM}" \
  -v "${NIX_STORE_VOLUME}:/nix" \
  -v "${REPO_ROOT}:/src:ro" \
  "${IMAGE}" \
  bash -lc "
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update >/dev/null
apt-get install -y --no-install-recommends \
  ca-certificates \
  gnupg \
  gpg-agent \
  tar \
  nix-bin \
  git \
  rsync \
  file \
  build-essential >/dev/null

if ! getent group nixbld >/dev/null; then
  groupadd -r nixbld
fi
for i in \$(seq 1 10); do
  if ! id -u nixbld\$i >/dev/null 2>&1; then
    useradd -r -g nixbld -G nixbld -d /var/empty -s /usr/sbin/nologin nixbld\$i
  else
    usermod -a -G nixbld nixbld\$i || true
  fi
done

rm -rf /homeless-shelter || true
export HOME=/root
export NIX_CONFIG=\$'experimental-features = nix-command flakes\nsandbox = false\n'

mkdir -p /work
rsync -a /src/ /work/
cd /work

if [[ \"${DIAGNOSE_ONLY}\" = \"1\" ]]; then
  exec bash ./scripts/dev/run-secure-pack-smoketest.sh --diagnose-only
fi

# zt adapter currently executes secure-scan/secure-pack via go run in send flow.
# Ensure a recent Go toolchain is available in PATH inside the container.
exec nix shell nixpkgs#go --command bash ./scripts/dev/run-secure-pack-smoketest.sh --client \"${CLIENT_NAME}\"
"
