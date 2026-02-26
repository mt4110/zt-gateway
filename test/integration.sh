#!/bin/sh
set -eu

echo "=== Starting Integration Tests ==="

usage() {
    cat <<'EOF'
Usage: ./test/integration.sh [--client <name>]

Runs zt integration tests against the secure-pack packet flow.
Default client: local-smoketest
EOF
}

CLIENT_NAME="local-smoketest"
while [ "$#" -gt 0 ]; do
    case "$1" in
        --client)
            shift
            if [ "$#" -eq 0 ] || [ -z "${1:-}" ]; then
                echo "[FAIL] --client requires a value." >&2
                exit 2
            fi
            CLIENT_NAME="$1"
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
    shift
done

PACKET_GLOB="bundle_${CLIENT_NAME}_*.spkg.tgz"

# Clean up previous artifacts
rm -rf artifact.zp
rm -f bundle_*.spkg.tgz

# Integration tests should validate zt flow, not local scanner installation state.
# Relax scanner requirements temporarily so CI runners without ClamAV/YARA can run.
SCAN_POLICY_FILE="policy/scan_policy.toml"
SCAN_POLICY_BAK="$(mktemp)"
cp "$SCAN_POLICY_FILE" "$SCAN_POLICY_BAK"
LOCAL_RECIP_FILE="tools/secure-pack/recipients/local-smoketest.txt"
LOCAL_RECIP_BAK=""
LOCAL_RECIP_EXISTED="0"
cleanup() {
    cp "$SCAN_POLICY_BAK" "$SCAN_POLICY_FILE"
    rm -f "$SCAN_POLICY_BAK"
    if [ -n "${LOCAL_RECIP_BAK:-}" ] && [ -f "${LOCAL_RECIP_BAK:-}" ]; then
        if [ "${LOCAL_RECIP_EXISTED:-0}" = "1" ]; then
            cp "${LOCAL_RECIP_BAK}" "${LOCAL_RECIP_FILE}"
        else
            rm -f "${LOCAL_RECIP_FILE}"
        fi
        rm -f "${LOCAL_RECIP_BAK}"
    fi
    rm -rf artifact.zp safe.txt blocked.exe
    rm -f bundle_*.spkg.tgz
}
trap cleanup EXIT

if ! command -v gpg >/dev/null 2>&1; then
    echo "[FAIL] gpg is required for secure-pack integration tests." >&2
    exit 1
fi

ROOT_FPR="$(gpg --show-keys --with-colons ./tools/secure-pack/ROOT_PUBKEY.asc | awk -F: '/^fpr:/ {print $10; exit}')"
if [ -z "$ROOT_FPR" ]; then
    echo "[FAIL] Failed to resolve ROOT_PUBKEY fingerprint from tools/secure-pack/ROOT_PUBKEY.asc" >&2
    exit 1
fi
export ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS="$ROOT_FPR"

if [ "$CLIENT_NAME" = "local-smoketest" ]; then
    if [ -f "$LOCAL_RECIP_FILE" ]; then
        LOCAL_RECIP_EXISTED="1"
        LOCAL_RECIP_BAK="$(mktemp)"
        cp "$LOCAL_RECIP_FILE" "$LOCAL_RECIP_BAK"
    fi
    export GNUPGHOME="${GNUPGHOME:-$(pwd)/tmp/gnupg-smoketest}"
    echo "[SETUP] Preparing local secure-pack recipient/signing key for client=${CLIENT_NAME}"
    bash ./scripts/dev/setup-secure-pack-localtest-gpg.sh "$CLIENT_NAME" "ZT Smoke Test (${CLIENT_NAME})" "zt-smoketest+${CLIENT_NAME}@local"
else
    RECIP_FILE="tools/secure-pack/recipients/${CLIENT_NAME}.txt"
    if [ ! -f "$RECIP_FILE" ]; then
        echo "[FAIL] Recipient file not found: $RECIP_FILE" >&2
        echo "       For local smoke tests, use: ./test/integration.sh --client local-smoketest" >&2
        exit 1
    fi
    echo "[SETUP] Using existing recipient config: $RECIP_FILE"
    if [ -z "${GNUPGHOME:-}" ]; then
        echo "[WARN] GNUPGHOME is not set. secure-pack signing will use your default GPG keyring." >&2
    fi
fi

# Verify is fail-closed when signer pins are missing/mismatched.
# Prefer active secret-key fingerprints (actual packet signer candidates).
# Fallback to recipient file when no secret key is discoverable.
SIGNER_PINS="$(gpg --batch --with-colons --list-secret-keys 2>/dev/null | awk -F: '/^fpr:/ {print $10}' | paste -sd, - || true)"
if [ -z "$SIGNER_PINS" ]; then
    RECIP_FILE="tools/secure-pack/recipients/${CLIENT_NAME}.txt"
    if [ ! -f "$RECIP_FILE" ]; then
        echo "[FAIL] Recipient file not found for signer pin setup: $RECIP_FILE" >&2
        exit 1
    fi
    SIGNER_PINS="$(awk 'NF && $1 !~ /^#/ {print $1}' "$RECIP_FILE" | paste -sd, -)"
fi
if [ -z "$SIGNER_PINS" ]; then
    echo "[FAIL] No signer fingerprints available for verify pinning." >&2
    exit 1
fi
export ZT_SECURE_PACK_SIGNER_FINGERPRINTS="$SIGNER_PINS"

cat > "$SCAN_POLICY_FILE" <<'EOF'
required_scanners = []
require_clamav_db = false
EOF

# Create dummy files
echo "This is safe content." > safe.txt
echo "Executable content" > blocked.exe

# Case 1: Safe File
echo "[TEST] Case 1: Sending safe.txt (Should Succeed)"
# Assuming 'nix run' is too slow for tight loop dev, but good for CI.
# We will use 'go run' for speed if acceptable, but let's stick to 'nix run' to match "Goal" criteria.
# To speed up local runs, we can use the binaries directly if built, but 'nix run' is the contract.
nix run .#zt -- send --client "$CLIENT_NAME" --allow-degraded-scan --force-public safe.txt

set -- $PACKET_GLOB
if [ -e "$1" ]; then
    PACKET_PATH="$1"
    echo "  [PASS] Packet generated: $PACKET_PATH"
else
    echo "  [FAIL] Packet not found ($PACKET_GLOB)."
    exit 1
fi

echo "  [TEST] Verifying generated packet"
nix run .#zt -- verify "$PACKET_PATH"
echo "  [PASS] Packet verification succeeded."

# Clean up
rm -rf artifact.zp
rm -f bundle_*.spkg.tgz

# Case 2: Blocked File
echo "[TEST] Case 2: Sending blocked.exe (Should Fail with Exit 1)"
set +e
nix run .#zt -- send --client "$CLIENT_NAME" --allow-degraded-scan --force-public blocked.exe
EXIT_CODE=$?
set -e

if [ $EXIT_CODE -eq 1 ]; then
    echo "  [PASS] zt exited with 1 as expected."
else
    echo "  [FAIL] zt exited with $EXIT_CODE, expected 1."
    exit 1
fi

set -- $PACKET_GLOB
if [ -e "$1" ]; then
    echo "  [FAIL] Packet should NOT be created for blocked file."
    exit 1
else
    echo "  [PASS] No packet created."
fi

echo "=== All Tests Passed ==="
