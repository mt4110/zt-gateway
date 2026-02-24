#!/bin/sh
set -e

echo "=== Starting Integration Tests ==="

# Clean up previous artifacts
rm -rf artifact.zp

# Integration tests should validate zt flow, not local scanner installation state.
# Relax scanner requirements temporarily so CI runners without ClamAV/YARA can run.
SCAN_POLICY_FILE="policy/scan_policy.toml"
SCAN_POLICY_BAK="$(mktemp)"
cp "$SCAN_POLICY_FILE" "$SCAN_POLICY_BAK"
cleanup() {
    cp "$SCAN_POLICY_BAK" "$SCAN_POLICY_FILE"
    rm -f "$SCAN_POLICY_BAK"
    rm -rf artifact.zp safe.txt blocked.exe
}
trap cleanup EXIT
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
nix run .#zt -- send --force-public safe.txt

if [ -d "artifact.zp" ]; then
    echo "  [PASS] Artifact directory created."
else
    echo "  [FAIL] Artifact directory not found."
    exit 1
fi

if [ -f "artifact.zp/metadata.json" ]; then
    echo "  [PASS] Metadata found."
else
    echo "  [FAIL] Metadata missing."
    exit 1
fi

# Clean up
rm -rf artifact.zp

# Case 2: Blocked File
echo "[TEST] Case 2: Sending blocked.exe (Should Fail with Exit 1)"
set +e
nix run .#zt -- send --force-public blocked.exe
EXIT_CODE=$?
set -e

if [ $EXIT_CODE -eq 1 ]; then
    echo "  [PASS] zt exited with 1 as expected."
else
    echo "  [FAIL] zt exited with $EXIT_CODE, expected 1."
    exit 1
fi

if [ -d "artifact.zp" ]; then
    echo "  [FAIL] Artifact directory should NOT be created for blocked file."
    exit 1
else
    echo "  [PASS] No artifact created."
fi

echo "=== All Tests Passed ==="
