#!/bin/sh
set -e

echo "=== Starting Integration Tests ==="

# Clean up previous artifacts
rm -rf artifact.zp

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
