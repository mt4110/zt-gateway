#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

echo "[v0.8.0-core-gate] running receipt hint command/path contracts"
go test ./gateway/zt -count=1 -run 'Receiver(SuggestedReceiptPath|VerifyCommandWithReceipt).*Contract'

echo "[v0.8.0-core-gate] running share-json receipt hint contract"
go test ./gateway/zt -count=1 -run 'RenderReceiverShareJSON_Contract|StdoutShareTransport_JSONContract|FileShareTransportWritesJSON'

echo "[v0.8.0-core-gate] running flow e2e receipt linkage contract"
go test ./gateway/zt -count=1 -run 'ShareJSONToVerifyToReceipt_E2EContract'

echo "[v0.8.0-core-gate] ok"
