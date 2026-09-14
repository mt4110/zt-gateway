#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

echo "[v0.9.0-core-gate] running channel template unit contracts"
go test ./gateway/zt -count=1 -run 'BuildReceiverChannelTemplates(Contract|RejectsNonPacketPath)'

echo "[v0.9.0-core-gate] running share-json channel template contracts"
go test ./gateway/zt -count=1 -run 'RenderReceiverShareJSON_(Contract|ChannelTemplatesContract)|StdoutShareTransport_JSONContract|FileShareTransportWritesJSON'

echo "[v0.9.0-core-gate] running flow e2e channel template linkage contract"
go test ./gateway/zt -count=1 -run 'ShareJSONToVerifyToReceipt_E2EContract'

echo "[v0.9.0-core-gate] ok"
