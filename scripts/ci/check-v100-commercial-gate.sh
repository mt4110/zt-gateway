#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

echo "[v1.0-commercial-gate] running local SoR contracts"
go test ./gateway/zt -count=1 -run 'InitializeLocalSOR|ValidateLocalSORTenantID|LocalSORSchema_RejectsEmptyTenantID'

echo "[v1.0-commercial-gate] running dashboard commercial contracts"
bash ./scripts/ci/check-dashboard-contract-gate.sh

echo "[v1.0-commercial-gate] running WebAuthn/step-up contracts"
go test ./control-plane/api/cmd/zt-control-plane -count=1 -run 'WebAuthn|StepUp'

echo "[v1.0-commercial-gate] running sales operations pack gate"
bash ./scripts/ci/check-v100-sales-pack-gate.sh

echo "[v1.0-commercial-gate] ok"
