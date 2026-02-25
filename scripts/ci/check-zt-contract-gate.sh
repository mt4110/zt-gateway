#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

echo "[contract-gate] running zt contract tests"
go test ./gateway/zt -count=1 -run 'Contract|JSONContract|E2EContract'

echo "[contract-gate] running zt audit trail contract tests (v0.5-A)"
go test ./gateway/zt -count=1 -run 'Audit.*Contract'

echo "[contract-gate] running zt audit tamper-detection contract tests (v0.5-B)"
go test ./gateway/zt -count=1 -run 'Audit.*(ChainContract|SignatureContract|VerifyE2EContract|DetectsTamper)'

echo "[contract-gate] running zt audit verify contract tests (v0.5-C)"
go test ./gateway/zt -count=1 -run 'AuditVerify(CLI_SuccessAndFailureContract|FailClosedContract|KeyRotationContract|LegacyV05AContract)'

echo "[contract-gate] running gateway/control-plane integration contract tests (v0.5d-5)"
go test ./gateway/zt -count=1 -run 'GatewayEvent(Sync|Signing).*Contract'

echo "[contract-gate] running gateway/control-plane e2e regression contract tests (v0.5e-4)"
go test ./gateway/zt -count=1 -run 'GatewayControlPlaneE2EContract.*'

echo "[contract-gate] ok"
