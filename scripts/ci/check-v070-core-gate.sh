#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

echo "[v0.7.0-core-gate] running policy status all-kinds contract"
go test ./gateway/zt -count=1 -run 'PolicyStatus_AllKindsContract'

echo "[v0.7.0-core-gate] running sync backlog SLO determinism contract"
go test ./gateway/zt -count=1 -run 'SyncCLIJSONContract_BacklogSLODeterminismContract'

echo "[v0.7.0-core-gate] running runbook anchor contracts"
go test ./gateway/zt -count=1 -run 'BuildQuickFixBundleWithCode_RunbookAnchorContract|PolicyStatus_SetConsistencyContract|PolicyStatus_AllKindsContract|SyncCLIJSONContract_(BacklogVisibilityContract|AckIntegrityMismatchContract)'

echo "[v0.7.0-core-gate] running scan posture contracts"
go test ./gateway/zt -count=1 -run 'ScanPosture_(ProfileContract|ViolationContract)'

echo "[v0.7.0-core-gate] running file-type explainability contracts"
go test ./gateway/zt -count=1 -run 'FileTypeGuard_JSONExplainabilityContract|PolicyDecisionContract_(FileTypeGuardExplainabilityContract|FileTypeGuardIncludedInEventPayloadContract)'

echo "[v0.7.0-core-gate] ok"
