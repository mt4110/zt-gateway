#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

if [ -n "${ZT_BREAK_GLASS_REASON:-}" ]; then
    echo "[v0.9.2-boundary-gate] FAIL ZT_BREAK_GLASS_REASON is set; remove persistent break-glass override from CI/startup environment." >&2
    exit 1
fi

echo "[v0.9.2-boundary-gate] running boundary policy/unit contracts"
go test ./gateway/zt -count=1 -run 'TeamBoundary|RunSend_TeamBoundaryBreakGlassEnvPresentFailFast|RunVerify_TeamBoundaryBreakGlassEnvPresentFailFast|ClassifyVerifyPacketFailure|BuildVerificationReceipt_BoundaryMetadata'

echo "[v0.9.2-boundary-gate] running share-json/setup/doctor boundary contracts"
go test ./gateway/zt -count=1 -run 'RenderReceiverShareJSON_BoundaryContract|CollectSetupPreflightChecks_IncludesTeamBoundaryChecks|RunConfigDoctor_JSONContract_(Success|TeamBoundaryBreakGlassEnvPresentDetected)'

echo "[v0.9.2-boundary-gate] ok"
