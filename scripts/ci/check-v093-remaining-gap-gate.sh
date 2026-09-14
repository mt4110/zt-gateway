#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

if [ -n "${ZT_BREAK_GLASS_REASON:-}" ]; then
    echo "[v0.9.3-remaining-gap-gate] FAIL ZT_BREAK_GLASS_REASON is set; remove persistent break-glass override from CI/startup environment." >&2
    exit 1
fi

echo "[v0.9.3-remaining-gap-gate] running receive trust-anchor parity contracts"
go test ./tools/secure-pack/internal/workflows -count=1 -run 'ReceiverWorkflow_SignerPin(MissingReturnsCode|MismatchReturnsCode|MatchExtracts)|ResolveSecurePackSignerFingerprintPins_FromAllowlistFile'

echo "[v0.9.3-remaining-gap-gate] running unpack hardening contracts"
go test ./tools/secure-pack/internal/pack -count=1 -run 'NormalizeUnpackAllowedFingerprints|UnpackPacket_RequiresSignerAllowlist'

echo "[v0.9.3-remaining-gap-gate] running boundary degraded-scan guardrail contracts"
go test ./gateway/zt -count=1 -run 'RunSend_TeamBoundaryAllowDegradedRequiresBreakGlass|EnforceTeamBoundaryDegradedScanOverride_(DisabledFailsClosed|ReasonRequired|TokenAccepted|TokenExpired)'

echo "[v0.9.3-remaining-gap-gate] running setup/doctor scan posture contracts"
go test ./gateway/zt -count=1 -run 'CollectSetupPreflightChecks_IncludesScanPostureChecks|CollectSetupPreflightChecksWithPolicy_StrictProfileClamAVRequirement|RunConfigDoctor_JSONContract_(Success|ScanPostureRequiredScannersFail)'

echo "[v0.9.3-remaining-gap-gate] ok"
