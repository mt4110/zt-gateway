#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

echo "[v0.9.4-true-zt-gate] running secure-rebuild fail-closed contracts"
go test ./tools/secure-rebuild -count=1 -run 'RunRebuild_(FailClosedOnUnsupportedExtension|PNGSanitizerWritesOutput)'

echo "[v0.9.4-true-zt-gate] running gateway rebuild/team-boundary/provenance contracts"
go test ./gateway/zt -count=1 -run 'CollectSetupPreflightChecks_RebuildSanitizerCoverageFail|RunConfigDoctor_JSONContract_RebuildSanitizerCoverageFail|ResolveTeamBoundaryPolicy_RequiredAliasEnv|EmitArtifactEvent_IncludesRebuildProvenanceContract'

echo "[v0.9.4-true-zt-gate] running control-plane envelope/security contracts"
go test ./control-plane/api/cmd/zt-control-plane -count=1 -run 'EventIngestEnvelopeErrorsContract|ValidateControlPlaneSecurityConfig_StrictGuards'

echo "[v0.9.4-true-zt-gate] ok"

