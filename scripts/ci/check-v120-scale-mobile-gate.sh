#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

echo "[v1.2-scale-mobile-gate] running control-plane mobile/issuer/ha contracts"
go test ./control-plane/api/cmd/zt-control-plane -count=1 -run 'ControlPlaneSSOAuthenticateBearerToken|ExtractControlPlaneMFAAuditContext|CollectControlPlaneHAStatus|HandleHealthz_IncludesHASection'

echo "[v1.2-scale-mobile-gate] running control-plane tenant isolation contracts"
go test ./control-plane/api/cmd/zt-control-plane -count=1 -run 'DashboardActivityCSVExportContract_DropsCrossTenantRowsAtScale'

echo "[v1.2-scale-mobile-gate] running gateway scale/realtime/legal contracts"
go test ./gateway/zt -count=1 -run 'HandleDashboardClientsAPI_TenantIsolationAtScale|HandleDashboardSignatureHoldersAPI_TenantIsolationAtScale|CollectDashboardSignatureHolderSnapshot_RealtimeSLO|CollectDashboardSnapshot_KPIIncludesSignatureHolderRealtimeMetrics|RunAuditCommand_Report_LegalTemplate|AppendAuditEvent_ExternalLedger'

echo "[v1.2-scale-mobile-gate] checking dashboard schema upgrade"
rg -q "SchemaVersion:\\s+7" gateway/zt/commands_dashboard.go

echo "[v1.2-scale-mobile-gate] ok"
