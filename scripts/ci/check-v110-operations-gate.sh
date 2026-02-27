#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

echo "[v1.1-operations-gate] running SCIM/auth contracts"
go test ./control-plane/api/cmd/zt-control-plane -count=1 -run 'SCIMSync|AuthenticateControlPlaneRequest_SCIMRoleMappingApplied|ControlPlaneSSOAuthenticateBearerToken'

echo "[v1.1-operations-gate] running dashboard KPI/signature/anomaly contracts"
go test ./gateway/zt -count=1 -run 'HandleDashboardSignatureHoldersAPI|CollectDashboardSnapshot_KPIUsesLocalSORExchangeMetrics|CollectDashboardAlertStatus_IncludesAnomalyFalsePositiveSignal'

echo "[v1.1-operations-gate] running audit report/rotation contracts"
go test ./gateway/zt -count=1 -run 'RunAuditCommand_Report_GeneratesJSONAndPDF|RunAuditCommand_Rotate_ArchivesOldMonthsAndRetainsCurrent'

echo "[v1.1-operations-gate] checking postgres index optimizations"
rg -q "idx_event_ingest_tenant_received_at" control-plane/api/cmd/zt-control-plane/event_keys_db.go
rg -q "idx_event_ingest_tenant_kind_received_at" control-plane/api/cmd/zt-control-plane/event_keys_db.go
rg -q "idx_event_ingest_signature_anomaly_time" control-plane/api/cmd/zt-control-plane/event_keys_db.go

echo "[v1.1-operations-gate] ok"

