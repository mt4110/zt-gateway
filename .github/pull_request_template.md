## Summary

- What changed:
- Why:

## Validation

- [ ] `go test ./gateway/zt -count=1`
- [ ] `go test ./control-plane/api/cmd/zt-control-plane -count=1`
- [ ] `bash ./scripts/ci/check-zt-contract-gate.sh`
- [ ] `bash ./scripts/ci/check-control-plane-contract-gate.sh`

## v0.5e Contract Checklist

- [ ] v0.5e-1 `zt sync --json` contract: `error_class/error_code` + stdout(JSON)/exit code fixed
- [ ] v0.5e-2 spool failure state contract: `first_failed_at/last_failed_at/error_class` persisted, fail-closed auto-retry suppressed, `--force` resend confirmed
- [ ] v0.5e-3 CP ingest idempotency contract: `event_id + payload_sha256` duplicate handling + OpenAPI updated
- [ ] v0.5e-4 Gateway↔CP E2E contract: registry enabled send/verify->sync, missing `key_id` reject, rotation cutover verified
- [ ] v0.5e-5 ops docs synced: `README.md`, `docs/OPERATIONS.md`, `docs/EVENT_KEY_ROTATION_RUNBOOK.md`
