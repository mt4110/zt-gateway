#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

openapi="docs/openapi/control-plane-v1.yaml"

echo "[openapi-contract-gate] validating required v0.6.0MAX fields"

patterns=(
  "IngestAccepted:"
  "endpoint: { type: string, example: /v1/events/scan }"
  "payload_sha256: { type: string }"
  "accepted_at: { type: string, format: date-time }"
  "required: [status, ingest_id, duplicate, endpoint, payload_sha256, accepted_at]"
  "policy_set_id: { type: string }"
  "freshness_slo_seconds: { type: integer }"
  "rotation_id: { type: string }"
  "active_key_id: { type: string }"
)

for p in "${patterns[@]}"; do
  if ! rg -n --fixed-strings "$p" "$openapi" >/dev/null; then
    echo "missing OpenAPI contract line: $p" >&2
    exit 1
  fi
done

echo "[openapi-contract-gate] ok"
