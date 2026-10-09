# Verification event summary API

`GET /v1/verification-events/{ingest_id}/summary` returns a fixed, minimal summary for one persisted `verify` event. It reads `event_ingest` in PostgreSQL and requires an event with a verified signed envelope and a trusted tenant from the signing-key registry.

## Requirements

- PostgreSQL configured with `ZT_CP_POSTGRES_DSN` and the existing `event_ingest` schema.
- SSO enabled with `ZT_CP_SSO_ENABLED=1`, a trusted issuer, audience, and configured HS256 or RS256 verification key.
- JWT must have a valid signature and permitted algorithm, trusted issuer, matching audience, valid time claims, `exp`, nonempty `sub`, and nonempty `tenant_id` (or the configured claim names). The verifier allows 30 seconds of clock skew; `iat` may not be more than 30 seconds in the future.
- A viewer, operator, auditor, or admin role from the existing JWT role mapping may read summaries. Every role, including admin, remains scoped to the tenant in that JWT. SCIM does not fill a missing tenant claim for this endpoint.
- The event was accepted with a signature verified against an enabled key registry entry whose tenant is recorded as `envelope_tenant_id`.

The API does not accept API-key-only or dashboard-token authentication. It ignores tenant and role request headers. It does not offer cross-tenant lookup.

## Find and read one event

Use the existing event activity view or the signed ingest response's `ingest_id`. An ingest acceptance response alone does not guarantee a PostgreSQL row: the current dual-write path can accept JSONL while PostgreSQL persistence fails.

```sh
curl --fail-with-body \
  -H "Authorization: Bearer $ZT_SSO_JWT" \
  http://127.0.0.1:8080/v1/verification-events/ing_demo_001/summary
```

The public response is a flat object with exactly these eight fields:

```json
{"schema_version":1,"ingest_id":"ing_demo_001","tenant_id":"tenant_demo_a","kind":"verify","received_at":"2026-10-10T00:00:00Z","reported_result":"verified","reported_policy_decision":"allow","event_signature_verified":true}
```

`reported_result` and `reported_policy_decision` describe values reported in the stored event. Missing or unrecognized values become `unknown`; they do not count as success. `event_signature_verified` records that event signature verification succeeded at ingest time. This API does not scan or re-verify the file, validate the current status of the signing key, or make a malware-free claim. It also does not protect other existing detail APIs or change their authorization behavior.

## Tenant denial check

Use an event listed under tenant A, then call with a valid JWT whose tenant is B. The API returns the same fixed `{"error":"not_found"}` response as it does for a nonexistent or ineligible ID. An admin JWT for B is still restricted to B.

## LeakFence handoff contract candidate

This endpoint is a flat JSON source candidate for a later LeakFence integration:

- `tenant_field`: `tenant_id`
- `id_field`: `ingest_id`
- `max_records`: `1`
- `max_bytes`: `4096`
- `fields`: `schema_version`, `ingest_id`, `tenant_id`, `kind`, `received_at`, `reported_result`, `reported_policy_decision`, `event_signature_verified`
- permission candidate: `verification-event-summary:read`

The permission string is a proposed integration identifier only; it does not grant JWT authority. No production daily quota is set here. A future handoff must construct its principal, tenant, permission, and allowed `record_ids` from server-side validated authentication and the enforced tenant lookup. It must not copy the URL ID directly into an allowlist or treat the response payload as authority.

The Control Plane is a Go service, not a Cloudflare Worker. A Service Binding alone does not connect these components. A later connection test must establish how verified authentication and authorization cross the Cloudflare boundary, and prove there is no route around the protected lookup.

## Validation evidence

The API passed both mock-DB contract tests and a local integration test against disposable PostgreSQL 16. The integration test exercised signed event ingestion, the real PostgreSQL JSONB summary query, same-tenant retrieval, and cross-tenant denial for viewer and admin roles. This confirms the local Control Plane path; it does not establish production deployment behavior. Full commands, outcomes, and remaining limits are recorded in [the evidence note](./evidence/VERIFICATION_EVENT_SUMMARY.md). Use synthetic tenant A/B credentials and event signing keys; retain only a public dummy ID and sanitized response, never JWTs, private keys, or real event payloads.
