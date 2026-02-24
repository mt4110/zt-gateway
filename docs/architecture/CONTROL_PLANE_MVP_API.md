# Control Plane MVP API (Go API)

## Positioning

This is **not** the end-user file upload API.

- End users use `zt` CLI (`send/scan/verify`)
- This API is the **Control Plane ingest + policy distribution API**
- Purpose: audit, policy sync, rule metadata, dashboard data

Language choice of this server does **not** limit client languages.
Any client can call it over HTTP/JSON. If needed later, add SDKs (Go/Python/TS), but keep the server in Go.

## Why Go API (MVP)

- Same language as the core tools (`zt`, `secure-scan`, `secure-pack`)
- Easier operational model (fewer runtimes)
- Good fit for high-throughput event ingest and async processing
- Faster to ship a robust MVP than introducing TS/Node + Prisma now

## MVP Design Principle

- Keep local CLI fast/offline-first
- Accept async event uploads from CLI (best-effort / retryable)
- Keep responses small and deterministic
- Do not proxy payload files

## Minimal Endpoints (MVP)

### `POST /v1/events/scan`

Purpose:
- Receive scan result event emitted by local `zt send` / `zt scan`

Request body (summary):
- `event_id` (uuid)
- `occurred_at`
- `host_id`
- `tool_version`
- `target_name`
- `result` (`allow|deny`)
- `reason`
- `summary`
- `scanners`
- `policy`
- `provenance`
- `rule_hash`
- `signature` (optional in MVP, recommended next)

Response:
- `202 Accepted`
- `{ "status": "accepted", "event_id": "...", "ingest_id": "..." }`

### `POST /v1/events/artifact`

Purpose:
- Receive artifact/packet creation event after `secure-pack`

Request body (summary):
- `event_id`
- `occurred_at`
- `artifact_kind` (`artifact.zp|spkg.tgz`)
- `artifact_sha256`
- `file_name`
- `sender_identity`
- `recipient_name`
- `signer_fingerprint`
- `policy_version`
- `rule_hash`

Response:
- `202 Accepted`

### `POST /v1/events/verify`

Purpose:
- Receive verification result event from `zt verify`

Request body (summary):
- `event_id`
- `occurred_at`
- `artifact_sha256`
- `artifact_kind`
- `verifier_identity`
- `result` (`verified|failed|warning`)
- `reason`
- `details`

Response:
- `202 Accepted`

### `GET /v1/policies/extension/latest`

Purpose:
- Distribute latest `extension_policy.toml`

Response:
- `200 OK`
- `{ "version": "...", "sha256": "...", "content_toml": "...", "effective_at": "..." }`

### `GET /v1/policies/scan/latest`

Purpose:
- Distribute latest `scan_policy.toml`

Response:
- `200 OK`
- `{ "version": "...", "sha256": "...", "content_toml": "...", "effective_at": "..." }`

## Optional (MVP+) Endpoint

### `GET /v1/rules/latest`

Purpose:
- Return metadata only (not necessarily binaries yet)
- Lets dashboard and CLI compare expected `rule_hash` / bundle version

Response:
- `200 OK`
- `{ "composite_rule_hash": "...", "components": [...], "updated_at": "..." }`

## Async and Performance Guidance (Important)

Your instinct is right: "fast" and "async where possible" matters.
But the correct split is:

- **CLI path**: synchronous only for local safety decisions (`scan/rebuild/pack/verify`)
- **Control Plane uploads**: async / retryable / batched

This means:

- `zt send` must not wait on Control Plane to decide if a file is safe
- `zt send` may enqueue event and continue if network/API is down
- Background uploader can flush events later

In short:
- Safety decision path = local + synchronous
- Audit/telemetry path = remote + asynchronous

## Recommended Go API MVP Stack

- HTTP router: stdlib `net/http` (or `chi` if you want ergonomics)
- DB: Postgres
- SQL layer: `sqlc` + `pgx`
- Migrations: `golang-migrate` (or `atlas`, but keep simple)
- Queue (MVP): Postgres table + worker goroutine (no Kafka yet)
- Auth (MVP): static API key per tenant or mTLS later

## MVP "Useful Enough" Acceptance Criteria

- CLI can upload scan/artifact/verify events without blocking local operation
- Dashboard queries can answer:
  - Who sent what to whom
  - Which signer fingerprint was used
  - Which rule hash/policy version was applied
  - Why a file was denied
- Policy fetch endpoints can pin versions and hashes

## What Not To Build Yet

- File upload/storage API for payload contents
- Multi-step workflow engine
- WebSocket streaming
- Multi-region anything
- SDKs before API stabilizes

