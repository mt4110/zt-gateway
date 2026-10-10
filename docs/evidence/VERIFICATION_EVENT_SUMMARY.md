# Verification event summary implementation evidence

- Test-time source base: `faa539d91a5c0e79d959e33d3b93934763e410a3` (`Initial public release`) plus the then-uncommitted implementation. Those implementation changes were subsequently committed as `8f5d8f6`, with this evidence clarified in `7d16d3b`, and merged in PR #1 as `8d228813`. The original local test record is not a claim that CI ran against an uncommitted tree.
- Environment: macOS Darwin 27.0.0, arm64; Go `go1.27.1 darwin/arm64`.
- Test data: generated Ed25519 event-signing key and short-lived HS256 test JWTs; synthetic tenant IDs and payload only. No production credentials or event data.

## Mock database and handler tests

- Command: `go test ./control-plane/api/...`
- Input conditions: signed synthetic verify envelope passes through the existing ingest handler; sqlmock accepts the event insert and returns the synthetic stored row for summary lookup. Contract cases also model tenant mismatch, missing IDs, malformed requests, signature metadata inconsistency, failed authentication, JWT issuer/audience/signature/time/claim failures, DB errors, request cancellation, query timeout, and sensitive payload fields.
- Expected: one fixed eight-field response for a same-tenant eligible row; no response data on denial or failure; tenant A and B lookups share a fixed not-found response.
- Actual: passed (`zt-control-plane-api/cmd/zt-control-plane`; other API packages compile).
- Evidence limit: sqlmock verifies handler and query contract. It does not verify PostgreSQL JSONB operators, schema, transaction behavior, or actual DB cancellation.

## Disposable PostgreSQL end-to-end check

- Environment: temporary `postgres:16` container with a tmpfs data directory and an ephemeral localhost port. The container was created only for this check with a generated database/user/password; it held synthetic test data only and was configured for automatic removal when stopped.
- Command: `ZT_CP_TEST_POSTGRES_DSN=<disposable-local-PostgreSQL-DSN> go test ./cmd/zt-control-plane -run '^TestVerificationSummaryPostgresIngestToRead$' -count=1 -v`
- Input conditions: the opt-in test created the existing schema, generated an Ed25519 keypair and a signed verify event with synthetic tenant A, then submitted it through the mounted ingest handler. It used short-lived synthetic JWTs for tenant A viewer, tenant B viewer, and tenant B admin.
- Expected: ingest returns an `ingest_id`; PostgreSQL stores the verified envelope and JSONB payload; tenant A retrieves the flat eight-field response with reported `failed` / `degraded`; sensitive payload values are absent; tenant B viewer and admin get the same fixed 404.
- Actual: passed against PostgreSQL 16 (`TestVerificationSummaryPostgresIngestToRead`, 0.04s on the isolated run). The complete Control Plane API module suite also passed against that same disposable PostgreSQL database.
- Cleanup: the test container was stopped and auto-removed; no project or user PostgreSQL container or database was used.
- Evidence limit: this confirms the real PostgreSQL schema/query and handler ingest-to-read path. It is a local synthetic integration check, not a Cloudflare/LeakFence connection test or a production deployment test.

## API contract and workspace checks

- Command: `./scripts/ci/check-openapi-contract-gate.sh`
- Expected/actual: existing required OpenAPI contract fields present; passed.
- Command: `yq -e '.paths."/v1/verification-events/{ingest_id}/summary".get.responses."200".content."application/json".schema."$ref" == "#/components/schemas/VerificationEventSummary"' docs/openapi/control-plane-v1.yaml`
- Expected/actual: the route references the fixed summary schema and the YAML parses; passed.
- Command: `git diff --check`
- Expected/actual: no whitespace errors; passed.
- Command: `go test ./...` from the host shell.
- Actual: failed before the environment correction because this host does not have `gpg` on `PATH`; `TestFullFlow` invokes the `gpg` executable directly.
- Root cause and correct command: `flake.nix` includes `pkgs.gnupg` in the development shell. Running `nix develop --command go test ./...` from the repository root passed the workspace suite (`zt-gateway-workspace`, 8.153s after the final test guard change). The test was not skipped or weakened. `TestFullFlow` now fails fast with the required command when invoked outside the supported environment; that diagnostic was checked with `go test ./tools/secure-pack/test -run '^TestFullFlow$' -count=1`.

## Remaining end-to-end checks

- No Cloudflare or LeakFence connection was attempted. This change provides only the candidate summary contract documented in `VERIFICATION_EVENT_SUMMARY.md`.
