# Control Plane Draft (v0.1.0-pre)

## Goal

Keep `zt` CLI fast/offline-capable while making auditability and policy distribution centrally managed.

- Data Plane (local CLI path): `scan -> rebuild -> pack -> verify` runs locally, DB not required
- Control Plane (server): Postgres-backed API for audit, policy, rule bundle, signer metadata

## Non-Goals (v0.1.x)

- Real-time message relay or file transfer proxy
- Mandatory online check for every local `zt send` / `zt verify`
- Storing user payload files in the control plane DB

## Responsibilities Split

### Data Plane (Go CLI / local tools)

- Execute `secure-scan`, `secure-rebuild`, `secure-pack`
- Enforce local extension policy
- Produce signed local audit log/event envelope
- Queue events for later upload when offline

### Control Plane (API + Postgres)

- Receive audit events and verification logs
- Serve versioned policies (`extension_policy`, scanner requirements)
- Track rule bundle metadata (hash/version/source)
- Manage signer metadata / allowlists / recipient registry metadata
- Provide dashboard queries (who signed/sent what to whom)

## Minimal Postgres Schema (Draft)

```sql
create table tenants (
  id uuid primary key,
  slug text unique not null,
  created_at timestamptz not null default now()
);

create table policy_versions (
  id uuid primary key,
  tenant_id uuid not null references tenants(id),
  policy_kind text not null,              -- extension_policy, scan_policy
  version text not null,                  -- e.g. 2026.02.24-1
  content_toml text not null,
  sha256 text not null,
  created_by text not null,
  created_at timestamptz not null default now(),
  unique (tenant_id, policy_kind, version)
);

create table rule_bundles (
  id uuid primary key,
  tenant_id uuid not null references tenants(id),
  engine text not null,                   -- clamav, yara, composite
  version text not null,
  sha256 text not null,
  source_uri text,
  provenance_json jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  unique (tenant_id, engine, version)
);

create table signer_keys (
  id uuid primary key,
  tenant_id uuid not null references tenants(id),
  key_fingerprint text not null,
  key_type text not null,                 -- pgp, minisign, x509 (future)
  status text not null,                   -- active, revoked, retired
  metadata_json jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  unique (tenant_id, key_fingerprint)
);

create table recipient_profiles (
  id uuid primary key,
  tenant_id uuid not null references tenants(id),
  name text not null,
  fingerprint text not null,
  metadata_json jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  unique (tenant_id, name)
);

create table artifact_records (
  id uuid primary key,
  tenant_id uuid not null references tenants(id),
  artifact_kind text not null,            -- artifact.zp, spkg.tgz
  artifact_sha256 text not null,
  file_name text not null,
  sender_identity text not null,
  recipient_name text,
  signer_fingerprint text,
  policy_version_id uuid references policy_versions(id),
  rule_bundle_id uuid references rule_bundles(id),
  scan_rule_hash text,
  created_at timestamptz not null default now(),
  unique (tenant_id, artifact_sha256)
);

create table scan_jobs (
  id uuid primary key,
  tenant_id uuid not null references tenants(id),
  artifact_record_id uuid references artifact_records(id),
  target_name text not null,
  result text not null,                   -- allow, deny
  reason text not null,
  summary_json jsonb not null default '{}'::jsonb,
  scanners_json jsonb not null default '[]'::jsonb,
  provenance_json jsonb not null default '{}'::jsonb,
  started_at timestamptz not null,
  finished_at timestamptz not null
);

create table verification_logs (
  id uuid primary key,
  tenant_id uuid not null references tenants(id),
  artifact_record_id uuid references artifact_records(id),
  verifier_identity text not null,
  result text not null,                   -- verified, failed, warning
  reason text not null,
  details_json jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
```

## API Responsibility Draft

### In-scope (v0.1.x / v0.2.x)

- `POST /v1/events/scan`
- `POST /v1/events/artifact`
- `POST /v1/events/verify`
- `GET /v1/policies/extension/latest`
- `GET /v1/policies/scan/latest`
- `GET /v1/policies/keyset`
- `GET /v1/rules/latest`
- `GET /v1/dashboard/activity`

### Out-of-scope (later)

- User management / SSO
- Workflow approvals
- Payload file storage
- Cross-tenant routing

## TS + Prisma vs Go + pgx/sqlc (Control Plane)

### Option A: TypeScript + Prisma + Postgres

Pros:
- Dashboard/API開発が速い（React/Next 連携しやすい）
- Prisma migration/CRUD が扱いやすい
- 将来の管理画面まで一気通貫で実装しやすい

Cons:
- Node runtime 運用が1つ増える
- 高スループット ingest ではチューニング余地が必要
- コアGoツールとは別言語運用になる

Best fit:
- ダッシュボードを早く出したい
- 管理UI主導で価値検証したい

### Option B: Go API + pgx/sqlc + Postgres

Pros:
- コアと同言語で運用/レビューしやすい
- 型安全なSQL運用（sqlc）
- ingest系APIの性能・配布が扱いやすい

Cons:
- 管理画面は別途（TS/Reactなど）必要
- CRUD中心の実装速度はPrismaより遅いことがある

Best fit:
- まずAPI/監査基盤を固めたい
- 運用面を最小化したい

## Recommendation (Current Project Stage)

- **Now (v0.1.x):** Go core を継続、Control Plane は設計のみ or 最小Go API
- **Next (v0.2.x):** Dashboardが必要になったら TS + Prisma + Postgres を別サービスで追加
- **Rule:** CLI data path に online dependency を入れない（オフライン可 / 後送信）

## Open Decisions

- Tenant model is needed for OSS v0.1.0 or single-tenant first?
- Event upload auth method (mTLS / API key / signed envelope)?
- Policy version pinning in artifacts (required vs optional)?
- Verification logs retention policy?
