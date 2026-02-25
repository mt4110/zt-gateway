# Control Plane Postgres Smoke Test

## Purpose

Validate Control Plane dual-write:

- JSONL persists under `control-plane/data/events/*.jsonl`
- Postgres receives the same event ingest rows (`event_ingest`)

## Prerequisites

- Colima (Docker Desktop を使わない前提)
- Docker CLI (`docker`)
- One of:
  - `docker compose` plugin, or
  - `docker-compose` binary

## 0. Colima Onboarding (Docker Desktopなし)

Install (Homebrew):

```bash
brew install colima docker docker-compose
```

Start Colima (example):

```bash
colima start --cpu 4 --memory 8 --disk 60
```

Check daemon:

```bash
docker ps
docker context ls
```

If `docker-compose` does not use the Colima socket automatically, set:

```bash
export DOCKER_HOST="unix://$HOME/.colima/default/docker.sock"
```

If you previously used Docker Desktop and see `docker-credential-desktop` errors, use a clean Docker config for the session:

```bash
mkdir -p ./tmp/docker-config
printf '{}' > ./tmp/docker-config/config.json
export DOCKER_CONFIG="$PWD/tmp/docker-config"
```

Stop when done:

```bash
colima stop
```

## 1. Start Postgres

From repo root:

```bash
# docker compose plugin
docker compose -f control-plane/docker-compose.postgres.yml up -d

# or docker-compose binary
docker-compose -f control-plane/docker-compose.postgres.yml up -d
```

## 2. Prepare Event Key Registry (optional but recommended)

```bash
mkdir -p control-plane/config
cp control-plane/config/event_key_registry.example.toml control-plane/config/event_key_registry.toml
# Fill public_key_b64 with your Ed25519 public key
```

## 3. Start Control Plane API with Postgres

```bash
export ZT_CP_POSTGRES_DSN='postgres://zt:zt-dev-password@127.0.0.1:5432/zt_control_plane?sslmode=disable'
export ZT_CP_EVENT_KEY_REGISTRY_FILE="$PWD/control-plane/config/event_key_registry.toml"

go run ./control-plane/api/cmd/zt-control-plane
```

Notes:

- If you want to enforce signatures with a single key (legacy mode):
  - `ZT_CP_EVENT_VERIFY_PUBKEY_B64=...`
- If `ZT_CP_EVENT_KEY_REGISTRY_FILE` exists and has entries, `key_id` is required and checked (`tenant_id` も取り込みます)
- When Postgres is enabled, the TOML registry is used as a **bootstrap source** and imported into `event_signing_keys`

## 4. Emit Events from `zt`

In another shell:

```bash
export ZT_CONTROL_PLANE_URL='http://127.0.0.1:8080'
export ZT_EVENT_SIGNING_KEY_ID='dev-smoke'
export ZT_EVENT_SIGNING_ED25519_PRIV_B64='REPLACE_WITH_BASE64_ED25519_PRIVATE_KEY_OR_SEED'

bash ./scripts/dev/setup-secure-pack-localtest-gpg.sh
export GNUPGHOME="$PWD/tmp/gnupg-smoketest"
ROOT_FPR="$(gpg --show-keys --with-colons ./tools/secure-pack/ROOT_PUBKEY.asc | awk -F: '/^fpr:/ {print $10; exit}')"
export ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS="${ROOT_FPR}"

echo "control-plane smoke payload" > safe.txt
go run ./gateway/zt send --client local-smoketest --allow-degraded-scan --force-public safe.txt
PACKET_PATH="$(ls -t ./bundle_local-smoketest_*.spkg.tgz | head -n 1)"
go run ./gateway/zt verify "$PACKET_PATH"
```

## 5. Verify JSONL + Postgres

JSONL:

```bash
tail -n 3 control-plane/data/events/scan.jsonl
tail -n 3 control-plane/data/events/artifact.jsonl
tail -n 3 control-plane/data/events/verify.jsonl
```

Postgres:

```bash
docker exec -it zt-control-plane-postgres psql -U zt -d zt_control_plane \
  -c "select kind, event_id, envelope_verified, envelope_tenant_id, envelope_key_id, received_at from event_ingest order by received_at desc limit 10;" \
  -c "select key_id, tenant_id, alg, enabled, source from event_signing_keys order by key_id;"
```

Optional dashboard API check:

```bash
curl -s 'http://127.0.0.1:8080/v1/dashboard/activity?limit=10'
```

## 6. Stop Postgres

```bash
docker compose -f control-plane/docker-compose.postgres.yml down
# or: docker-compose -f control-plane/docker-compose.postgres.yml down
```
