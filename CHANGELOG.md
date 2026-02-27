# Changelog

このファイルはユーザー向けの変更履歴を記録します。

フォーマット方針:

- `Added`: 新機能
- `Changed`: 既存挙動の変更
- `Fixed`: バグ修正
- `Security`: セキュリティ関連

## [Unreleased]

### Added

- Monorepo structure (`zt-gateway`, `secure-pack`, `secure-scan`, `secure-rebuild`)
- `zt` adapter layer for legacy/new tool coexistence
- `secure-scan` non-interactive JSON mode (`check --json`)
- `secure-scan` strict mode (`--strict`)
- `zt` extension policy file (`policy/extension_policy.toml`)
- `zt send --strict`
- local GPG smoke test setup script for packet verification
- `zt send --share-json` now includes `receipt_hint` (`version` / `path` / `command`) for receiver-side `--receipt-out` guidance
- `zt send --share-json` now includes `channel_templates` (`version` / `slack_text` / `email_subject` / `email_body`) for Cloud-Agnostic Wrapper handoff
- v0.8.0 architecture baseline docs (`docs/architecture/V0.8.0_DESIGN.md`, `docs/architecture/V0.8.0_IMPLEMENTATION_TICKETS.md`)
- v0.9.0 architecture baseline docs (`docs/architecture/V0.9.0_DESIGN.md`, `docs/architecture/V0.9.0_IMPLEMENTATION_TICKETS.md`)
- expected-pin bootstrap for `check-zt-setup-json-actual-gate.sh` (`ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS_EXPECTED`)
- v1 blueprint freeze decisions for receipt ID / audit retention / trust profile thresholds / OS fix priority
- one-command CI variable bootstrap script (`scripts/dev/bootstrap-ci-root-pin-expected.sh`)
- v0.9.7 dashboard safety gate (`scripts/ci/check-v097-dashboard-safety-gate.sh`)

### Changed

- `zt send` now uses new `secure-scan` JSON mode for scan gating
- `zt verify` output format aligned across legacy artifact and packet modes
- `secure-scan` JSON now includes `rule_hash`
- `zt dashboard` now emits `danger.signals[].code=dashboard_alert_dispatch_unsafe_config` when external alert dispatch is enabled without webhook allowlist

### Security

- Fail-closed extension policy (`DENY / SCAN_ONLY / SCAN_REBUILD`)
- Size limit enforcement (`max_size_mb`)
- Optional strict scanner availability enforcement
- Audit trail tamper-detection baseline (`events.jsonl` hash-chain + optional Ed25519 record signatures + verification contracts)

## [0.1.0] - YYYY-MM-DD

### Added

- Initial public pre-release of Zero-Trust local gateway monorepo

### Changed

- TBD

### Fixed

- TBD

### Security

- TBD
