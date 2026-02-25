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

### Changed

- `zt send` now uses new `secure-scan` JSON mode for scan gating
- `zt verify` output format aligned across legacy artifact and packet modes
- `secure-scan` JSON now includes `rule_hash`

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
