# Zero-Trust Local Gateway
## zt-gateway / secure-pack / secure-scan / secure-rebuild

ローカル実行を前提に、ファイル受け渡しを「検査・再構成・封緘・検証」で強化するツール群です。

- 送信側: `zt send`
- 受信側: `zt verify`
- 証跡: event spool と JSON 出力

> Status: pre-release（統合開発中）
> 本番の高機密データ運用前に `SECURITY.md` と `THREAT_MODEL.md` を必ず確認してください。

## README の読み方

- 最短で動かす: [Quick Start](#quick-start)
- 安全設計と運用ルール: [なぜ安全か / 安全境界](#なぜ安全か--安全境界)
- 実運用の正本: `docs/OPERATIONS.md`
- 詳細設計: `docs/architecture/README.md`

## Quick Start

### 送信側（最短）

1. Root key fingerprint pin を設定

```bash
ROOT_FPR="$(gpg --show-keys --with-colons ./tools/secure-pack/ROOT_PUBKEY.asc | awk -F: '/^fpr:/ {print $10; exit}')"
export ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS="${ROOT_FPR}"
```

2. セットアップ確認

```bash
go run ./gateway/zt setup --json
go run ./gateway/zt config doctor --json
```

3. 送信

```bash
go run ./gateway/zt send --client <recipient-name> --copy-command ./safe.txt
```

### 受信側（最短）

```bash
zt verify ./bundle_xxx.spkg.tgz
```

必要に応じて証跡を保存:

```bash
zt verify --receipt-out ./receipt_bundle_xxx.json ./bundle_xxx.spkg.tgz
```

## なぜ安全か / 安全境界

### 設計意図

- ネットワークを信用しない前提で、ローカル処理を積み上げて安全性を高めます。
- 処理は `scan -> rebuild -> pack(sign/encrypt) -> verify` の順で実行します。
- 判定不能・設定破損・署名不整合は fail-closed で停止します。

### 現在効いている主な安全機構

- 拡張子ポリシーのデフォルト拒否（未知拡張子や危険形式を `DENY`）
- MIME / magic bytes の整合チェック
- `scan_policy.toml` / `extension_policy.toml` 読み込み失敗時の fail-closed
- `tools.lock` 署名検証と root fingerprint pin
- `secure-pack verify` の署名 + SHA256 照合
- `zt setup --json` / `zt config doctor --json` による事前診断

### 安全運用の必須ルール

1. `zt send --client <name>` と `zt verify` を標準手順として固定する
2. 送受信は `*.spkg.tgz` を使用し、検証を省略しない
3. `--allow-degraded-scan` は緊急時のみ使い、`--break-glass-reason` を必ず付与する
4. signer/root fingerprint pin を端末と CI に固定する
5. CI で `zt setup --json` / `zt config doctor --json` を定期実行する

### 現状の安全境界（重要）

- 一部機能は統合途中です。全形式に対する再構成を保証しません。
- 強い保証が必要な環境では、導入前に脅威モデル・運用手順・鍵運用をレビューしてください。

## 主要コマンド

```bash
# 環境チェック
go run ./gateway/zt setup --json
go run ./gateway/zt config doctor --json

# 送信 / 検証
go run ./gateway/zt send --client <recipient-name> ./safe.txt
go run ./gateway/zt verify ./bundle_xxx.spkg.tgz

# ポリシー同期状態
go run ./gateway/zt policy status --json --kind all
go run ./gateway/zt sync --json

# 監査/連携向け
go run ./gateway/zt send --client <recipient-name> --share-json ./safe.txt
```

## 追加運用（任意）

- dashboard: `go run ./gateway/zt dashboard`
- relay drive: `go run ./gateway/zt relay drive ...`
- relay auto-drive: `go run ./gateway/zt relay auto-drive ...`
- relay hook: `go run ./gateway/zt relay hook ...`

詳細は `go run ./gateway/zt --help-advanced` を参照してください。

## CI / 自動化

推奨:

- `scripts/ci/check-zt-setup-json-gate.sh`
- `scripts/ci/check-zt-setup-json-actual-gate.sh`
- `scripts/ci/check-policy-contract-gate.sh`
- `scripts/ci/check-sync-observability-gate.sh`
- `scripts/ci/check-openapi-contract-gate.sh`

`ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS_EXPECTED` などの pin は GitHub Actions Variables で配布してください。

## ドキュメント

- ドキュメント目次（現行）: `docs/README.md`
- 現行設計目次: `docs/architecture/README.md`
- 運用・一次切り分け: `docs/OPERATIONS.md`
- セキュリティ方針: `SECURITY.md`
- 脅威モデル: `THREAT_MODEL.md`
- API/OpenAPI: `docs/openapi/`
- secure-pack ローカル検証: `docs/SECURE_PACK_SMOKETEST.md`
- Control Plane/Postgres 検証: `docs/CONTROL_PLANE_POSTGRES_SMOKETEST.md`

## ディレクトリ構成

```text
.
├── control-plane/           # Control Plane API
├── docs/                    # 設計・運用・契約
├── gateway/
│   └── zt/                  # Gateway CLI
├── policy/                  # extension/scan/team-boundary/client 設定
├── scripts/
│   ├── ci/                  # CI ゲート
│   └── dev/                 # 開発補助スクリプト
├── test/
├── testdata/
├── tools/
│   ├── secure-pack/
│   ├── secure-scan/
│   ├── secure-rebuild/
│   └── poc/
├── CHANGELOG.md
├── LICENSE
├── SECURITY.md
└── THREAT_MODEL.md
```

## 開発の始め方

### Go workspace

このリポジトリは `go.work` で複数モジュールを同時開発します。

```bash
go work sync
```

### Colima（Docker Desktop を使わない構成）

```bash
brew install colima docker docker-compose
colima start --cpu 4 --memory 8 --disk 60
docker ps
```

停止:

```bash
colima stop
```
