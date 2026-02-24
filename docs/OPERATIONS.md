# Operations Guide (CI / Helpdesk / Runbook Quick Reference)

`zt-gateway` の運用時に、CI担当・Helpdesk・運用担当が最初に見るための共通参照ページです。

## 目的

- `ZT_ERROR_CODE` / `SECURE_PACK_ERROR_CODE` の一次切り分けを統一する
- `zt setup --json` の CI ゲート運用を標準化する
- `ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS` の配布手順（GitHub Actions Variables）を共通化する

## まず確認する順番（問い合わせ / CI失敗）

1. `ZT_ERROR_CODE=...` が出ているか確認
2. JSON出力がある場合は `error_code` / `checks[]` / `quick_fixes[]` を確認
3. `ZT_SEND_PACK_FAILED` の場合は `SECURE_PACK_ERROR_CODE=...` を確認
4. supply-chain 系なら `zt setup --json` の `secure_pack_*` checks と `resolved.pin_*` を確認

## 代表エラーコード一覧（`zt` 側 / Helpdesk・CI向け）

| Error Code | 主な発生箇所 | 代表原因 | 一次対応 |
| --- | --- | --- | --- |
| `ZT_SETUP_CHECKS_FAILED` | `zt setup` / `zt setup --json` | setup checks に `fail` がある | `checks[]` と `quick_fixes[]` を確認。supply-chain 3項目 / policy parse / spool権限を優先確認 |
| `ZT_PRECHECK_SUPPLY_CHAIN_FAILED` | `zt send` 開始直後 | `tools.lock` / `tools.lock.sig` / `ROOT_PUBKEY.asc` 不備、pin未設定・不一致、署名検証失敗 | `zt setup --json` を先に実行し、`secure_pack_*` チェックと `resolved.pin_*` を確認 |
| `ZT_SEND_EXTENSION_POLICY_LOAD_FAILED` | `zt send` | `policy/extension_policy.toml` parse/load失敗 | policy構文修正。fail-closed なので送信再試行前に修正必須 |
| `ZT_SEND_SCAN_POLICY_LOAD_FAILED` | `zt send` | `policy/scan_policy.toml` parse/load失敗 | policy構文修正。fail-closed なので送信再試行前に修正必須 |
| `ZT_SEND_POLICY_BLOCKED` | `zt send` | 拡張子ポリシー/サイズ/MIME整合チェックで block | 対象ファイル形式と `extension_policy.toml` を確認。必要なら運用レビュー後に policy更新 |
| `ZT_SEND_SCAN_UPDATE_FAILED` | `zt send --update` | `freshclam` 不在/DB更新失敗/ネットワーク不可 | `freshclam` / ClamAV DB / ネットワークを確認。急ぎなら `--update` なしで再試行（運用判断） |
| `ZT_SEND_SCAN_JSON_PARSE_FAILED` | `zt send` | secure-scan JSON出力が壊れている/想定外 | secure-scan バージョン差分・stderr・直近変更を確認 |
| `ZT_SEND_SCAN_CHECK_FAILED` | `zt send` | secure-scan 実行失敗（JSON結果なし） | scanner依存関係・stderr・PATH を確認 |
| `ZT_SEND_SCAN_DENIED` | `zt send` | secure-scan 判定が `allow` 以外 | scan結果の `reason` を確認し、検体/環境/ルールを切り分け |
| `ZT_SEND_SANITIZE_FAILED` | `zt send` | `secure-rebuild` 失敗 | 対象形式の対応状況・入力破損・rebuild stderr を確認 |
| `ZT_SEND_PACK_FAILED` | `zt send` | `secure-pack` 側失敗 | 併記される `SECURE_PACK_ERROR_CODE=...` を優先確認 |
| `ZT_SEND_CLIENT_REQUIRED` | `zt send` | `--client <name>` 未指定 | `--client <recipient-name>` を付与 |
| `ZT_VERIFY_PACKET_FAILED` | `zt verify` | `.spkg.tgz` の署名/整合性検証失敗 | 受領ファイル改ざん/破損の可能性。再受領して再検証 |
| `ZT_VERIFY_UNSUPPORTED_INPUT` | `zt verify` | `.spkg.tgz` 以外入力（legacy含む） | `zt verify <packet.spkg.tgz>` に統一 |
| `ZT_SCAN_CHECK_FAILED` | `zt scan` | secure-scan 実行失敗 | stderr / scanner依存関係 / PATH を確認 |
| `ZT_SCAN_TUI_FAILED` | `zt scan --tui` | secure-scan TUI起動失敗 | TTY環境・依存関係・secure-scan 実行可否を確認 |
| `ZT_CONFIG_DOCTOR_FAILED` | `zt config doctor` | config/env/spool等の doctor fail | `zt config doctor --json` の `checks[]` を確認 |
| `ZT_CONFIG_USAGE` | `zt config doctor` / `zt config` | 引数不正 | usageに合わせて再実行 |
| `ZT_CONFIG_UNKNOWN_SUBCOMMAND` | `zt config` | 未対応サブコマンド | `zt config doctor` のみ使用 |

## `secure-pack` 側（供給網/封緘の詳細）

- `SECURE_PACK_ERROR_CODE=SP_ROOT_PIN_MISSING`
- `SECURE_PACK_ERROR_CODE=SP_ROOT_PIN_MISMATCH`
- `SECURE_PACK_ERROR_CODE=SP_TOOLS_LOCK_SIGNATURE_INVALID`
- `SECURE_PACK_ERROR_CODE=SP_TOOL_HASH_MISMATCH`
- `SECURE_PACK_ERROR_CODE=SP_TOOL_VERSION_MISMATCH`

## `zt setup --json` で見るポイント（supply-chain）

優先チェック:

- `checks[].name == secure_pack_supply_chain_files`
- `checks[].name == secure_pack_root_pubkey_fingerprint`
- `checks[].name == secure_pack_tools_lock_signature`

補助フィールド（`resolved`）:

- `actual_root_fingerprint`
- `pin_source` (`env` / `build-in` / `env+build-in` / `none` / `invalid`)
- `pin_match_count`

## CI ゲート（標準）

fixtureゲート（ロジック回帰検知）:

- `scripts/ci/check-zt-setup-json-gate.sh`
- 固定署名fixtureで `zt setup --json` を実行し、supply-chain 3項目の `ok` を検証

actual repo ゲート（実artifact直検査）:

- `scripts/ci/check-zt-setup-json-actual-gate.sh`
- `tools/secure-pack/tools.lock` / `tools.lock.sig` / `ROOT_PUBKEY.asc` が存在する場合は fail-closed
- `ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS` 未設定時は `fail`
- `zt setup --json` の全体 `ok` は参考値（supply-chain 以外の失敗に影響されるため）
- `resolved.pin_match_count >= 1` を必須化
- `ZT_BIN=/path/to/linux-zt` を指定すると、`go build` の代わりに既存バイナリで実行可能（Ubuntu コンテナ検証用）

注意（重要）:

- `tools.lock` の `tar_sha256` / `tar_version` は OS 依存です
- macOS は通常 `bsdtar`、GitHub Actions `ubuntu-latest` は通常 GNU tar のため、macOS で生成した `tools.lock` は CI actual repo ゲートで失敗する可能性があります
- CI green を狙う場合は、Ubuntu/Linux 環境で `tools.lock` を生成・署名してください

## GitHub Actions Variable 配布（`ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS`）

fingerprint は秘密値ではない前提のため、GitHub Actions `Variables` を推奨します（`Secrets` は fallback）。

`gh` CLI:

```bash
gh variable set ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS \
  --repo mt4110/zt-gateway \
  --body "OLD_FPR_40HEX,NEW_FPR_40HEX"
```

`gh api`（REST API）:

```bash
# 作成（初回）
gh api \
  --method POST \
  -H "Accept: application/vnd.github+json" \
  /repos/mt4110/zt-gateway/actions/variables \
  -f name='ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS' \
  -f value='OLD_FPR_40HEX,NEW_FPR_40HEX'

# 更新（値差し替え）
gh api \
  --method PATCH \
  -H "Accept: application/vnd.github+json" \
  /repos/mt4110/zt-gateway/actions/variables/ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS \
  -f name='ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS' \
  -f value='NEW_FPR_40HEX'
```

`curl`（`GH_TOKEN` 利用）:

```bash
curl -sS -X PATCH \
  -H "Authorization: Bearer ${GH_TOKEN}" \
  -H "Accept: application/vnd.github+json" \
  https://api.github.com/repos/mt4110/zt-gateway/actions/variables/ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS \
  -d '{"name":"ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS","value":"NEW_FPR_40HEX"}'
```

必要権限の目安:

- `gh auth login` / `GH_TOKEN` で repo admin 相当（Actions variables 更新権限）
- Fine-grained token の場合は対象 repo の `Variables` 更新権限を含める

## 実artifact配置 -> actual repo ゲート通過（実施順）

1. `tools/secure-pack/ROOT_PUBKEY.asc` を配置
2. `tools/secure-pack/tools.lock` を配置
3. `tools/secure-pack/tools.lock.sig` を配置（`tools.lock` に対応）
4. `ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS` を GitHub Actions Variable/Secret に設定
5. ローカル確認:

```bash
bash ./scripts/ci/check-zt-setup-json-actual-gate.sh
```

6. CI の actual repo ゲート通過を確認（`pin_match_count >= 1`）

## Ubuntu/Linux で `tools.lock` を生成・署名・差し替え（CI green 用）

推奨: Ubuntu 環境（ローカルVM / cloud VM / GitHub Codespaces / Ubuntu runner相当）で実行する。

前提:

- root signing key の秘密鍵が `gpg` に import 済み
- `gpg`, `tar`, `sha256sum` が利用可能

補助スクリプト:

```bash
bash ./scripts/dev/generate-secure-pack-tools-lock.sh \
  --root-key "your-root-key@example.com"
```

このスクリプトは以下を生成/更新します:

- `tools/secure-pack/tools.lock`
- `tools/secure-pack/tools.lock.sig`
- `tools/secure-pack/ROOT_PUBKEY.asc`

実施順（Linux pin 差し替え）:

1. Ubuntu/Linux で上記スクリプトを実行
2. 出力された `root_fingerprint` を確認
3. `ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS` を GitHub Actions Variable に設定/更新
4. `bash ./scripts/ci/check-zt-setup-json-actual-gate.sh` を実行して local green 確認
5. `bash ./scripts/ci/check-pre-push-readiness.sh` を実行
6. `git diff` / `git status` を確認して commit/push
7. CI の actual repo ゲート green を確認

補足:

- root key をローテーションしない場合でも、`ROOT_PUBKEY.asc` は同時に再出力して整合性を固定する運用を推奨
- root key をローテーションする場合は `docs/SECURE_PACK_KEY_ROTATION_RUNBOOK.md` の併記期間/切替手順に従う

## commit/push 前の最終チェック（運用標準）

```bash
bash ./scripts/ci/check-pre-push-readiness.sh
```

実行内容:

- `go test ./gateway/zt`
- `go test ./tools/secure-pack/internal/workflows`
- fixture supply-chain gate
- actual repo supply-chain gate
- `git status --short` の表示（目視確認用）

macOS で repo の `tools.lock` が Linux pin の場合:

```bash
SKIP_ACTUAL_GATE=1 bash ./scripts/ci/check-pre-push-readiness.sh
```

その場合、actual repo ゲートは Ubuntu/Linux 側で別途実行して補完する（上記手順）。
