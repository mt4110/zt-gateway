# Secure-Pack Root Key Rotation Runbook

`ROOT_PUBKEY.asc` fingerprint pin は `zt setup` / `zt send` precheck / `secure-pack send` を fail-closed で止める前提です。鍵ローテーション時は「旧+新 fingerprint の併記期間」を明示して段階的に切り替えます。

## 目的

- root key のローテーションを安全に実施する
- 端末/CI の pin 更新漏れで業務停止しないようにする
- rollback を事前定義して、切替日に迷わないようにする

## 変更計画テンプレート（必須項目）

- `旧 fingerprint`: `OLD_FPR_40HEX`
- `新 fingerprint`: `NEW_FPR_40HEX`
- `併記開始日`（旧+新許容開始）: `YYYY-MM-DD`
- `切替日`（新鍵で署名開始）: `YYYY-MM-DD`
- `旧fingerprint削除日`（pin から旧を外す日）: `YYYY-MM-DD`
- `rollback期限`（旧鍵へ戻せる運用期限）: `YYYY-MM-DD`
- `承認者`: `name`
- `周知先`: `helpdesk / ops / CI owners`

## 手順（標準）

1. 事前確認
- 新 `ROOT_PUBKEY.asc` を別経路で配布し、fingerprint を電話/対面/別チャネルで照合する
- `tools.lock` を新鍵で署名できることをローカルで確認する
- `zt setup --json` と `secure-pack send` のリグレッション（固定fixtureテスト + ローカルsmoketest）を実施する

2. 併記期間を開始（旧+新許容）
- 端末/CI の pin を `OLD,NEW` に更新する
- 例:

```bash
export ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS="OLD_FPR_40HEX,NEW_FPR_40HEX"
export SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS="OLD_FPR_40HEX,NEW_FPR_40HEX"
```

3. 切替日（新鍵で署名開始）
- `tools/secure-pack/ROOT_PUBKEY.asc` を新鍵に更新する
- `tools/secure-pack/tools.lock` を新鍵で再署名して `tools.lock.sig` を更新する
- CI で `zt setup --json` ゲートとテストを通す
- 切替実施時刻（UTC/ローカル）を記録する

4. 監視期間（併記継続）
- helpdesk に `ZT_ERROR_CODE=ZT_PRECHECK_SUPPLY_CHAIN_FAILED` / `SECURE_PACK_ERROR_CODE=...` の問い合わせ導線を共有する
- CI/端末の失敗ログを確認し、pin 未更新端末を洗い出す

5. 旧fingerprint削除日
- 端末/CI の pin から旧 fingerprint を削除し、新 fingerprint のみ残す
- 旧鍵の配布物/手順が残っていないか確認する

## Rollback 手順（事前合意）

1. 新鍵の署名/配布に問題が出た場合、`ROOT_PUBKEY.asc` と `tools.lock.sig` を旧鍵版に戻す
2. 端末/CI pin を `OLD,NEW`（または `OLD` のみ）に戻す
3. `zt setup --json` ゲートを再実行して `secure_pack_root_pubkey_fingerprint` と `secure_pack_tools_lock_signature` が `ok` であることを確認する
4. rollback 実施日時・原因・再試行条件を記録する

## CI / 自動化メモ

- 追加済みの `scripts/ci/check-zt-setup-json-gate.sh` は固定署名fixtureで `zt setup --json` を実行し、以下3項目を必須 `ok` として検証する
- `secure_pack_supply_chain_files`
- `secure_pack_root_pubkey_fingerprint`
- `secure_pack_tools_lock_signature`
- 実artifactをCIで検査する場合は、別ステップで `tools.lock` / `tools.lock.sig` / `ROOT_PUBKEY.asc` を配置し、`ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS` を CI secret/variable に設定して `go run ./gateway/zt setup --json` を実行する
- 追加済みの `scripts/ci/check-zt-setup-json-actual-gate.sh` は repo 内の `tools/secure-pack/` 実artifact を直接検査する。実artifactが存在する場合は `ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS` 未設定で fail-closed、未配置なら `skip` する
- GitHub Actions では `Variables` に `ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS` を設定するのを推奨（fingerprint は秘密値ではないため）。`Secrets` は fallback として利用可

詳細な配布コマンド（`gh variable set` / `gh api` / `curl`）と actual repo ゲート通過手順は `docs/OPERATIONS.md` を参照してください。

## `zt setup --json` の machine-readable 補助フィールド（supply-chain pin）

- `resolved.actual_root_fingerprint`
- `resolved.pin_source` (`env` / `built-in` / `env+built-in` / `none` / `invalid`)
- `resolved.pin_match_count`

## エラーコード（運用問い合わせ向け）

運用の正本（CI/Helpdesk 共通参照）: `docs/OPERATIONS.md`

鍵ローテーション時の問い合わせでも、エラーコードの一次切り分け表（`zt` / `secure-pack`）は `docs/OPERATIONS.md` を正本として参照してください。

ローテーション時に特に見るコード（抜粋）:

- `ZT_PRECHECK_SUPPLY_CHAIN_FAILED`
- `ZT_SETUP_CHECKS_FAILED`
- `ZT_SEND_PACK_FAILED`（直後の `SECURE_PACK_ERROR_CODE=...` を確認）
- `SECURE_PACK_ERROR_CODE=SP_ROOT_PIN_MISSING`
- `SECURE_PACK_ERROR_CODE=SP_ROOT_PIN_MISMATCH`
- `SECURE_PACK_ERROR_CODE=SP_TOOLS_LOCK_SIGNATURE_INVALID`
