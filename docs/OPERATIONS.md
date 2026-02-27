# Operations Guide (Current)

この文書は、`zt-gateway` の**現行運用**に絞った一次対応ガイドです。

## Scope

- 対象: `zt send` / `zt verify` / `zt setup --json` / `zt config doctor --json` / `zt policy status --json` / `zt sync --json`
- 目的: CI・Helpdesk・運用担当が、失敗時に最短で原因を切り分ける
- 詳細 runbook: `docs/V0.9.2_ABNORMAL_USECASES.md`

## まず確認する順番

1. `ZT_ERROR_CODE` または `SECURE_PACK_ERROR_CODE` の有無を確認
2. `go run ./gateway/zt setup --json` で supply-chain check と pin解決値を確認
3. `go run ./gateway/zt config doctor --json` で設定劣化を確認
4. `go run ./gateway/zt policy status --json --kind all` で整合性/鮮度を確認
5. `go run ./gateway/zt sync --json` で backlog と `error_class/error_code` を確認

## 標準コマンド（運用）

```bash
# setup / doctor
go run ./gateway/zt setup --json
go run ./gateway/zt config doctor --json

# send / verify
go run ./gateway/zt send --client <recipient-name> ./safe.txt
go run ./gateway/zt verify ./bundle_xxx.spkg.tgz

# policy/sync
go run ./gateway/zt policy status --json --kind all
go run ./gateway/zt sync --json
```

## エラー一次切り分け

### `ZT_PRECHECK_SUPPLY_CHAIN_FAILED`

- 主因: root pin 未設定/不一致、`tools.lock.sig` 検証失敗、依存ツール差分
- 対応:
  1. `zt setup --json` の `checks[]` と `resolved.pin_*` を確認
  2. root/signer pin を再配布
  3. 必要なら `docs/SECURE_PACK_KEY_ROTATION_RUNBOOK.md` を実施

### `ZT_SEND_POLICY_BLOCKED`

- 主因: 拡張子/サイズ/MIME整合違反
- 対応:
  1. `policy/extension_policy.toml` を確認
  2. ファイル形式と運用ルールを照合
  3. 例外はレビュー承認後に policy 変更

### `ZT_SEND_SCAN_DENIED` / `ZT_SEND_SCAN_CHECK_FAILED`

- 主因: scan結果が deny、または scanner 実行失敗
- 対応:
  1. scanner 稼働状況を確認
  2. `policy/scan_policy.toml` の required_scanners を確認
  3. 緊急時のみ `--allow-degraded-scan --break-glass-reason ...`

### `ZT_VERIFY_PACKET_FAILED` / `ZT_VERIFY_SIGNER_PIN_MISMATCH`

- 主因: packet 改ざん/破損、署名者 pin 不一致
- 対応:
  1. packet 再受領
  2. signer pin（allowlist）を再配布
  3. 鍵事故時は `docs/V0.9.2_ABNORMAL_USECASES.md` の該当手順を実施

## policy/sync 一次復旧

### policy status

`zt policy status --json --kind all` で次を確認:

- `overall_set_consistency`
- `overall_freshness_state`
- `critical_kinds`

`unknown` / `critical` が出たら、`zt sync --json` の結果と合わせて runbook 実施。

### sync status

`zt sync --json` で次を確認:

- `pending_count`
- `oldest_pending_age_seconds`
- `retryable_count`
- `fail_closed_count`
- `error_class` / `error_code`

運用判断:

- `error_class=retryable`: 監視継続（必要時のみ `--force`）
- `error_class=fail_closed`: 設定修正後に `go run ./gateway/zt sync --force --json`
- `error_code=ingest_ack_mismatch`: Control Plane 側契約と ACK 整合を調査

## Team Boundary / break-glass

- `policy/team_boundary.toml` で境界を固定
- `ZT_BREAK_GLASS_REASON` の常駐設定は禁止（fail-fast対象）
- break-glass は `--break-glass-reason "incident=<id>;approved_by=<id>;expires_at=<RFC3339>"`

異常系は `docs/V0.9.2_ABNORMAL_USECASES.md` を正本として対応。

## key-repair

鍵事故対応の標準 runbook ID は `docs/OPERATIONS.md#key-repair`。

### 受付条件

- `compromised` 判定済み、または同等の疑いがある
- tenant と対象 key_id が確定している

### 手順

1. 影響 key の状態を `compromised` または `rotating` へ遷移
2. `key-repair job` を起票（operator / evidence_ref / summary を記録）
3. `detected -> contained -> rekeyed -> rewrapped -> completed` の順で遷移
4. 失敗時は `failed` に遷移し、再実行条件を明記
5. 監査ログ（JSON/CSV）を保存

## KR-001

`kr-001` は最小対応フローです。

- 条件: 単一 tenant / 単一 key でのインシデント
- 完了条件: `key_repair` job が `completed`、関連証跡が保存済み

## CI ゲート（推奨）

- `scripts/ci/check-zt-setup-json-gate.sh`
- `scripts/ci/check-zt-setup-json-actual-gate.sh`
- `scripts/ci/check-policy-contract-gate.sh`
- `scripts/ci/check-policy-set-gate.sh`
- `scripts/ci/check-sync-observability-gate.sh`
- `scripts/ci/check-openapi-contract-gate.sh`
- `scripts/ci/check-v098-dashboard-auth-gate.sh`
- `scripts/ci/check-v099-dashboard-mutation-coverage-gate.sh`
- `scripts/ci/check-v130-operations-gap-closure-gate.sh`

## Pin 配布（CI標準）

必要な GitHub Actions Variables:

- `ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS_EXPECTED`
- `ZT_SECURE_PACK_SIGNER_FINGERPRINTS_EXPECTED`

配布スクリプト:

```bash
# root pin
bash ./scripts/dev/bootstrap-ci-root-pin-expected.sh --expected-pins "OLD_ROOT_FPR_40HEX,NEW_ROOT_FPR_40HEX"

# signer pin
bash ./scripts/dev/bootstrap-ci-signer-pin-expected.sh --expected-pins "OLD_SIGNER_FPR_40HEX,NEW_SIGNER_FPR_40HEX"

# root + signer 一括
bash ./scripts/dev/bootstrap-ci-trust-pins.sh \
  --root-expected-pins "OLD_ROOT_FPR_40HEX,NEW_ROOT_FPR_40HEX" \
  --signer-expected-pins "OLD_SIGNER_FPR_40HEX,NEW_SIGNER_FPR_40HEX"
```

## 監査/通知

- 共有導線は `zt send --share-json` を標準化
- 外部通知は allowlist と token を設定した場合のみ有効化
- event spool を一次証跡として保存し、必要に応じて Control Plane に同期

## 関連文書

- `docs/README.md`
- `SECURITY.md`
- `THREAT_MODEL.md`
- `docs/SECURE_PACK_SMOKETEST.md`
- `docs/SECURE_PACK_KEY_ROTATION_RUNBOOK.md`
- `docs/V0.9.2_ABNORMAL_USECASES.md`
