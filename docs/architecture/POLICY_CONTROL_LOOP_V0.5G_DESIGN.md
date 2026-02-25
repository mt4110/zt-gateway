# v0.5g Design: Policy Control Loop Operational Hardening

## Context

v0.5f で以下を固定済み:

- signed policy bundle 検証契約（署名/期限/鍵）
- activation 契約（`active`/`staged`/`last_known_good` + atomic apply）
- `policy_decision` 出力契約（CLI/JSON/receipt/audit 整合）
- staleness/offline 契約（profile 別 fail-closed/degraded）
- keyset endpoint + policy latest ETag 再取得契約

v0.5g は、この心臓部を現場運用で崩さないための「自動配布・段階展開・鍵運用・観測」を契約化する。

## Goal

- 利用者操作なしで policy を安全同期できる（unconscious security）
- 段階展開（canary -> default）を決定論的に実施できる
- 鍵ローテーションを停止なく実施できる
- 障害時は `policy_decision` と runbook だけで一次復旧できる

## Non-goal

- UI ダッシュボードの大幅刷新
- ポリシー評価ロジック自体（ルール言語）の刷新
- マルチリージョン分散配信

## v0.5g Scope (Proposed)

### v0.5g-1 Gateway Policy Sync Loop Contract

- Gateway にバックグラウンド同期ループを追加（pull 型）
- 同期順序を固定:
  1. `GET /v1/policies/keyset`（If-None-Match 対応）
  2. `GET /v1/policies/{kind}/latest?profile=...`（If-None-Match 対応）
  3. verify -> stage -> activate
- 同期メタを `*.meta.json` に保存:
  - `etag_keyset`, `etag_latest`, `last_fetch_at`, `last_success_at`, `last_error_code`
- 失敗時:
  - `active` は不変
  - `last_known_good` へ rollback 契約維持
  - `policy_decision.error_class/error_code` を固定出力

契約テスト:
- 304 応答で再適用しない
- 同一 manifest 再取得で active 不変
- 同期失敗でも active 維持

### v0.5g-2 CP Rollout (Canary) Contract

- latest endpoint を rollout-aware 化:
  - 入力: `profile`, `gateway_id`, `channel`（default: `stable`）
  - 出力追加: `rollout_id`, `rollout_channel`, `rollout_rule`
- 配布判定は決定論的に固定:
  - 例: `sha256(gateway_id + rollout_id) % 100 < canary_percent`
- `duplicate_rule` を配布契約として維持（再取得 idempotent）

契約テスト:
- 同一 `gateway_id` で常に同じ配布結果
- canary 比率変更でのみ配布結果が変わる
- stable/canary の境界を再現可能

### v0.5g-3 Keyset Rotation Contract

- keyset schema を拡張:
  - `status: active|next|retiring`
  - `valid_from`, `valid_to`
- Gateway 検証契約:
  - `active` と `next` を有効期間内で受理
  - 期限外/未知 key は fail-closed
- rotate 手順を固定:
  1. `next` 配布
  2. bundle を `next` 署名で publish
  3. `next -> active` 昇格
  4. 旧鍵 `retiring` -> 削除

契約テスト:
- overlap window 中の無停止切替
- 旧鍵期限超過後の fail-closed

### v0.5g-4 CP Signing Bootstrap Capsule Contract

運用上の env 必須感を減らすため、署名鍵設定をカプセル化する。

- 既定動作を `auto`（env不要）に固定
  - 起動時に鍵未存在なら自動生成し `control-plane/data/keys/` に永続化
- 新しい選択モード:
  - `ZT_CP_POLICY_SIGNING_MODE=auto|env|file`（default: `auto`）
- 既存 env は互換維持:
  - `ZT_CP_POLICY_SIGNING_ED25519_PRIV_B64`
  - `ZT_CP_POLICY_SIGNING_KEY_ID`
  - `ZT_CP_POLICY_BUNDLE_TTL_HOURS`
- 失敗時は明確な起動エラーコードで停止（silent fallback 禁止）

契約テスト:
- env 未設定でも endpoint が起動可能（auto）
- env/file 指定時は優先順が固定
- 不正鍵入力時は fail-fast

### v0.5g-5 Min Gateway Version Enforcement Contract

- bundle の `min_gateway_version` を厳密評価
- バージョン不一致時:
  - `error_class=fail_closed`
  - `error_code=policy_gateway_version_unsupported`
- Receipt/Audit へ同一 `policy_decision` を記録

契約テスト:
- 要件未満バージョンは常に deny
- CLI/JSON/receipt/audit で reason 一致

### v0.5g-6 Policy Status and Doctor Contract

- 新コマンド: `zt policy status --json`
- 最小出力項目:
  - `active.manifest_id`, `active.expires_at`
  - `staged.manifest_id`
  - `last_known_good.manifest_id`
  - `last_sync_at`, `next_sync_at`, `sync_error_code`
- `zt setup --json` / `zt config doctor --json` に policy loop health を追加

契約テスト:
- status JSON の required fields 固定
- stale/verify_failed/version_unsupported の診断分岐が固定

### v0.5g-7 CI Gate and E2E Regression Contract

- CI に `policy-rollout-gate` を追加
- E2E 一本化:
  - keyset rotate -> canary publish -> gateway sync -> decision change -> receipt/audit/sync 整合
- rollback E2E:
  - 壊れた canary bundle 配布時に active 不変 + LKG 維持

## API / Schema Delta (Draft)

### `GET /v1/policies/{kind}/latest`

追加（案）:

- request query:
  - `gateway_id` (required in v0.5g)
  - `channel` (`stable|canary`, optional)
- response fields:
  - `rollout_id`
  - `rollout_channel`
  - `rollout_rule`

### `GET /v1/policies/keyset`

追加（案）:

- `keys[].status`
- `keys[].valid_from`
- `keys[].valid_to`

## Error Contract Additions (Draft)

- `policy_gateway_version_unsupported`
- `policy_rollout_not_eligible`（canary 非対象時の情報コード。判定は fail ではなく keep-active）
- `policy_sync_transport_failed`
- `policy_sync_http_5xx`

## Exit Criteria

- 自動同期ループで `active` を人手なし更新できる
- canary/stable 配布が `gateway_id` 単位で決定論的に再現可能
- 鍵ローテーション中も verify/activate が停止しない
- version 不一致 policy は確実に fail-closed
- `zt policy status --json` と runbook だけで一次復旧可能
- `policy-rollout-gate` が独立 CI ゲートとして常時 green

## Implementation Order (Recommended)

1. v0.5g-4 CP signing bootstrap capsule
2. v0.5g-3 keyset rotation schema + verify
3. v0.5g-1 gateway sync loop
4. v0.5g-5 min version strict enforcement
5. v0.5g-2 rollout/canary contract
6. v0.5g-6 status/doctor contract
7. v0.5g-7 e2e + CI gate + runbook
