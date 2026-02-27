# Operations Guide (CI / Helpdesk / Runbook Quick Reference)

`zt-gateway` の運用時に、CI担当・Helpdesk・運用担当が最初に見るための共通参照ページです。

## 目的

- `ZT_ERROR_CODE` / `SECURE_PACK_ERROR_CODE` の一次切り分けを統一する
- `zt setup --json` の CI ゲート運用を標準化する
- `ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS` の配布手順（GitHub Actions Variables）を共通化する

## まず確認する順番（問い合わせ / CI失敗）

1. `ZT_ERROR_CODE=...` が出ているか確認
2. `zt policy status --json` で `set_consistency` / `freshness_state` / `sync_error_code` を確認（v0.7.0 実装後は `--kind all` を優先）
3. `zt sync --json` で `error_class` / `error_code` / `pending_count` / `oldest_pending_age_seconds` を確認
4. JSON出力がある場合は `quick_fix_bundle.runbook` と `quick_fix_bundle.runbook_anchor`（存在時）を起点に修復コマンドを実行
5. `ZT_SEND_PACK_FAILED` の場合は `SECURE_PACK_ERROR_CODE=...` を確認
6. supply-chain 系なら `zt setup --json` の `secure_pack_*` checks と `resolved.pin_*` を確認

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
| `ZT_SEND_TEAM_BOUNDARY_POLICY_FAILED` | `zt send` | `policy/team_boundary.toml` 欠落/破損（required時） | boundary policy を復旧し再実行 |
| `ZT_SEND_TEAM_BOUNDARY_RECIPIENT_DENIED` | `zt send` | `allowed_recipients` 不一致 | recipient allowlist 更新。緊急時は理由付き break-glass |
| `ZT_SEND_TEAM_BOUNDARY_SHARE_ROUTE_DENIED` | `zt send` | `allowed_share_routes` 不一致 | share-route allowlist 更新。緊急時は理由付き break-glass |
| `ZT_SEND_TEAM_BOUNDARY_BREAK_GLASS_ENV_PRESENT` | `zt send` | `ZT_BREAK_GLASS_REASON` 常駐設定を起動時に検知 | `ZT_BREAK_GLASS_REASON` を shell/profile/CI から除去し、`docs/V0.9.2_ABNORMAL_USECASES.md#break-glass-override-left-enabled` を実施 |
| `ZT_SEND_TEAM_BOUNDARY_BREAK_GLASS_REASON_REQUIRED` | `zt send` | break-glass 理由未指定で緊急解除不可 | `--break-glass-reason` を設定し、`docs/V0.9.2_ABNORMAL_USECASES.md#break-glass-reason-required` を実施 |
| `ZT_SEND_TEAM_BOUNDARY_BREAK_GLASS_TOKEN_INVALID` | `zt send` | break-glass token 形式不正/TTL超過 | `docs/V0.9.2_ABNORMAL_USECASES.md#break-glass-token-invalid` を実施 |
| `ZT_SEND_TEAM_BOUNDARY_BREAK_GLASS_TOKEN_EXPIRED` | `zt send` | break-glass token 期限切れ | `docs/V0.9.2_ABNORMAL_USECASES.md#break-glass-token-expired` を実施 |
| `ZT_SEND_AUDIT_APPEND_FAILED` | `zt send` | 監査ログ追記失敗（追跡不能のため fail-closed） | `docs/V0.9.2_ABNORMAL_USECASES.md#audit-trail-append-failed` を実施 |
| `ZT_VERIFY_PACKET_FAILED` | `zt verify` | `.spkg.tgz` の署名/整合性検証失敗 | 受領ファイル改ざん/破損の可能性。再受領して再検証 |
| `ZT_VERIFY_TEAM_BOUNDARY_POLICY_FAILED` | `zt verify` | `policy/team_boundary.toml` 欠落/破損（required時） | boundary policy を復旧し再実行 |
| `ZT_VERIFY_TEAM_BOUNDARY_SIGNER_DENIED` | `zt verify` | team boundary signer 不一致 | signer allowlist / team boundary signer を整合 |
| `ZT_VERIFY_TEAM_BOUNDARY_BREAK_GLASS_ENV_PRESENT` | `zt verify` | `ZT_BREAK_GLASS_REASON` 常駐設定を起動時に検知 | `ZT_BREAK_GLASS_REASON` を shell/profile/CI から除去し、`docs/V0.9.2_ABNORMAL_USECASES.md#break-glass-override-left-enabled` を実施 |
| `ZT_VERIFY_TEAM_BOUNDARY_BREAK_GLASS_REASON_REQUIRED` | `zt verify` | break-glass 理由未指定で緊急解除不可 | `--break-glass-reason` を設定し、`docs/V0.9.2_ABNORMAL_USECASES.md#break-glass-reason-required` を実施 |
| `ZT_VERIFY_TEAM_BOUNDARY_BREAK_GLASS_TOKEN_INVALID` | `zt verify` | break-glass token 形式不正/TTL超過 | `docs/V0.9.2_ABNORMAL_USECASES.md#break-glass-token-invalid` を実施 |
| `ZT_VERIFY_TEAM_BOUNDARY_BREAK_GLASS_TOKEN_EXPIRED` | `zt verify` | break-glass token 期限切れ | `docs/V0.9.2_ABNORMAL_USECASES.md#break-glass-token-expired` を実施 |
| `ZT_VERIFY_SIGNER_PIN_MISSING` | `zt verify` | signer allowlist 未設定 | allowlist を配布して再検証 |
| `ZT_VERIFY_SIGNER_PIN_MISMATCH` | `zt verify` | signer fingerprint 不一致（鍵ローテ/喪失含む） | 鍵喪失/ローテ runbook へ遷移 |
| `ZT_VERIFY_SIGNER_PIN_CONFIG_INVALID` | `zt verify` | signer pin 設定形式不正 | 40/64 hex 形式に修正 |
| `ZT_VERIFY_AUDIT_APPEND_FAILED` | `zt verify` | 監査ログ追記失敗（追跡不能のため fail-closed） | `docs/V0.9.2_ABNORMAL_USECASES.md#audit-trail-append-failed` を実施 |
| `ZT_VERIFY_UNSUPPORTED_INPUT` | `zt verify` | `.spkg.tgz` 以外入力（legacy含む） | `zt verify <packet.spkg.tgz>` に統一 |
| `ZT_SCAN_CHECK_FAILED` | `zt scan` | secure-scan 実行失敗 | stderr / scanner依存関係 / PATH を確認 |
| `ZT_SCAN_TUI_FAILED` | `zt scan --tui` | secure-scan TUI起動失敗 | TTY環境・依存関係・secure-scan 実行可否を確認 |
| `ZT_CONFIG_DOCTOR_FAILED` | `zt config doctor` | config/env/spool等の doctor fail | `zt config doctor --json` の `checks[]` を確認 |
| `policy_team_boundary_signer_split_brain_detected` | `zt config doctor --json` (`checks[].code`) | team boundary signer と verify signer pin の配布ずれ | `docs/V0.9.2_ABNORMAL_USECASES.md#signer-policy-split-brain-detected` を実施 |
| `policy_team_boundary_break_glass_guardrail_weak` | `zt config doctor --json` (`checks[].code`) | break-glass が恒常化しやすい設定 | `docs/V0.9.2_ABNORMAL_USECASES.md#break-glass-guardrail-weak` を実施 |
| `policy_team_boundary_break_glass_env_present` | `zt config doctor --json` (`checks[].code`) | `ZT_BREAK_GLASS_REASON` 常駐で戻し忘れ | `docs/V0.9.2_ABNORMAL_USECASES.md#break-glass-override-left-enabled` を実施 |
| `policy_team_boundary_break_glass_reason_required` | `policy_decision.reason_code` / `quick_fix_bundle.runbook_anchor` | break-glass 理由未指定で緊急解除不可 | `docs/V0.9.2_ABNORMAL_USECASES.md#break-glass-reason-required` を実施 |
| `policy_team_boundary_break_glass_token_invalid` | `zt config doctor --json` (`checks[].code`) | break-glass token 形式不正 | `docs/V0.9.2_ABNORMAL_USECASES.md#break-glass-token-invalid` を実施 |
| `policy_team_boundary_break_glass_token_expired` | `zt config doctor --json` (`checks[].code`) | break-glass token 期限切れ | `docs/V0.9.2_ABNORMAL_USECASES.md#break-glass-token-expired` を実施 |
| `policy_audit_trail_append_unavailable` | `zt config doctor --json` (`checks[].code`) | 監査ログ追記不可/チェーン破損 | `docs/V0.9.2_ABNORMAL_USECASES.md#audit-trail-append-failed` を実施 |
| `ZT_CONFIG_USAGE` | `zt config doctor` / `zt config` | 引数不正 | usageに合わせて再実行 |
| `ZT_CONFIG_UNKNOWN_SUBCOMMAND` | `zt config` | 未対応サブコマンド | `zt config doctor` のみ使用 |

## `secure-pack` 側（供給網/封緘の詳細）

- `SECURE_PACK_ERROR_CODE=SP_ROOT_PIN_MISSING`
- `SECURE_PACK_ERROR_CODE=SP_ROOT_PIN_MISMATCH`
- `SECURE_PACK_ERROR_CODE=SP_TOOLS_LOCK_SIGNATURE_INVALID`
- `SECURE_PACK_ERROR_CODE=SP_TOOL_HASH_MISMATCH`
- `SECURE_PACK_ERROR_CODE=SP_TOOL_VERSION_MISMATCH`
- `SECURE_PACK_ERROR_CODE=SP_SIGNER_PIN_MISSING`
- `SECURE_PACK_ERROR_CODE=SP_SIGNER_PIN_MISMATCH`
- `SECURE_PACK_ERROR_CODE=SP_SIGNER_PIN_CONFIG_INVALID`

## v0.9.2 異常系ユースケース（正本）

`Team Boundary` 運用時の利用不能シーンと復旧手順は次を正本として参照してください。  
`docs/V0.9.2_ABNORMAL_USECASES.md`

## Control Plane event sync（v0.5e 運用固定）

`zt sync --json` は `error_class` / `error_code` を固定出力します。  
現場一次対応は下表だけ見れば判断できるようにします。

| `error_class` | 代表 `error_code` | 意味 | 自動再試行 | 一次対応 |
| --- | --- | --- | --- | --- |
| `none` | `none` | 同期成功（または pending なし） | n/a | 通常運用 |
| `retryable` | `http_503`, `transport_failed`, `sync_backlog_slo_breached` | 5xx / 通信失敗 / backlog SLO超過 | 継続（指数バックオフ） | 監視継続。必要時のみ `zt sync --force --json` |
| `fail_closed` | `envelope.required`, `envelope.key_id_required`, `envelope.key_id_not_allowed` | 署名/鍵設定の契約不一致 | 抑制（`--force` 時のみ再送） | 設定修正後に `zt sync --force --json` |
| `internal` | `internal_failed`, `ingest_ack_mismatch` | spool I/O 障害 / CP ACK 契約不一致 | 停止 | ローカル環境修復、または CP ACK 契約修正 |

補足:

- `ZT_EVENT_SIGNING_KEY_ID` 未設定でも envelope 署名自体は可能ですが、event key registry 有効時は `envelope.key_id_required` で reject されます
- `pending.jsonl` には `first_failed_at` / `last_failed_at` / `error_class` が保存されます
- `fail_closed` は busy loop を避けるため、`--force` なしの自動再試行を行いません

標準手順（sync fail-closed 対応）:

1. `zt sync --json` を実行し、`error_class` / `error_code` を確認
2. `fail_closed` の場合は鍵設定（`ZT_EVENT_SIGNING_KEY_ID` / registry 側許可鍵）を修正
3. 修正後に `zt sync --force --json` を実行し、`ok=true` を確認

## v0.6.0MAX 一次対応フロー

判定順序（固定）:

1. `zt policy status --json --kind extension` / `--kind scan` を実行
2. `set_consistency` が `skew_detected` なら [policy-set-skew-detected](#policy-set-skew-detected) を実施
3. `freshness_state` が `critical` なら [policy-sync-slo-breached](#policy-sync-slo-breached) を実施
4. `zt sync --json` を実行し、`pending_count` / `oldest_pending_age_seconds` / `error_code` を確認
5. `error_code=sync_backlog_slo_breached` なら [sync-backlog-slo-breached](#sync-backlog-slo-breached) を実施
6. `error_code=ingest_ack_mismatch` なら [ingest-ack-mismatch](#ingest-ack-mismatch) を実施

### policy-set-skew-detected

- 症状: `set_consistency=skew_detected`, `sync_error_code=policy_set_skew_detected`
- 一次対応:
  1. CP で extension/scan の publish セット（`policy_set_id`）を揃える
  2. Gateway で `zt sync --force --json` を実行
  3. 再度 `zt policy status --json` で `set_consistency=consistent` を確認

### policy-sync-slo-breached

- 症状: `freshness_state=critical`, `sync_error_code=policy_sync_slo_breached`
- 一次対応:
  1. Control Plane 到達性と keyset/bundle endpoint を確認
  2. `zt sync --force --json` を実行
  3. `last_sync_at` と `freshness_state=fresh|stale` への遷移を確認

### sync-backlog-slo-breached

- 症状: `zt sync --json` で `error_code=sync_backlog_slo_breached`
- 一次対応:
  1. `pending_count` と `oldest_pending_age_seconds` を監視
  2. retryable 失敗（`http_5xx` / `transport_failed`）の継続原因を除去
  3. `zt sync --force --json` で backlog の縮小を確認

### ingest-ack-mismatch

- 症状: `zt sync --json` で `error_code=ingest_ack_mismatch`
- 一次対応:
  1. CP `202` 応答が `endpoint` / `payload_sha256` / `accepted_at` を返すか確認
  2. Gateway-CP 間で body 変換（proxy/filter）が入っていないか確認
  3. 修正後に `zt sync --force --json` で再送成功を確認

## v0.7.0 一次対応フロー（設計反映）

この節は `docs/architecture/V0.7.0_DESIGN.md` に基づく運用更新案です。
実装完了後は以下の順序で固定します。

判定順序（固定）:

1. `zt policy status --json --kind all` で `overall_set_consistency` / `overall_freshness_state` / `critical_kinds` を確認
2. `zt sync --json` で `backlog_slo_seconds` / `backlog_breached` / `backlog_breached_since` / `error_code` を確認
3. `quick_fix_bundle.runbook_anchor` がある場合は該当アンカーに直接遷移する
4. `runbook_anchor` がない場合は本ページの `error_code` 対応節で一次復旧する

### file-type-guard-reason-codes

- 想定トリガ: `ZT_SEND_POLICY_BLOCKED` かつ `reason=policy_magic_mismatch:*`
- 主要 `reason_code`:
  - `expected_pdf`: `.pdf` 拡張子だが PDF シグネチャ不一致
  - `pdf_missing_eof_marker`: PDF 末尾 `%%EOF` が見つからない
  - `expected_text_like`: `.txt/.md/.csv/.json` だが text 判定不可
  - `expected_docx_ooxml` / `expected_xlsx_ooxml` / `expected_pptx_ooxml`: OOXML 必須部品不足
- 一次対応:
  1. ファイル供給元へ再取得を依頼（転送中破損・誤拡張子を除外）
  2. MIME/magic bytes 偽装が疑われる場合は `DENY` 維持で運用レビュー
  3. policy 例外化は変更審査を通すまで禁止（fail-closed 維持）

### policy-scan-posture-violation

- 想定トリガ: `policy_scan_posture_violation`
- 症状:
  - strict 必須 profile（`internal/confidential/regulated`）で degraded 実行が混入
  - `required_scanners` / `require_clamav_db` 契約不一致
- 一次対応:
  1. `policy/scan_policy.toml`（または profile policy）を確認
  2. scanner 実行環境（ClamAV DB / YARA）を復旧
  3. 復旧後に `zt setup --json` と `zt send` を再実行

### policy-set-consistency-reason

- 想定トリガ: `set_consistency!=consistent`
- 代表 reason:
  - `skew_detected`
  - `missing_extension`
  - `missing_scan`
  - `set_id_missing`
- 一次対応:
  1. extension/scan の publish セットを同じ `policy_set_id` に揃える
  2. `zt sync --force --json` 実行
  3. `zt policy status --json --kind all` で収束確認

### sync-backlog-slo-breached-v070

- 想定トリガ: `error_code=sync_backlog_slo_breached` + `backlog_breached=true`
- 一次対応:
  1. `pending_count` と `backlog_breached_since` の推移を監視
  2. `http_5xx` / `transport_failed` の継続要因を除去
  3. `zt sync --force --json` で backlog 減少を確認

### ingest-ack-mismatch-v070

- 想定トリガ: `error_code=ingest_ack_mismatch`
- v0.7.0 確認項目:
  - `ack_schema_version`
  - `canonical_payload_sha256`
- 一次対応:
  1. CP の 202 ACK が canonical hash を返しているか確認
  2. Gateway-CP 間の payload 正規化/改変有無を確認
  3. 修正後に `zt sync --force --json` で再送成功を確認

## Policy Control Loop 一次復旧（v0.5f）

現場での一次対応を `policy_decision` / `error_code` だけで判断できるように固定します。

| 症状 | 代表 `policy_decision.error_code` | 判定 | 一次対応 |
| --- | --- | --- | --- |
| policy 署名不正 / 鍵不一致 | `policy_verify_failed` | fail-closed | `GET /v1/policies/keyset` の active key と Gateway 信頼鍵を確認し、policy を再取得して再適用 |
| policy 期限切れ（confidential/regulated） | `policy_stale` | fail-closed | CP 側で新 policy を publish し、Gateway で fetch/activate。復旧前の送信は停止 |
| policy 期限切れ（internal/public・grace内） | `policy_stale` | degraded | 期限内に更新。grace 超過で fail-closed へ遷移するため前倒しで更新 |
| staged policy 破損 | `policy_activation_verify_failed` | fail-closed | `active` は不変。`last_known_good` へ rollback 済みか確認し、破損 bundle を再配布 |

最短確認コマンド:

```bash
bash ./scripts/ci/check-policy-contract-gate.sh
zt setup --json
zt sync --force --json
```

## `zt setup --json` で見るポイント（supply-chain）

優先チェック:

- `checks[].name == secure_pack_supply_chain_files`
- `checks[].name == secure_pack_root_pubkey_fingerprint`
- `checks[].name == secure_pack_tools_lock_signature`

補助フィールド（`resolved`）:

- `profile`
- `actual_root_fingerprint`
- `pin_source` (`env` / `built-in` / `env+built-in` / `none` / `invalid`)
- `pin_match_count`

互換性リゾルバ（`compatibility`）:

- `status` (`ok` / `warn`)
- `category`（例: `root_pin_mismatch`, `tool_version_mismatch`）
- `environment.os` / `environment.package_source` / `environment.pin_source`
- `fix_candidates[]`（優先順の修復コマンド候補）

## break-glass unlock 運用（trusted signer 必須）

`unlock token` は `ZT_BREAKGLASS_TRUSTED_SIGNERS` が未設定だと有効化されません（fail-closed）。

運用ルール:

- 本番運用では `ZT_BREAKGLASS_TRUSTED_SIGNERS` を必須化する
- 形式は `<signer_id>:<pubkey_b64>` をカンマ区切り（`;` / 改行区切りも可）
- 承認は 2 名以上（`unlock issue` で最低 2 signer 必須）
- token は短い TTL（例: `4h` / `24h`）を原則とし、作業完了後に revoke

設定例:

```bash
export ZT_BREAKGLASS_TRUSTED_SIGNERS="ops1:BASE64_PUBKEY_1,ops2:BASE64_PUBKEY_2"
```

一次対応フロー:

1. `go run ./gateway/zt unlock verify --json` で `active` / `reason` を確認
2. `go run ./gateway/zt setup --json` で `checks[].name=="breakglass_trusted_signers"` を確認
3. `reason=trusted_signers_not_configured` の場合は `ZT_BREAKGLASS_TRUSTED_SIGNERS` を設定
4. `reason=insufficient_valid_approvals` の場合は 2名以上で token を再発行
5. 作業完了後は `go run ./gateway/zt unlock revoke` で token を削除

注意:

- `ZT_BREAKGLASS_ALLOW_EMBEDDED_SIGNERS=1` は緊急回避向け。通常運用では使わない
- token ファイルだけ存在する状態は安全側で `inactive` 判定になる

## dashboard unlock badge の意味（運用判定）

`zt dashboard` / `/api/status` の `unlock.badge` は以下で固定。

| badge | UI表示 | 意味 | 一次対応 |
| --- | --- | --- | --- |
| `active` | 有効 | trusted signer 固定 + 2承認以上 + 期限内 | 解除作業を実施し、終了後 revoke |
| `pending` | 解除申請中 | token はあるが有効承認が不足 | 2名承認で再発行し verify |
| `expired` | 期限切れ | token の有効期限超過 | 新規 issue（期限短め） |
| `inactive` | 無効 | trusted signer 未設定/署名不整合など | `unlock verify --json` の `reason` を解消 |
| `none` | 未設定 | token 未配置 | 平常運用（解除不要） |

確認コマンド:

```bash
go run ./gateway/zt dashboard
# または
go run ./gateway/zt dashboard --json | jq '.unlock'
```

## dashboard danger / local lock 運用

`zt dashboard` / `/api/status` は `danger` と `lock` を固定出力します。

- `danger.level`: `high` / `medium` / `low`
- `danger.signals[]`: 危険信号コード一覧（原因トリアージの起点）
- `lock.locked=true`: 送信系を手動停止中（`zt send` / `zt relay` は fail-closed）

既定 lock ファイル:

- `<repo>/.zt-spool/local-lock.json`
- 変更時: `ZT_LOCAL_LOCK_FILE`

主要 danger signal 例:

| code | 重大度 | 意味 | 一次対応 |
| --- | --- | --- | --- |
| `local_lock_active` | high | 手動ロック中 | 解除条件を満たしたら dashboard から unlock |
| `secure_pack_supply_chain_files_missing` | high | `tools.lock` など不足 | supply-chain 必須ファイルを復旧 |
| `tools_lock_signature_unverified` | high | `tools.lock.sig` 未検証/失敗 | root key / signature を再検証 |
| `root_pin_mismatch` | high | root pin 不一致 | pin 配布値と `ROOT_PUBKEY` を照合 |
| `policy_freshness_critical` | high | policy鮮度がcritical | CP同期と policy fetch を復旧 |
| `receipt_tamper_detected` | high | verify receipt が改ざん検知 | 対象受領物を隔離し再受領 |

ロック操作（dashboard API 直接呼び出し例）:

```bash
# lock
curl -sS -X POST http://127.0.0.1:8787/api/lock \
  -H 'content-type: application/json' \
  -d '{"action":"lock","reason":"incident triage"}'

# unlock
curl -sS -X POST http://127.0.0.1:8787/api/lock \
  -H 'content-type: application/json' \
  -d '{"action":"unlock","reason":"incident closed"}'
```

送信系の停止確認:

```bash
go run ./gateway/zt send --client clientA ./safe.txt
# => ZT_ERROR_CODE=ZT_LOCAL_LOCK_ACTIVE
```

## relay drive: Google Drive API 直upload 手順

`relay drive` は 2経路をサポート:

- ローカル同期フォルダへの handoff（`--folder`）
- Google Drive API への直接 upload（`--api-upload`）

API upload 前提:

- OAuth access token を取得（Drive upload 可能 scope）
- 必要時のみ `--drive-folder-id` を指定（未指定時は My Drive 直下）
- token は `--oauth-token` または `ZT_GOOGLE_DRIVE_ACCESS_TOKEN`

最短手順:

```bash
export ZT_GOOGLE_DRIVE_ACCESS_TOKEN="<oauth_access_token>"

go run ./gateway/zt relay drive \
  --packet ./bundle_clientA_20260224T120000Z.spkg.tgz \
  --api-upload \
  --drive-folder-id "<google_drive_folder_id>" \
  --write-json
```

併用手順（同期フォルダ + API）:

```bash
go run ./gateway/zt relay drive \
  --packet ./bundle_clientA_20260224T120000Z.spkg.tgz \
  --folder "$HOME/Google Drive/My Drive/zt-share" \
  --api-upload \
  --drive-folder-id "<google_drive_folder_id>" \
  --write-json
```

出力確認:

- API upload 成功時は `api_packet_id` / `api_verify_id`（`--write-json` 時は `api_share_json_id`）が表示される
- `--folder` 併用時は `drive_packet` / `verify_text` / `share_json` のローカルパスが表示される

代表エラー切り分け:

- `--oauth-token or ZT_GOOGLE_DRIVE_ACCESS_TOKEN is required`  
  token 未設定。env または flag を設定
- `drive upload failed: status=401/403`  
  token期限切れ / scope不足 / folder権限不足
- `drive upload response missing id`  
  API応答異常。レスポンス本文と Google 側設定を確認

補足:

- `--api-upload` 未指定時は `--folder` 必須（ローカル handoff モード）
- upload 対象は packet 本体 + `*.verify.txt` + `*.share.json`（`--write-json=true` 時）

## relay auto-drive 運用（watch -> send -> drive）

`relay auto-drive` は watch フォルダ内の通常ファイルを順次処理します。

- 入力: plaintext 元ファイル
- 実行: `zt send --share-json` で packet 生成、続けて `relay drive` 実行
- 成功時: 元ファイルを `.zt-done/` へ移動
- 失敗時: 元ファイルを `.zt-error/` へ移動
- 部分書き込み対策: `--stable-window` 経過後のみ処理開始
- 再試行: `--max-retries` / `--retry-backoff` で指数バックオフ
- 重複送信抑止: `--dedup-ledger`（既定: `.zt-spool/relay-auto-drive-dedup.jsonl`）

最小実行:

```bash
go run ./gateway/zt relay auto-drive \
  --client clientA \
  --watch-dir ./dropbox/send-queue \
  --folder "$HOME/Google Drive/My Drive/zt-share" \
  --poll-interval 5s \
  --stable-window 3s \
  --max-retries 3 \
  --retry-backoff 5s
```

バッチ1回実行:

```bash
go run ./gateway/zt relay auto-drive \
  --client clientA \
  --watch-dir ./dropbox/send-queue \
  --folder "$HOME/Google Drive/My Drive/zt-share" \
  --once
```

注意:

- `zt send` が実行されるため、local lock が有効なら fail-closed で停止
- `*.spkg.tgz` / `*.verify.txt` / `*.share.json` は watch 対象から除外
- `--max-retries` を超えたファイルは `.zt-error/` へ移動

## relay hook 運用（拡張/外部連携）

`relay hook` は、将来の OS 拡張・ブラウザ拡張と繋ぐためのローカルブリッジです。

- `relay hook wrap`: 単発ファイルをCLIからラップ
- `relay hook finder-quick-action`: Finderで選択した複数ファイルを一括ラップ
- `relay hook serve`: HTTP API (`/v1/wrap`) を公開

起動例:

```bash
export ZT_RELAY_HOOK_TOKEN="<long_random_token>"
go run ./gateway/zt relay hook serve --client clientA --addr 127.0.0.1:8791
```

API 呼び出し例:

```bash
curl -sS -X POST http://127.0.0.1:8791/v1/wrap \
  -H "Authorization: Bearer ${ZT_RELAY_HOOK_TOKEN}" \
  -H "content-type: application/json" \
  -d '{"path":"./sample.txt","client":"clientA","share_format":"ja"}'
```

Finder Quick Action (macOS) 運用:

1. Quick Action 自動登録を実行

```bash
go run ./gateway/zt relay hook install-finder \
  --client clientA \
  --share-format auto \
  --force-public \
  --force \
  --json
```

2. 設定だけ更新したい場合は `configure-finder` を実行（workflow再作成なし）

```bash
go run ./gateway/zt relay hook configure-finder \
  --client clientA \
  --share-format auto \
  --force-public \
  --json
```

force-public 運用方針（repo guard）:

- `mt4110/zt-gateway` は Public リポジトリのため、当面は `--force-public` を有効化して運用
- 本番推奨は private/internal リポジトリへ移行し、`--force-public` を外して fail-closed を維持
- 移行完了後は Finder Quick Action 設定（`~/.config/zt/finder-quick-action.env`）から `ZT_RELAY_HOOK_FORCE_PUBLIC` を削除/0化

3. 生成物を確認

```bash
ls -la ~/.config/zt/finder-quick-action.env
ls -la ~/.local/share/zt/finder-quick-action/run.sh
ls -la ~/Library/Services/"ZT Wrap via Relay Hook.workflow"
```

`/v1/wrap` API 固定契約（v1）:

- Request JSON: `path`(required), `client`(optional if default), `share_format`(auto|ja|en)
- Success JSON: `api_version`, `ok`, `source_path`, `packet_path`, `share_format`, `verify_command`, `receipt_out?`, `receipt_command?`
- Error JSON: `api_version`, `ok=false`, `error_code`, `error`, `input?`

エラーコード runbook:

- `method_not_allowed`: 呼び出しメソッドを `POST /v1/wrap` に修正
- `unauthorized`: `Authorization: Bearer <token>` と `ZT_RELAY_HOOK_TOKEN` の一致確認
- `invalid_json`: JSON構文、未知フィールド、末尾ゴミを除去
- `missing_path`: request body に `path` を設定
- `missing_client`: request body `client` か、serve起動時 `--client` を設定
- `invalid_share_format`: `share_format` を `auto|ja|en` のいずれかに修正
- `wrap_failed`: `zt send` 相当の失敗。`zt send --client <name> <file>` を単体実行して原因切り分け
- `local_lock_active`: `zt dashboard` または `zt unlock` runbookで lock 状態を解消

注意:

- token 未設定時は無認証になるため、本番運用では `ZT_RELAY_HOOK_TOKEN` を必須化
- local lock 有効時は `/v1/wrap` も fail-closed で `423 Locked`

## CI ゲート（標準）

fixtureゲート（ロジック回帰検知）:

- `scripts/ci/check-zt-setup-json-gate.sh`
- 固定署名fixtureで `zt setup --json` を実行し、supply-chain 3項目の `ok` を検証
- policy 契約は `scripts/ci/check-policy-contract-gate.sh` で独立実行（bundle署名 / keyset / activation / decision / policy e2e）

actual repo ゲート（実artifact直検査）:

- `scripts/ci/check-zt-setup-json-actual-gate.sh`
- `tools/secure-pack/tools.lock` / `tools.lock.sig` / `ROOT_PUBKEY.asc` が存在する場合は fail-closed
- `ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS` 未設定時は `fail`
- `ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS_EXPECTED` が設定されている場合:
  - `ROOT_PUBKEY.asc` から解決した fingerprint が expected pins に含まれることを検証
  - 検証成功時のみ `ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS` を自動bootstrap
- ローカル pre-push では `ZT_PREPUSH_AUTO_EXPECTED_PIN_BOOTSTRAP=1` を付けると、
  `ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS*` 未設定時に `ROOT_PUBKEY.asc` から expected pin を一時自動設定できる（one-trust 簡易運用）
- `ZT_SECURE_PACK_ALLOW_LOCAL_PIN_BOOTSTRAP=1` はローカル簡易運用向け（同一repo起点のため zero-trust 強度は下がる）
- 判定優先順位は `gate必須項目 > zt setup --json 全体ok`（`setup_ok` / `error_code` は informational）
- スクリプト出力の `gate_ok=true|false|skipped` を一次判定に使う（`skipped` は必須ファイル欠落時）
- `resolved.pin_match_count >= 1` を必須化
- `ZT_BIN=/path/to/linux-zt` を指定すると、`go build` の代わりに既存バイナリで実行可能（Ubuntu コンテナ検証用）

注意（重要）:

- `tools.lock` の `tar_sha256` / `tar_version` は OS 依存です
- macOS は通常 `bsdtar`、GitHub Actions `ubuntu-latest` は通常 GNU tar のため、macOS で生成した `tools.lock` は CI actual repo ゲートで失敗する可能性があります
- CI green を狙う場合は、Ubuntu/Linux 環境で `tools.lock` を生成・署名してください

## 監査証跡MVP（v0.5-A）運用確認

監査ログは append-only の JSONL として `events.jsonl` に記録されます。

- 既定パス: `<repo>/.zt-spool/events.jsonl`
- 変更時: `ZT_EVENT_SPOOL_DIR` を使っている場合は `<ZT_EVENT_SPOOL_DIR>/events.jsonl`

最小必須フィールド（契約）:

- `event_id`
- `event_type`
- `timestamp`
- `result`
- `endpoint`
- `payload_sha256`

ローカル確認例:

```bash
tail -n 20 ./.zt-spool/events.jsonl | jq .
```

`send -> verify` 監査確認例:

```bash
jq -r '.event_type' ./.zt-spool/events.jsonl | sort | uniq -c
```

## 契約テストと担保範囲（v0.5-A 追加）

- `TestAuditEventsJSONL_SchemaContract`  
  `events.jsonl` の required fields と `payload_sha256` 算出契約を担保
- `TestAuditEventsJSONL_ResultFallbackContract`  
  `result` 欠落時のフォールバック（`recorded`）契約を担保
- `TestShareJSONToVerifyToReceipt_AuditE2EContract`  
  既存 `send -> verify` 導線で監査ログに `send` / `verify` が各1件出るE2E契約を担保
- `scripts/ci/check-zt-contract-gate.sh`  
  上記監査契約テストを CI 実行対象として明示

## 契約テストと担保範囲（v0.5-B 追加: 監査改ざん検知）

- `TestAuditEventsJSONL_ChainContract`  
  `prev_record_sha256` / `record_sha256` の連結ハッシュ契約を担保
- `TestAuditEventsJSONL_SignatureContract`  
  `ZT_AUDIT_SIGNING_ED25519_PRIV_B64` 有効時の監査レコード署名契約を担保
- `TestShareJSONToVerifyToReceipt_AuditVerifyE2EContract`  
  `send -> verify` 導線で監査ログ全体のチェーン+署名検証が通る E2E 契約を担保
- `TestAuditVerifyE2EContract_DetectsTamper`  
  監査ログ改ざん時に検証失敗となる契約を担保
- `scripts/ci/check-zt-contract-gate.sh`  
  v0.5-B 契約テストを CI 実行対象として明示

## GitHub Actions Variable 配布（`ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS`）

fingerprint は秘密値ではない前提のため、GitHub Actions `Variables` を推奨します（`Secrets` は fallback）。

1コマンド bootstrap（推奨）:

```bash
# 推奨: 承認済み pins を明示
bash ./scripts/dev/bootstrap-ci-root-pin-expected.sh --expected-pins "OLD_FPR_40HEX,NEW_FPR_40HEX"

# One-trust（ローカル ROOT_PUBKEY 依存）
bash ./scripts/dev/bootstrap-ci-root-pin-expected.sh --trust-local-root-key

# ローカル shell へ export だけしたい場合（gh 不要）
eval "$(bash ./scripts/dev/bootstrap-ci-root-pin-expected.sh --trust-local-root-key --print-env)"
```

ローカル pre-push で毎回 export を省略する場合:

```bash
ZT_PREPUSH_AUTO_EXPECTED_PIN_BOOTSTRAP=1 bash ./scripts/ci/check-pre-push-readiness.sh
```

`gh` CLI（手動運用時）:

```bash
gh variable set ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS_EXPECTED \
  --repo mt4110/zt-gateway \
  --body "OLD_FPR_40HEX,NEW_FPR_40HEX"
```

直接 pin を渡す運用（従来）:

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
- control-plane の event envelope 署名鍵（`/v1/admin/event-keys`）をローテーションする場合は `docs/EVENT_KEY_ROTATION_RUNBOOK.md` に従う（併存72h / 切替完了24h静穏 / delete保留7日）

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
