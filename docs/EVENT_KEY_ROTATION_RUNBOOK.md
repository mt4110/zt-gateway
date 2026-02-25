# Control Plane Event Key Rotation Runbook

`/v1/admin/event-keys` のローテーション運用を fail-closed で固定するための手順です。  
本Runbookは **event envelope署名鍵（`key_id`）** の切替を対象にします。

## 固定ポリシー（v0.5d-3）

- 旧鍵/新鍵 併存最小期間: **72時間**
- 切替完了（静穏）判定: **旧鍵での verified ingest が直近24時間で 0 件**
- 旧鍵 delete 保留期間: **disable 実施後 7日間**

上記は API 側でも強制されます。

## 前提

- Postgres 有効化済み（`event_signing_keys` / `event_ingest` を利用）
- 新鍵を `enabled=true` で登録済み
- 送信側が新 `key_id` で署名可能（`ZT_EVENT_SIGNING_KEY_ID=<new-key-id>`）

## 標準手順

1. 新鍵を登録（有効化）

```bash
curl -sS -X POST "http://127.0.0.1:8080/v1/admin/event-keys" \
  -H "Content-Type: application/json" \
  -d '{"key_id":"evk_2026q1","tenant_id":"tenant-a","public_key_b64":"<BASE64_PUBKEY>","enabled":true,"updated_by":"ops","reason":"rotation add"}'
```

2. 送信側を新鍵へ切替（併存開始）
- `ZT_EVENT_SIGNING_KEY_ID` を新鍵へ変更
- 旧鍵はまだ disable しない（併存期間を確保）

3. 切替 readiness を確認

```bash
curl -sS "http://127.0.0.1:8080/v1/admin/event-keys/evk_old/rotation-status?replacement_key_id=evk_2026q1" | jq .
```

確認ポイント:
- `checks.ready_disable == true` になるまで待機

4. 旧鍵を disable

```bash
curl -sS -X DELETE "http://127.0.0.1:8080/v1/admin/event-keys/evk_old?mode=disable&replacement_key_id=evk_2026q1&updated_by=ops&reason=rotation_disable"
```

5. delete readiness を確認（7日保留）

```bash
curl -sS "http://127.0.0.1:8080/v1/admin/event-keys/evk_old/rotation-status?replacement_key_id=evk_2026q1" | jq .
```

確認ポイント:
- `checks.ready_delete == true`

6. 旧鍵を delete

```bash
curl -sS -X DELETE "http://127.0.0.1:8080/v1/admin/event-keys/evk_old?mode=delete&replacement_key_id=evk_2026q1&updated_by=ops&reason=rotation_delete"
```

## Gateway 側 cutover 確認（v0.5e）

rotation 中の `zt sync --json` 判定は以下で固定します。

1. 併存期間（旧鍵/新鍵とも許可）:
   - 旧 `key_id` でも `zt sync --force --json` が `ok=true` で通ること
2. 切替完了後（旧鍵 disable 後）:
   - 旧 `key_id` は `error_class=fail_closed`, `error_code=envelope.key_id_not_allowed` になること
3. 送信側を新 `key_id` に更新後:
   - `zt sync --force --json` が `ok=true` に戻ること

例:

```bash
zt sync --force --json | jq '{ok,error_class,error_code,sent,remaining}'
```

## 代表的な拒否エラー（契約）

- `replacement_key_id_required`
- `replacement_key_id_must_differ`
- `rotation_replacement_key_not_enabled`
- `rotation_coexistence_period_not_elapsed`
- `rotation_switch_not_complete`
- `event_key_delete_requires_disabled`
- `event_key_delete_hold_not_elapsed`

## Rollback（切替後問題時）

1. 旧鍵を再有効化

```bash
curl -sS -X PATCH "http://127.0.0.1:8080/v1/admin/event-keys/evk_old" \
  -H "Content-Type: application/json" \
  -d '{"enabled":true,"updated_by":"ops","reason":"rotation rollback"}'
```

2. 送信側 `ZT_EVENT_SIGNING_KEY_ID` を旧鍵へ戻す
3. 事象収束後、再度本Runbookの Step 3 から実施
