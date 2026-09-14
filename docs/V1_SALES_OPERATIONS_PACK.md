# V1 Sales Operations Pack (LFC-1012)

初回導入説明をこの 1 ドキュメントだけで完結できるようにした運用パックです。  
対象: セールス同席デモ、導入前レビュー、初期運用引き継ぎ。

## 1. 導入チェックリスト（初回 30 分）

- [ ] Local SoR を有効化した `zt` が起動できる（`go run ./gateway/zt setup --json` が pass）
- [ ] tenant 固定運用値を決める（`ZT_DASHBOARD_TENANT_ID`）
- [ ] 認証方式を決める（`ZT_CP_API_KEY` または `ZT_CP_SSO_ENABLED=1`）
- [ ] MFA/Passkey を有効化する（`ZT_CP_WEBAUTHN_ENABLED=1`）
- [ ] event 署名検証を有効化する（`ZT_CP_EVENT_VERIFY_PUBKEY_B64` または event key registry）
- [ ] ダッシュボード API の tenant 境界を確認する（tenant 不一致が `tenant_scope_violation`）
- [ ] Key Repair の runbook 導線を確認する（`docs/OPERATIONS.md`）
- [ ] 外部通知を使う場合だけ明示有効化する（`ZT_DASHBOARD_ALERT_DISPATCH_ENABLED=1`）

## 2. Security Note（販売説明用）

- デフォルトは Local-First。外部送信なしで運用可能。
- fail-closed を基本方針とし、設定不足時は処理を拒否する。
- tenant 境界違反は API レベルで拒否し、横断参照を防止する。
- 外部通知はデフォルト OFF。利用時も HTTPS + allowlist + 最小 payload を強制する。
- 監査ログ（`.zt-spool/events.jsonl`）に重要操作と通知 dispatch 成否を記録する。

## 3. Runbook（最短運用手順）

1. 初期健全性確認

```bash
go run ./gateway/zt setup --json
go run ./gateway/zt dashboard --json | jq '.danger,.lock,.alerts,.kpi'
```

2. Local dashboard API 疎通確認

```bash
curl -s "http://127.0.0.1:8787/api/clients?tenant_id=<TENANT_ID>&page=1&page_size=10" | jq .
curl -s "http://127.0.0.1:8787/api/keys?tenant_id=<TENANT_ID>&page=1&page_size=10" | jq .
curl -s "http://127.0.0.1:8787/api/signature-holders?tenant_id=<TENANT_ID>" | jq .
```

3. 異常時の標準導線

- lock/unlock/break-glass は dashboard から実施し、incident 監査記録を確認
- Key Repair は `detected -> contained -> rekeyed -> rewrapped -> completed` を追跡
- 詳細 runbook は `docs/OPERATIONS.md` と `docs/V0.9.2_ABNORMAL_USECASES.md` を参照

## 4. 5分デモ手順（営業同席テンプレ）

1. `zt dashboard` を開き、`danger` と `alerts` が `low` から開始することを示す
2. `send/verify` を 1 回実行し、`kpi.verify_receipts_total` が増えることを示す
3. `/api/clients` と `/api/signature-holders` で tenant ごとの可視化を示す
4. 鍵を `compromised` へ遷移し、`danger=high` と Key Repair 起票を示す
5. `/api/alerts/dispatch` を dry-run で実行し、安全ゲート（allowlist/HTTPS）を説明する
6. 監査ログに dispatch 結果が残ることを示して終了する

## 5. デモ前の固定確認（失敗防止）

- `bash ./scripts/ci/check-v100-commercial-gate.sh` が pass
- `go test ./gateway/zt -count=1` が pass
- `go test ./control-plane/api/cmd/zt-control-plane -count=1 -run 'Dashboard|WebAuthn|StepUp|ControlPlaneSSO'` が pass

