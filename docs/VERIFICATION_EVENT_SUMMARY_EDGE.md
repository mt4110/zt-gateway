# LeakFence向けの要約専用origin

既存の要約APIに、認可結果をWorkerへ渡すためのopt-in起動モードを追加する。
通常起動のAPI応答は変更しない。

## 起動設定

- `ZT_CP_SUMMARY_EDGE_ONLY=1`
- `ZT_CP_SUMMARY_EDGE_SECRET`：paddingなしbase64urlのランダム32-byte接続鍵
- `ZT_CP_SUMMARY_AUTHORITY_KEY`：別のランダム32-byte HMAC鍵
- 既存SSO設定、署名鍵レジストリ、PostgreSQL設定
- `ZT_CP_ADDR`：専用のprivate/loopback listener

片方の鍵だけ、同じ鍵、モード指定なしの鍵設定などは起動時に拒否する。
専用インスタンスは `GET /v1/verification-events/{ingest_id}/summary` だけを受け付ける。
通常の取り込み・管理・詳細APIは別の非公開インスタンスで運用する。

クライアントに接続鍵を渡さない。Workerはクライアントのヘッダーを転送せず、新しく次を付ける。

- `Authorization`：利用者のSSO JWT
- `X-ZT-Edge-Secret`：接続鍵
- `X-ZT-Read-Nonce`：要求ごとに新しい128-bitランダム値のhex

JWTを持っていても接続鍵がなければ401。DBを読む前に拒否する。
JWT認証・tenantで絞るSQL・取得行の再確認に成功した後に限り、
`X-ZT-Read-Authority` を発行する。このヘッダーは公開応答へ転送しない。

認可結果は30秒期限、nonce、パス、issuerとsubjectに基づく主体識別子、JWTのtenant、
固定permission、一件の認可済みingest_idを含む。検査対象のJSON本文から生成しない。
形式は `base64url(JSON).base64url(HMAC-SHA-256("zt-summary-authority-v1." + base64url(JSON)))`。
このHMACはファイル検証や本文の安全性の証明ではない。

通常のControl Plane、DB、接続鍵を別経路で公開すればLeakFenceを迂回できる。
全APIの保護や管理者・ホスト侵害への防御を約束しない。
permissionは接続契約の識別子であり、JWTへ新しい権限を付与しない。
同一tenantでの閲覧であり個人所有者のACLではない。SCIMによるtenant補完は行わない。

## 検証

```sh
go test ./control-plane/api/... -count=1
```

専用入口の経路制限、接続鍵のない直接要求の拒否、認可結果のMACとscope、設定不備を確認する。
既存要約APIのJWT・DB異常系試験も維持する。

LeakFence側の `npm run validate:zt -- /absolute/path/to/zt-gateway` は
新しいローカルPostgreSQLを作り、`TestVerificationSummaryEdgeFixture` を限定起動する。
fixtureは実取り込み・SSO・SQLと本番用の専用ハンドラーを使う。起動方法だけがhttptestのloopback server。
故障注入はローカルfixtureファイルだけで選び、本番のHTTP入力から利用できない。
本番DB・実イベント・実認証鍵へ接続しない。
fixtureは終了または20分で停止し、テストデータの削除・既存DBの変更は行わない。

Cloudflareへの配置・公開は別途承認された範囲に限る。
[LeakFenceの接続手順](https://github.com/mt4110/leak-fence/blob/feat/zt-gateway-validation/docs/ZT_GATEWAY_INTEGRATION.md) に
Worker・秘密設定・停止・証拠の手順がある。
