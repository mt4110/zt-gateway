# zt-gateway v1.0 実装ブループリント (確定版)

## 0. この文書の位置づけ

この文書は、次スレから実装を開始するための確定設計である。
対象は次の4点。

- 設計方針
- 詳細設計 (CLI契約 / JSON契約 / ログ契約)
- 実装手順
- マイルストーンとExit Criteria

関連:

- `docs/STRATEGY_PLAN_V1.0.md`
- `docs/COMPETITIVE_EVALUATION_V1.0.md`

## 1. 設計原則 (固定)

1. Fail-closed を崩さない
2. 既存導線へ寄生し、利用者に新しい操作を強要しない
3. 機械可読の証跡を標準化し、人間向け表示は1行で完結させる
4. OS/配布差分は製品が吸収し、利用者には修復コマンドだけを返す
5. v1.0は「実運用価値」を優先し、先進機能は v1.x に段階分離する

## 2. スコープ確定

## v1.0 に入れる

- Trust Status Line (主要経路で1行安全表示)
- Verification Receipt (`zt verify --receipt-out`)
- Trust Profiles (`--profile`)
- Safe Failure Envelope (`quick_fix_bundle`)
- 監査証跡MVP (send/verifyイベント)
- Cloud-Agnostic Wrapper の最小実装 (Slack/メール向け固定テンプレ)
- 互換性リゾルバ (pin/tar差分の説明 + 環境別修復案)

## v1.x へ送る

- 受信側ブラウザ完結検証の本番運用
- Device-Bound Ephemeral Files
- ブロックチェーン打刻
- Smart File Contract の高次条件 (Wi-Fi, IdP属性, ハードウェア拘束の高度化)

## 3. 詳細設計

## 3.1 Trust Status Line

### 対象コマンド

- `zt send`
- `zt verify`
- `zt setup --json` (要約表示)

### 表示契約

- 成功時:
  - `TRUST: verified=true tamper=false policy=pass receipt=<id>`
- 失敗時:
  - `TRUST: verified=false tamper=unknown policy=fail reason=<error_code>`

### 実装メモ

- 既存 `ZT_ERROR_CODE` と整合
- 人間向け最終行として常時出力

## 3.2 Verification Receipt

### CLI

- `zt verify <artifact> --receipt-out <path>`
- `--receipt-out` 未指定時は標準出力に要約のみ

### JSON契約 (v1)

```json
{
  "receipt_version": "v1",
  "receipt_id": "uuid-or-hash",
  "verified_at": "RFC3339",
  "artifact": {
    "path": "string",
    "sha256": "hex"
  },
  "verification": {
    "signature_valid": true,
    "tamper_detected": false,
    "policy_result": "pass"
  },
  "provenance": {
    "sender": "string",
    "client": "string",
    "key_fingerprint": "40HEX"
  },
  "tooling": {
    "zt_version": "string",
    "secure_pack_version": "string"
  }
}
```

### 互換方針

- `receipt_version` で将来拡張
- 既存 `--share-json` に `receipt_hint` フィールドを追加可能にする

## 3.3 Trust Profiles

### CLI

- `zt send --profile public|internal|confidential|regulated`
- `zt setup --profile <name>`

### 意味

- `public`: 共有優先、最低限の検査
- `internal`: 標準運用
- `confidential`: 厳格ポリシー + 監査強化
- `regulated`: 監査必須 + 失敗時強制停止

### 実装方針

- 既存 policy ファイル群を profile 名で解決
- 解決結果は `resolved.profile` として JSON に露出

## 3.4 Safe Failure Envelope

### JSON契約

```json
{
  "error_code": "ZT_*",
  "summary": "string",
  "quick_fix_bundle": {
    "why": "string",
    "commands": ["cmd1", "cmd2"],
    "runbook": "docs/...",
    "retry": "full command"
  }
}
```

### 実装方針

- 既存 `quick_fixes[]` を束ねて再実行可能な形式に正規化
- Helpdesk はこのbundleだけで一次対応可能にする

## 3.5 監査証跡MVP

### 出力先

- ローカル append-only ログ (JSONL)
- 初期パス: `.zt-spool/audit/events.jsonl`

### イベント種別

- `send_started`
- `send_completed`
- `verify_completed`
- `verify_failed`

### 最小フィールド

- `event_id`, `event_type`, `timestamp`
- `receipt_id` (あれば)
- `client`, `artifact_hash`, `result`, `error_code`

## 3.6 互換性リゾルバ

### 対象課題

- root pin mismatch
- tar実装差分に起因する `tools.lock` 不一致

### 出力

- 原因カテゴリ
- 現在環境 (`os`, `package_source`, `pin_source`)
- 修復コマンド候補 (優先順)

### 例

- `fix_candidates[0]`: Linux CI 向け再生成手順
- `fix_candidates[1]`: ローカル検証のみ回避手順

## 3.7 Cloud-Agnostic Wrapper (最小)

### 目的

既存クラウドを置換せず「土管化」する。

### v1.0実装

- `--share-json` 固定契約を維持
- Slack/メール貼り付け向けテンプレートを `text` に同梱
- 共有データは復号不能ペイロード + 検証コマンドを標準化

## 4. 実装手順 (次スレ開始順)

1. 契約固定: Trust Status Line / Receipt / Failure Envelope のschemaを先に確定
2. `zt verify --receipt-out` 実装 + テスト
3. Trust Status Lineを `send/verify/setup` に導入
4. 互換性リゾルバを `zt setup --json` に統合
5. Trust Profiles を実装し既存policyへ接続
6. 監査証跡MVP (JSONL append-only) 実装
7. `--share-json` テンプレ強化 (Slack/メール)
8. ドキュメント更新 (OPERATIONS / README / runbook)

## 5. マイルストーン (確定)

| Milestone | 主目的 | 主要成果 | Exit Criteria |
| --- | --- | --- | --- |
| M1: v0.3 | 無意識UXの土台 | Status Line, Failure Envelope, 互換性修復案 | 初回送信成功率 80%以上 |
| M2: v0.5 | 業務導線統合 | Receipt, 監査証跡MVP, Cloud Wrapper最小 | 問い合わせ件数 v0.3 比 40%削減 |
| M3: v1.0 | 製品化 | Trust Profiles, 運用標準化, 主要導線完成 | 初回実行成功率 90%以上 |

## 6. テスト戦略

- 契約テスト: JSON schema snapshot (receipt / failure envelope / share-json)
- 回帰テスト: `zt setup --json` gate に status/profile フィールドを追加
- E2E: sender -> share -> receiver verify -> receipt 生成 -> audit記録
- 異常系: pin mismatch, signature invalid, policy deny, scanner failure

## 7. 運用準備物 (v1.0までに必須)

- `docs/OPERATIONS.md` への新エラー/修復束追記
- 受信者向け1ページ手順 (検証 + レシート提出)
- ポリシー配布手順 (canary -> default)
- 鍵ローテーションrunbookとの整合確認

## 8. 未決事項 (実装開始前に凍結)

1. Receipt の `receipt_id` 生成方式 (UUIDか内容ハッシュか)
2. 監査ログの保持期間とローテーション方式
3. Trust Profiles の初期ポリシー閾値
4. 互換性修復コマンドのOS別優先順位

## 9. 次スレ開始テンプレート

次スレでは以下を最初の実装対象にする。

- タスクA: `zt verify --receipt-out` 実装
- タスクB: Trust Status Line の統一出力
- タスクC: Failure Envelope のJSON契約化

この3タスクが完了すれば、差別化の核である「証拠付き検証 + 無意識UX」の最小成立ができる。
