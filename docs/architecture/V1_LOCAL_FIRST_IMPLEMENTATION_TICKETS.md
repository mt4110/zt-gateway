# V1 Local-First Implementation Tickets

確認日: 2026-02-27

関連:
- `docs/architecture/V1_LOCAL_FIRST_COMMERCIAL_DESIGN.md`
- `docs/V1_IMPLEMENTATION_BLUEPRINT.md`

## 0. 進め方（固定）

1. v1.0 を「販売可能MVP」として先に収束させる
2. v1.1 は運用拡張（精度/自動化）
3. v1.2 は大規模対応とモバイル認証統合

完了条件（各バージョン共通）:
- 契約テスト + 回帰テスト + 運用runbook更新
- fail-closed要件を壊さない
- tenant分離の自動検証がある

## 1. v1.0 Ticket Set（販売可能MVP）

### LFC-1001: Local SoR（SQLite暗号化）
- 目的: 端末一次記録をローカルで完結
- 実装: `gateway/zt` に local DB層追加（assets/keys/exchanges/incidents）
- 受け入れ条件:
  - DB未初期化時に自動bootstrap
  - 暗号化OFFで起動不可（dev mode除く）

### LFC-1002: Tenant必須化
- 目的: マルチテナント分離を型レベルで固定
- 実装: 主要イベント/台帳へ `tenant_id` 非NULL制約
- 受け入れ条件:
  - tenant欠落リクエストがfail-closed
  - 既存dashboard APIがtenant違反を拒否

### LFC-1003: SSO(OIDC/SAML)基盤
- 目的: 企業導入の主認証
- 実装: CP auth middleware + token検証 + role claim連携
- 受け入れ条件:
  - viewer/operator/admin/auditor が機能
  - SSO未設定時は安全なローカル緊急導線のみ

### LFC-1004: Passkey/WebAuthn 二段目認証
- 目的: 生体(顔/指紋)をOS経由で利用
- 実装: WebAuthn challenge/attestation/assertion
- 受け入れ条件:
  - 管理操作（鍵操作/incident）にstep-up MFA適用
  - 認証失敗は操作不可

### LFC-1005: クライアント別資産ビュー
- 目的: 「何がどこにあるか」を即時確認
- 実装: client detail API/UI（file list, location, created_at, last_seen)
- 受け入れ条件:
  - client単位でページング・検索・CSV export
  - tenant跨ぎの閲覧不可

### LFC-1006: 鍵ライフサイクル可視化
- 目的: 鍵状態の運用判断を短縮
- 実装: key status API/UI（active/rotating/revoked/compromised）
- 受け入れ条件:
  - 状態遷移が監査ログに残る
  - compromised時に自動danger high

### LFC-1007: Key Repair MVP（壊れた鍵の修復）
- 目的: 鍵事故復旧を製品機能化
- 実装: recovery job（detect -> contain -> rekey -> rewrap）
- 受け入れ条件:
  - runbook ID付き監査証跡
  - 復旧完了まで危険状態を可視化

### LFC-1008: 利用回数/KPI集計
- 目的: 営業/運用で説明可能な成果指標
- 実装: exchanges集計（送受信回数、verify成功率、backlog）
- 受け入れ条件:
  - dashboard KPIとAPI値が一致
  - tenant別のSLO表示

### LFC-1009: 署名保有者数（MVP）
- 目的: 「何人が署名データを持つか」の可視化
- 実装: 配布イベント + receipt ACK 推定集計
- 受け入れ条件:
  - estimated count をクライアント別に表示
  - 算出根拠（イベント件数）を追跡可能

### LFC-1010: 外部通知安全ゲート
- 目的: 外部連携の情報漏えいリスク抑制
- 実装: デフォルトOFF + HTTPS + allowlist + 最小payload
- 受け入れ条件:
  - 設定不足時は送信拒否
  - 送信成否を監査ログへ記録

### LFC-1011: 契約ゲート（v1.0）
- 目的: リグレッション防止
- 実装: `check-v100-commercial-gate.sh` 追加
- 受け入れ条件:
  - authz/tenant/key repair/alerts の契約テスト通過

### LFC-1012: セールス向け運用パック
- 目的: 導入前説明の標準化
- 実装: runbook, security note, checklist, 5分デモ手順
- 受け入れ条件:
  - 初回導入手順が1ドキュメントで完結

## 2. v1.1 Ticket Set（運用拡張）

### LFC-1101: SCIMユーザー/グループ同期
- 受け入れ条件: role mapping自動反映

### LFC-1102: 署名保有者数の確定値化
- 受け入れ条件: estimated vs confirmed を併記

### LFC-1103: 鍵修復自動化率向上
- 受け入れ条件: 標準事故の自動復旧率KPI追加

### LFC-1104: 監査レポート自動生成
- 受け入れ条件: 月次監査PDF/JSONを出力

### LFC-1105: PostgreSQL集計最適化
- 受け入れ条件: 主要画面のP95レスポンス目標達成

### LFC-1106: 監査ログ保持/ローテーション機能
- 受け入れ条件: 保持期間設定と安全削除

### LFC-1107: 異常検知精度改善
- 受け入れ条件: false positive率の可視化

### LFC-1108: v1.1契約ゲート
- 受け入れ条件: v1.1追加API/UIの契約固定

## 3. v1.2 Ticket Set（大規模/モバイル統合）

### LFC-1201: モバイル認証統合
- 目的: 生体/パターンの運用統合
- 受け入れ条件: モバイル管理操作のMFA監査記録

### LFC-1202: Sign in with Apple（iCloud系）本番対応
- 受け入れ条件: enterprise SSO policyとの整合

### LFC-1203: 大規模テナント分離検証（1000+ client）
- 受け入れ条件: 負荷時もtenantリーク0件

### LFC-1204: 署名保有者数リアルタイム推定
- 受け入れ条件: 更新遅延SLOの定義と達成

### LFC-1205: 高可用CP構成
- 受け入れ条件: RPO/RTOの測定値提示

### LFC-1206: 改ざん耐性オプション（外部台帳は任意）
- 受け入れ条件: OFF時でも中核機能が成立

### LFC-1207: 監査証跡の法務テンプレ拡張
- 受け入れ条件: 契約監査で必要な項目を網羅

### LFC-1208: v1.2契約ゲート
- 受け入れ条件: 全追加仕様の自動検証

## 4. 依存関係（重要）

1. LFC-1001 -> 1005/1006/1007/1008/1009
2. LFC-1002 -> 1003/1005/1009/1011
3. LFC-1003 -> 1004/1005/1006
4. LFC-1007 -> 1008/1012
5. v1.1/v1.2 は v1.0ゲート成立後に着手

## 5. 実装順（推奨）

1. LFC-1001 Local SoR
2. LFC-1002 Tenant必須化
3. LFC-1003 SSO
4. LFC-1004 Passkey
5. LFC-1005/1006 可視化
6. LFC-1007 Key Repair
7. LFC-1008/1009 KPI/保有者数
8. LFC-1010 外部通知安全化
9. LFC-1011/1012 ゲートと運用パック

## 6. すぐ着手できる次タスク

1. `LFC-1001` のDBスキーマ定義
2. `LFC-1002` のtenant制約追加
3. `LFC-1011` のv1.0ゲート雛形作成

