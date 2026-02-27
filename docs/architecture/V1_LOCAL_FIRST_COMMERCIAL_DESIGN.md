# V1 Local-First Commercial Design (B2B販売向け)

確認日: 2026-02-27

## 1. 目的と前提

この設計は、以下を同時に満たすことを目的にする。

- 基本はローカル閉域（Local-First）
- 外部接続は必要最小限で明示許可制
- 企業販売で必要な監査性・運用性・説明可能性
- クライアント別の可視化（ファイル、鍵、所在、作成時刻、利用回数、保有者数）

## 2. 販売に必要な必須機能（MVP+）

1. 認証・認可
- SSO（OIDC/SAML）
- ローカル緊急アクセス（オフライン管理者）
- MFA/Passkey/WebAuthn
- 役割ベース権限（viewer/operator/admin/auditor）

2. 監査と証跡
- 署名付き監査ログ（改ざん検知）
- 重要操作の完全記録（lock/unlock/break-glass/rekey/revoke）
- CSV/JSONエクスポート

3. クライアント管理
- クライアント別ファイル一覧
- 鍵状態（active/rotating/revoked/compromised）
- 生成日時・最終利用日時・所在（local/cloud endpoint）
- 送受信回数、検証成功率
- 署名データ保有者数（推定/確定）

4. 鍵事故対応
- 鍵破損・漏えい・失効時のrunbook付き修復フロー
- 再発行（rekey）と再暗号化（rewrap）
- 復旧操作の監査連動

5. 運用アラート
- danger high
- backlog/SLO breach
- signature anomaly
- 通知はデフォルトOFF、明示ON時のみ送信

## 3. アーキテクチャ方針

1. System of Record
- 端末単位の真実はローカルDB（SQLite + 暗号化）
- Control Plane/PostgreSQL は集約・分析用途（任意）
- どちらか一方ではなく「Local SoR + Optional CP」

2. ネットワーク
- デフォルトは outbound 最小
- 外部連携先は allowlist + HTTPS 強制
- 接続不可時は fail-open ではなく fail-closed か degraded 明示

3. データ分離
- tenant_id を全イベント・全主要エンティティに必須化
- tenant境界違反は API レベルで拒否

## 4. 認証方式の設計

要望認証を製品要件に落とす。

1. SSOログイン（推奨メイン）
- OIDC/SAML
- SCIMでユーザー/グループ同期（将来）

2. 生体認証
- 直接実装せず、OSのプラットフォーム認証を利用
- macOS Touch ID / Windows Hello / Android Biometrics / iOS Face ID
- 実装面は WebAuthn/Passkey で吸収

3. パターン認証（Androidなぞり）
- モバイル専用のローカル解除要素として扱う
- 管理コンソール主認証には使わない（監査要件上弱い）

4. iCloud
- 「Sign in with Apple（OIDC）」として扱う
- 端末秘密情報はOS Keychain管理

5. オフライン緊急ログイン
- ハードウェアキー + 期限付き break-glass token
- 常用禁止、監査必須

## 5. データモデル（最小）

1. tenants
- tenant_id, name, plan, status, created_at

2. clients
- client_id, tenant_id, display_name, status, created_at, updated_at

3. file_assets
- asset_id, tenant_id, client_id, filename, content_sha256, created_at, last_seen_at, location_type, location_ref

4. key_materials
- key_id, tenant_id, client_id, key_purpose, status, fingerprint, created_at, rotated_at, revoked_at, compromise_flag

5. key_recovery_jobs
- job_id, tenant_id, key_id, trigger, state, started_at, finished_at, operator, summary

6. exchanges
- exchange_id, tenant_id, client_id, asset_id, sender, receiver, verify_result, created_at

7. signature_holders
- tenant_id, signature_id, holder_count_estimated, holder_count_confirmed, updated_at

8. incident_audit
- incident_id, tenant_id, action, reason, approver, expires_at, actor, recorded_at, evidence_ref

## 6. 要望への対応マッピング

1. クライアント別ファイルリスト
- `clients` + `file_assets` をJOINしダッシュボード表示

2. 鍵の状態
- `key_materials.status` で即時表示

3. 今どこにある
- `file_assets.location_type/location_ref`（local path, cloud object, endpoint）

4. いつ作られたか
- `created_at` を全エンティティで標準化

5. 鍵が壊れた場合の修復
- `key_recovery_jobs` + runbook連携 + 再暗号化ワークフロー

6. 利用回数
- `exchanges` を集計（送信回数、受信回数、検証成功率）

7. 何人が署名データを持っているか
- 配布先イベント + 受領ACK + verify receipt から `signature_holders` を算出

## 7. 鍵修復（Key Repair）標準フロー

1. 検知
- mismatch/verify fail/compromised flag で自動起票

2. 封じ込め
- 対象鍵を quarantine または revoke
- 関連送受信を一時ロック

3. 復旧
- 新鍵発行
- 対象資産の再暗号化（rewrap）
- 配布先への再配布

4. 監査
- すべて `incident_audit` に記録
- 監査証跡に runbook ID を紐付け

## 8. PostgreSQL採用判断

結論:

- 単体/小規模導入: ローカルSQLiteのみで開始
- 部門横断/多拠点: PostgreSQLを追加（分析・集約・管理）

採用基準:

- 同時接続数
- テナント数
- 監査保持期間
- 集計速度要件

## 9. 外部連携（Slack/Discord/LINE）設計

1. デフォルトOFF
- `ALERT_DISPATCH_ENABLED=0` を既定

2. 安全条件
- HTTPS only
- host allowlist 必須
- tenantごとの送信制御
- メッセージ最小化（PII/機密を含めない）

3. 失敗時
- 送信失敗で機密処理を継続させない方針を選択可能
- 既定は「通知失敗は記録し、業務フローはfail-safe運用」

## 10. 画面要件（販売デモで必要）

1. Tenant Overview
- 稼働クライアント数、高危険アラート、backlog、SLO

2. Client Detail
- ファイル一覧、鍵状態、最近の交換履歴、保有者数

3. Incident Console
- lock/unlock/break-glass、承認、監査証跡

4. Key Lifecycle
- 生成、ローテーション、失効、修復ジョブ

## 11. リリース分割提案

1. v1.0 (販売可能MVP)
- SSO + RBAC
- クライアント別可視化
- 鍵状態と修復ジョブ
- 監査ログ/CSV
- 外部連携の安全ゲート

2. v1.1
- 保有者数の精度向上（確定値率改善）
- SCIM連携
- 監査レポート自動生成

3. v1.2
- モバイル認証要素拡張（パターン/生体の運用統合）
- 大規模向けPostgreSQL最適化

## 12. 非機能要件（契約前提）

- 可用性目標（SLA）
- 保存期間ポリシー
- 暗号化（at-rest/in-transit）
- 監査ログ不変性
- 復旧目標（RPO/RTO）

## 13. 今回の意思決定（提案）

1. DB戦略
- Local SQLiteを一次、PostgreSQLは任意二次

2. 認証戦略
- SSO + Passkey/WebAuthn を主軸
- 生体はOS機能として利用

3. 監査戦略
- incident/key repair を最優先で監査統合

4. 外部連携戦略
- 明示opt-in + allowlist + HTTPS

