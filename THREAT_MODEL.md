# Threat Model (Draft)

## Document Status

- Version: `draft-pre-v0.1.0`
- Scope: monorepo integration phase (`zt-gateway`, `secure-scan`, `secure-pack`, `secure-rebuild`)

## System Overview

目的は「信頼できない経路で受け渡されるファイルを、ローカルで検査・再構成・封緘し、検証可能な形で扱う」ことです。

高レベルフロー:

1. `zt-gateway`: フロー制御・操作入口
2. `secure-scan`: 検査（ポリシー / AV / YARA / メタデータ検査）
3. `secure-rebuild`: 再構成（CDR相当）
4. `secure-pack`: 暗号化・署名・パッケージ化
5. `verify`: 受信側検証（署名・整合性・封緘の確認）

## Trust Assumptions

### Trusted (by design)

- ローカル実行環境（ホストOS / ユーザー権限）
- 秘密鍵・公開鍵管理
- 明示的に承認されたポリシーファイル
- 再現可能なツールチェーン（目標）

### Untrusted (default)

- ネットワーク経路
- 外部から持ち込まれるファイル
- ファイル名 / 拡張子 / メタデータ
- UI入力や手作業の判断
- SaaSや中継サービス

## Assets to Protect

- 機密ファイル内容
- 秘密鍵 / 署名鍵
- 受信者情報・指紋情報
- スキャン/検証結果（証跡）
- ポリシー定義

## Adversaries

- 通信経路上の盗聴・改ざん者
- 悪性ファイル送信者
- 利用者の操作ミスを誘う攻撃者
- 既知シグネチャ回避を狙う攻撃者

## Security Goals

1. 危険なファイルの持ち込みを入口で抑止する
2. 未対応/不明形式はデフォルト拒否する（fail closed）
3. 再構成可能な形式は再構成後の成果物を信頼対象にする
4. 送受信時に改ざん検知可能な封緘を行う
5. 何を通して何を拒否したかの説明可能性を保つ

## Non-Goals (Initial)

- 全てのマルウェア検知
- 完全なサンドボックス実行
- あらゆるファイル形式のCDR対応
- エンドポイント防御製品の代替

## Threats Considered

- 拡張子偽装（例: `invoice.pdf.exe`）
- 既知マルウェアの混入
- YARAで検知可能な秘密情報/パターン混入
- メタデータ経由の情報漏えい（画像Exifなど）
- 送信後の改ざん
- 運用ミスによる危険な形式の通過

## Threats Not Fully Mitigated Yet (Current Gaps)

- `zt-gateway` と各ツール間の統合仕様が移行途中
- 形式別の「必ず再構成すべきか」の強制が未完成
- 一部PoC実装が存在し、安全デフォルトが統一されていない
- `verify` の真正性保証は統合完了まで再設計中

## Security Controls by Stage (Target)

### Intake / Scan

- 拡張子 + MIME/magic bytes の整合チェック
- サイズ制限
- AV (ClamAV)
- YARAルール
- メタデータ検査（例: Exif）

### Rebuild / CDR

- 対応形式のみ再構成
- 再構成不可は拒否（または明示的な `SCAN_ONLY` ポリシー時のみ許可）

### Pack / Seal

- 受信者公開鍵暗号化
- 送信者署名
- ハッシュ・メタデータ・ポリシー指紋の封緘

### Verify / Receive

- 署名検証
- ハッシュ照合
- 封緘構造の整合確認

## Extension Policy Model (Recommended)

各拡張子は以下のいずれかに分類する:

- `DENY`
- `SCAN_ONLY`
- `SCAN_REBUILD`

この分類は README の対応表とポリシーファイル実装の双方で一致させる。
