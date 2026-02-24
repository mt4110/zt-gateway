# Security Policy

## Status

このプロジェクトは pre-release 段階です。`v0.1.0` までは仕様変更・破壊的変更が発生します。

## Supported Versions

現時点では固定の安定版はありません。

- `main` (pre-release): best effort

## Reporting a Vulnerability

機密性のある脆弱性報告は、公開Issueに投稿しないでください。

- 公開前期間: リポジトリ管理者へ非公開チャネルで連絡（GitHub公開時に正式窓口を記載予定）
- 非機密のバグ/誤検知/仕様議論: Issueで可

報告時に含めてほしい情報:

- 影響コンポーネント (`zt-gateway`, `secure-scan`, `secure-pack`, `secure-rebuild`)
- 再現手順
- 入力ファイル種別 / 実行環境
- 想定影響（情報漏えい、改ざん、検査回避など）
- 可能なら PoC（機密を含まない形）

## Disclosure Expectations

- 受領確認: best effort
- 再現確認後、修正方針を共有
- 公開時は影響範囲と回避策を明記

## Scope Notes (Current)

このリポジトリは統合中のため、READMEの「現状の安全境界」を必ず確認してください。特に以下は過信しないでください。

- 統合途中のCLIフロー
- 未対応形式の再構成
- 仕様移行中の署名/検証処理
