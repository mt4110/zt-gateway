# Zero-Trust Local Gateway (Monorepo, pre-release)
## zt-gateway / secure-pack / secure-scan / secure-rebuild

複雑な運用なしで、Zero Trust 前提の安全なファイル受け渡しを作るためのローカルファーストツール群です。

固定トーク（導入説明の最短版）:

- 送信側は約3分で導入して `zt send` まで到達できます
- 受信側は約1分で `zt verify` だけ実行すれば検証できます

売りたい価値（短く言うと）:

- お互いにソフトを入れるだけで、検査・封緘・検証つきのファイル受け渡しができる
- ネットワークを信用しなくても、署名と検証で受け渡しの証明を持てる
- SaaS依存なしでも運用できる（ローカル実行 + 後で監査同期）

ライセンス方針（現時点）: Apache-2.0 をベースに公開しつつ、将来の商用契約オプションを用意する方針です（`/Users/masakitakemura/algo_artis/zt-gateway/LICENSING.md`）。

## 3分で試す（Quick Start）

まずは送信側・受信側の両方で `zt` CLI を使える状態にしてください（同じリポジトリでもOK）。

### 送信側（コピペ最短）

1. セットアップ確認

```bash
go run ./gateway/zt setup
go run ./gateway/zt setup --json   # サポート/自動化向け
```

2. 送信（標準フロー）

```bash
go run ./gateway/zt send --copy-command ./safe.txt
```

3. 新 secure-pack 経路（spkg.tgz を使う場合）

```bash
go run ./gateway/zt send --client <recipient-name> --copy-command --share-format auto ./safe.txt
```

### 受信側（コピペ最短）

送信側の `[SHARE TEXT]` / `[SHARE]` に表示されたコマンドをそのまま実行:

```bash
zt verify ./artifact.zp
# または
zt verify ./bundle_xxx.spkg.tgz
```

最短デモ（送信側 / 受信側）:

![zt-gateway shortest flow demo GIF](docs/assets/zt-demo-two-pane.gif)

静止画像版（資料向け）:

![zt-gateway minimal sender/receiver demo](docs/assets/zt-demo-two-pane.svg)

困ったとき:

```bash
go run ./gateway/zt doctor
go run ./gateway/zt config doctor --json
go run ./gateway/zt setup --json
go run ./gateway/zt --help-advanced
```

## 何を自動でやるのか（利用者に見せたい体験）

`zt send` は、内部で次を順番に実行します。

1. `secure-scan` で検査（ポリシー・AV/YARA等）
2. `secure-rebuild` で再構成/無害化（必要な拡張子のみ）
3. `secure-pack` で暗号化・署名・封緘
4. イベントはローカルに spooling（必要なら Control Plane へ同期）

利用者は「送る」「検証する」に集中できます。

## Status

このリポジトリは **OSS公開準備中のモノレポ移行段階** です。

- `tools/secure-pack`, `tools/secure-scan`: 単体リポジトリ版を取り込み中（本命）
- `tools/secure-rebuild`: `zt-gateway` 側PoCを継続開発
- `tools/poc/*`: 退避した旧PoC実装（比較/参照用）

現時点では **本番の機密データ運用を推奨しません**。先に `SECURITY.md` と `THREAT_MODEL.md` を確認してください。

## 現状の安全境界 (重要)

このリポジトリには段階的に置き換え中の実装が混在しています。特に以下は未完成または統合途中です。

- `zt-gateway` と新しい `secure-pack` / `secure-scan` のCLI仕様は一部に互換アダプタを含む
- `secure-rebuild` は一部形式のみ再構成対応
- 拡張子ごとの「scan-only / rebuild必須 / deny」のポリシーは整備中
- 署名/検証フローの一部はPoC設計から再設計中

README の Quick Start は「導入と流れの理解」を目的にしたものです。実運用前に `SECURITY.md` / `THREAT_MODEL.md` を確認してください。

## 思想（設計の前提）

このシステムは、以下の「3つの信頼」と「3つの不信」の上に成り立っています。

### 信用するもの

1. ローカル: 自分の手元で動く処理
2. 鍵: 暗号学的な署名と検証
3. 再現可能性: Nixによる環境固定

### 信用しないもの

1. ネットワーク: 外部通信は盗聴・改ざんの対象
2. UI: 人間の操作はミスを誘発する
3. SaaS: 外部サービスは停止・侵害を前提に考える

## 対応拡張子ポリシー (v0.1.0 目標の初期方針)

以下は「現在の設計方針」です。実装状況とは分けて管理します。

| 拡張子 | 初期ポリシー | 再構成 (CDR) | 備考 |
| --- | --- | --- | --- |
| `.txt` `.md` `.csv` `.json` | `SCAN_ONLY` | なし | まず対象化しやすい |
| `.jpg` `.jpeg` `.png` | `SCAN_REBUILD` | あり (PoCあり) | 再エンコードでメタデータ除去 |
| `.pdf` | `SCAN_ONLY` から開始 | 後で追加 | `REBUILD` は後段実装 |
| `.docx` `.xlsx` `.pptx` | `SCAN_ONLY` から開始 | 後で追加 | 埋め込み/マクロ対策を別途設計 |
| `.zip` など圧縮 | `DENY` (初期) | なし | 再帰展開/zip bomb対策が必要 |
| 未知拡張子 | `DENY` | なし | fail closed |

注意:

- 拡張子だけでなく、将来的に MIME / magic bytes でも判定する前提です
- 例外許可はポリシーで明示し、デフォルト拒否を維持します

## 開発の始め方

### Go workspace (monorepo)

このリポジトリは `go.work` を使って複数モジュールを同時開発します。

対象モジュール:

- `gateway/zt`
- `tools/secure-pack`
- `tools/secure-scan`
- `tools/secure-rebuild`

### 既存のNixエントリポイント（互換レイヤ）

現在の `nix run .#zt` フローは旧PoC設計を前提にしている箇所があります。モノレポ統合に伴い更新予定です。

### Colima (Docker Desktop を使わない前提)

Control Plane の Postgres 検証は、Docker Desktop ではなく **Colima 前提** を推奨します。

最小オンボーディング:

```bash
brew install colima docker docker-compose
colima start --cpu 4 --memory 8 --disk 60
docker ps
```

停止:

```bash
colima stop
```

補足:

- `docker compose` プラグインが無い環境では `docker-compose` を使ってください
- Postgres dual-write の検証手順は `/Users/masakitakemura/algo_artis/zt-gateway/docs/CONTROL_PLANE_POSTGRES_SMOKETEST.md` を参照
- `zt` のイベント送信運用は `--no-auto-sync`（ローカル spool のみ）と `--sync-now`（コマンド終了時に強制同期）を使い分けできます
- `zt` のイベント自動同期デフォルトは `/Users/masakitakemura/algo_artis/zt-gateway/policy/zt_client.toml` の `auto_sync` で設定できます（優先順位: `CLI --no-auto-sync` > `ENV (ZT_NO_AUTO_SYNC / ZT_EVENT_AUTO_SYNC)` > `zt_client.toml` > built-in）
- `zt_client.toml` には `control_plane_url` / `api_key` も置けます（優先順位: `ENV (ZT_CONTROL_PLANE_URL / ZT_CONTROL_PLANE_API_KEY)` > `zt_client.toml` > built-in）
- 設定確認は `zt config doctor` で実行できます（設定解決元、spool 書き込み可否、署名鍵ENVの妥当性など）
- CI 用には `zt config doctor --json` を使うと純JSONで判定結果を取得できます
- `zt config doctor --json` は `version` と `exit_code` を含むので、CI 側で安定して判定できます
- `zt config doctor --json` は `schema_version` も含むので、CI 側でJSON互換判定を固定化できます
- `zt setup --json` も `schema_version` を含み、**破壊的変更時のみ** version を上げます（追加フィールドでは据え置き）
- `zt config doctor --json` は `generated_at` (UTC RFC3339) を含むので、CIログの時刻突合にも使えます
- `zt config doctor --json` は `command` / `argv` も含むので、CI実行時のトレースがしやすくなります

## ディレクトリ構成 (現在)

```text
.
├── flake.nix
├── gateway/
│   └── zt/                 # Gateway CLI (orchestrator)
├── tools/
│   ├── secure-pack/        # 本命実装（単体リポ取り込み）
│   ├── secure-scan/        # 本命実装（単体リポ取り込み）
│   ├── secure-rebuild/     # CDR/再構成 (PoC)
│   └── poc/                # 退避した旧PoC (比較用)
├── policy/
├── THREAT_MODEL.md
├── SECURITY.md
└── LICENSE
```

## v0.1.0 に向けた優先タスク

1. `zt-gateway` と `secure-pack` / `secure-scan` のCLI統合
2. 安全デフォルトの徹底（固定鍵禁止、fail closed）
3. `verify` の真正な署名検証実装
4. 拡張子ポリシー表と実装の整合
5. テスト/ドキュメント整備後に初回公開
