# Secure-Pack (Go Rewrite)

安全なファイル転送のための暗号化・署名・パッケージングツールです。
Slackなどの信頼できない経路でも、機密情報を安全に共有できます。
GPGを使用し、強力な暗号化と改ざん検知（署名）を、簡単なコマンドで実行します。

## 概要

このツールは、以下の「安全なファイル転送」のプロセスを自動化・簡略化します。

1.  **暗号化 (Encrypt)**: 指定した受信者(`recipients/`)しか開けないように保護
2.  **署名 (Sign)**: 送信者が確かに自分であることを証明
3.  **検証 (Verify)**: ファイルが改ざんされていないことを確認

従来の手動GPG操作をラップし、`.spkg.tgz` という単一のファイルにパッケージングしてやり取りします。

## 動作環境

- **必須**: Nix (環境構築ツール)
  - ※ Nixを使用しない場合、Go 1.22+ と GPG (`gnupg`) のバージョンを自力で完全に合わせる必要があります。推奨しません。

## セットアップ (Nixの導入)

### 1. Nixのインストール
まだインストールしていない場合は、以下のコマンドでインストールしてください。

```bash
# 公式インストーラー (MacOS / Linux)
sh <(curl -L https://nixos.org/nix/install)
```

**Nixとは？**
プロジェクトごとに独立した「開発環境」を作るツールです。

**なぜNixが必要？**
- **「環境の差異」をゼロにするため**: MacでもLinuxでも、誰のPCでも、全く同じバージョンのGoとGPGが使われることを保証します。
- **依存地獄からの解放**: プロジェクト専用の環境を作るため、自分のPCに入っている既存のツールと競合しません。

### 2. 開発環境の有効化
プロジェクトのディレクトリで以下を実行します。これにより、必要なツール(Go, GPG等)が全て揃ったシェルが起動します。

```bash
nix develop
# 🔐 Secure-Pack Dev Environment ... と表示されれば準備完了です
```

## 使い方 (CLI)

### 1. 送信者 (Sender)
ファイルを暗号化して、送信用のパケットを作成します。
内部処理: `tar` (アーカイブ) -> `gpg` (暗号化) -> `gpg` (署名) -> `tar` (パッケージング)

```bash
# 対話モード（推奨）
go run ./cmd/secure-pack

# コマンドライン
go run ./cmd/secure-pack send --client <クライアント名>

# 例: docsフォルダを clientA 向けに暗号化
go run ./cmd/secure-pack send --client clientA
# 出力: dist/bundle_clientA_YYYYMMDD...spkg.tgz
```

### 2. 受信者 (Receiver)
パケットを受け取り、検証して展開します。
内部処理: `tar` (展開) -> `gpg` (署名検証) -> `sha256` (ハッシュ確認) -> `gpg` (復号)

```bash
# 対話モード
go run ./cmd/secure-pack

# コマンドライン
go run ./cmd/secure-pack receive --in <ファイルパス> --out <出力先>

# 例
go run ./cmd/secure-pack receive --in dist/bundle_clientA_....spkg.tgz --out extracted_docs
```

### 3. 検証のみ (Verify)
展開はせずに、署名とハッシュが正しいかだけを確認します。

```bash
go run ./cmd/secure-pack verify --in <ファイルパス>
```

## プロセスの簡略化について

このツールは GPG の複雑なステップを **「1コマンド」** に凝縮しています。

- **送信時**: 「圧縮・暗号化・署名」を1回で実行します。
- **受信時**: 「検証・復号・展開」を1回で実行します。

ユーザーが行うのは「コマンドを叩く」ことと「できたファイルを送る/受け取る」ことだけです。

## ディレクトリ構成
- `cmd/secure-pack`: コマンドのエントリーポイント
- `internal/`: ロジックコード
- `recipients/`: 受信者の公開鍵指紋リスト (`.txt`)
- `dist/`: 生成されたパケットの出力先

## トラブルシューティング

### ビルド時にバージョン不整合エラーが出る場合
`compile: version "go1.xx" does not match go tool version "go1.yy"` というエラーが出た場合、Nixとローカル環境(Mise等)を行き来したことによるキャッシュの競合が原因です。以下のコマンドで解決します。

```bash
# キャッシュを削除して再ビルド
go clean -cache -modcache
go build -a -v ./cmd/secure-pack
```
