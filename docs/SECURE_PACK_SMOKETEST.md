# Secure-Pack Packet Smoke Test (Local GPG)

`zt verify <packet.spkg.tgz>` を実際に確認するためのローカル手順です。

## 目的

- `zt send --client ...` で `secure-pack` (新CLIアダプタ) を通す
- `.spkg.tgz` を生成する
- `zt verify <packet.spkg.tgz>` を通す

## 前提

- `gpg` がインストール済み
- リポジトリルートでコマンド実行

## セットアップ（推奨）

補助スクリプトを使うと、ローカル専用の `GNUPGHOME` と recipient ファイルを準備できます。

```bash
bash ./scripts/dev/setup-secure-pack-localtest-gpg.sh
```

このスクリプトは以下を行います。

- `tmp/gnupg-smoketest` にテスト鍵を生成（既存なら再利用）
- `tools/secure-pack/recipients/local-smoketest.txt` に fingerprint を書き込み

## 実行例

```bash
export GNUPGHOME="$(pwd)/tmp/gnupg-smoketest"
go run ./gateway/zt send --client local-smoketest safe.txt
go run ./gateway/zt verify ./bundle_local-smoketest_*.spkg.tgz
```

## strict スキャン確認（任意）

スキャナ未導入環境では `secure-scan --json` が既定で degraded allow を返します。厳密運用を試す場合:

```bash
export ZT_SCAN_STRICT=1
go run ./gateway/zt send --client local-smoketest safe.txt
```

この場合、ClamAV/YARA/ExifTool が1つも利用できないと `deny` になります。

## 注意

- `local-smoketest.txt` はローカル検証用の recipient 設定です
- 実運用の fingerprint や鍵はコミットしないでください
- `GNUPGHOME` はローカル検証用ディレクトリに限定してください
