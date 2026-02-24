# Secure-Pack Packet Smoke Test (Local GPG)

`zt verify <packet.spkg.tgz>` を実際に確認するためのローカル手順です。

## 目的

- `zt send --client ...` で `secure-pack` (新CLIアダプタ) を通す
- `.spkg.tgz` を生成する
- `zt verify <packet.spkg.tgz>` を通す

## 前提

- `gpg` がインストール済み
- リポジトリルートでコマンド実行
- `tools/secure-pack/tools.lock` / `tools.lock.sig` / `ROOT_PUBKEY.asc` が配置済み（`zt send` は fail-closed）

## ROOT_PUBKEY fingerprint pin 設定（必須）

`zt setup` / `zt send` precheck は `ROOT_PUBKEY.asc` の fingerprint pin が未設定だと失敗します。
先に fingerprint を別経路（電話/対面/別チャネル）で確認し、環境変数に固定してください。

```bash
# 1) repo内の root key fingerprint を取得（表示値は別経路で照合）
ROOT_FPR="$(gpg --show-keys --with-colons ./tools/secure-pack/ROOT_PUBKEY.asc | awk -F: '/^fpr:/ {print $10; exit}')"

# 2) zt の precheck/setup 用 pin（必須）
export ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS="${ROOT_FPR}"

# 3) secure-pack 単体CLIも使う場合は同じ値を設定（任意）
export SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS="${ROOT_FPR}"
```

鍵ローテーション時は複数許容できます（`,` または改行区切り）:

```bash
export ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS="OLD_FPR_40HEX,NEW_FPR_40HEX"
```

本番運用の切替手順（併記期間 / 切替日 / 削除日 / rollback）は `docs/SECURE_PACK_KEY_ROTATION_RUNBOOK.md` を参照してください。

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
ROOT_FPR="$(gpg --show-keys --with-colons ./tools/secure-pack/ROOT_PUBKEY.asc | awk -F: '/^fpr:/ {print $10; exit}')"
export ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS="${ROOT_FPR}"
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
- root key fingerprint は `ROOT_PUBKEY.asc` を受け取った経路とは別経路で確認してから pin してください
