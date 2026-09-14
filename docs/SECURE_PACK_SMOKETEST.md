# Secure-Pack Packet Smoke Test (Local GPG)

`zt verify <packet.spkg.tgz>` を実際に確認するためのローカル手順です。

## 目的

- `zt send --client ...` で `secure-pack` (新CLIアダプタ) を通す
- `.spkg.tgz` を生成する
- `zt verify <packet.spkg.tgz>` を通す

運用方針（CI canonical / ローカル mismatch 対策）は `docs/SECURE_PACK_LOCAL_EXECUTION_POLICY.md` を参照してください。

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

## 推奨実行（pin mismatch を先に診断してから実行）

`tools.lock` を CI canonical として維持するため、まず補助スクリプトで `gpg` / `tar` pin 一致を確認してから smoke を実行します。

```bash
# 診断のみ（mismatch 時は exit 3）
bash ./scripts/dev/run-secure-pack-smoketest.sh --diagnose-only

# pin 一致時のみ smoke 実行
bash ./scripts/dev/run-secure-pack-smoketest.sh --client local-smoketest
```

このスクリプトは以下を行います。

- `tools/secure-pack/tools.lock` の `gpg` / `tar` version + sha256 pin を読み取り
- 現在の `PATH` 上の `gpg` / `tar` と比較
- 一致時のみ `./test/integration.sh --client local-smoketest` を実行
- mismatch 時は fail-closed で停止し、CI canonical 運用の参照先を表示

## Ubuntu/Linux 実行を固定化する Docker wrapper（推奨）

macOS ローカルから Ubuntu runner 相当で再現したい場合は、専用 wrapper を使うと再現条件を揃えやすくなります。

```bash
# 診断のみ
bash ./scripts/dev/run-secure-pack-smoketest-ubuntu-docker.sh --diagnose-only

# フル実行
bash ./scripts/dev/run-secure-pack-smoketest-ubuntu-docker.sh --client local-smoketest
```

この wrapper は以下を固定化します。

- `ubuntu:24.04` コンテナで実行
- `linux/amd64` プラットフォームで実行（CI runner 相当）
- `gpg/tar` と `tools.lock` pin の一致確認
- `nix` + `nixbld` ビルドユーザー設定
- `go` ツールチェーン（`nix shell nixpkgs#go`）を使った `zt send` adapter 実行

## strict スキャン確認（任意）

スキャナ未導入環境では `secure-scan --json` が既定で degraded allow を返します。厳密運用を試す場合:

```bash
export ZT_SCAN_STRICT=1
go run ./gateway/zt send --client local-smoketest safe.txt
```

この場合、ClamAV/YARA/ExifTool が1つも利用できないと `deny` になります。

## 注意

- `zt send --client local-smoketest` が supply-chain pin 検証で止まる典型原因は、`tools/secure-pack/tools.lock` の `gpg` / `tar` pin とローカル環境（例: Homebrew の `gpg`）の不一致です
- `tools.lock` は CI の基準値として扱い、ローカル smoke はまず CI 相当環境（Ubuntu/Linux runner 相当）での実行を推奨します
- `Nix` は `zt` 実行には便利ですが、pin 一致は最終的に `PATH` 上の `gpg` / `tar` 実バイナリ（version + hash）に依存します
- Docker Desktop（macOS bind mount）では `GNUPGHOME` の socket 作成で `gpg-agent` が不安定になることがあるため、wrapper はコンテナ内ローカル FS（`/work`）へ rsync して実行します
- `local-smoketest.txt` はローカル検証用の recipient 設定です
- 実運用の fingerprint や鍵はコミットしないでください
- `GNUPGHOME` はローカル検証用ディレクトリに限定してください
- root key fingerprint は `ROOT_PUBKEY.asc` を受け取った経路とは別経路で確認してから pin してください
