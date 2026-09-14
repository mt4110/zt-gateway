# Secure-Pack Local Execution Policy (tools.lock pin mismatch)

`secure-pack` の supply-chain pin 検証（`tools.lock` + `tools.lock.sig` + `ROOT_PUBKEY.asc`）を維持したまま、CI とローカル smoke の運用差分を最小化するための方針です。

## 結論（採用案）

- 採用: **案A（CI canonical / 再現環境優先）**
- `tools/secure-pack/tools.lock` は **CI の基準値（canonical）** として扱う
- ローカル smoke の標準手順は **CI 相当環境（Ubuntu/Linux runner 相当）で実行**
- pin 検証は維持（緩めない）
- macOS などのローカル差分は、`tools.lock` を書き換えて吸収せず、実行環境側で吸収する

## 背景

- `tools.lock` は `gpg` / `tar` の **version + sha256 pin** を検証する
- pin は実行バイナリ依存のため、実質的に OS/配布パッケージ/CPUアーキテクチャ差分の影響を受ける
- そのため、`gpg` / `tar` 実バイナリが CI とローカル（例: Homebrew `gpg`, BSD tar）で異なると fail-closed で停止する
- これは設計どおりの安全側挙動であり、pin 検証を無効化して解決しない

## A/B 比較

### 案A: CI相当環境で実行（採用）

- 内容: `tools.lock` を CI canonical に固定し、ローカル smoke は Ubuntu/Linux runner 相当で実行
- 利点:
  - pin の意味を維持できる
  - CI とローカルの差分を減らせる
  - `tools.lock` の意図しない更新・誤コミットを防ぎやすい
- 欠点:
  - macOS 単体での即時実行性は少し落ちる
  - CI相当環境（VM/Codespaces/runner 等）の準備が必要

### 案B: ローカル用 `tools.lock` を更新（不採用: 標準運用として）

- 内容: 手元環境の `gpg` / `tar` に合わせて `tools.lock` と署名を再生成
- 利点:
  - 手元では通しやすい
- 欠点:
  - CI canonical とズレやすい
  - pin の一貫性レビューが難しくなる
  - 共有リポジトリで誤コミット事故を起こしやすい

## 標準運用ルール

- `tools.lock` / `tools.lock.sig` / `ROOT_PUBKEY.asc` は CI canonical としてレビュー対象
- ローカル smoke 前に、まず pin mismatch を診断する
- mismatch の場合は `tools.lock` を安易に更新せず、CI相当環境へ切り替える
- `tools.lock` 更新が必要なケース（root key 更新、CI側ツール更新反映など）は **Linux/Ubuntu** で実施する
- 更新時は `scripts/dev/generate-secure-pack-tools-lock.sh` を使用し、`docs/OPERATIONS.md` の手順に従う

## 実装反映（この方針に基づく）

- CI: `/.github/workflows/ci.yml` で `./test/integration.sh --client local-smoketest` を明示
- ローカル: `scripts/dev/run-secure-pack-smoketest.sh` を標準入口にする
  - `tools.lock` pin mismatch を先に診断
  - mismatch 時は fail-closed + CI canonical 運用を案内
  - pin 一致時のみ integration smoke を実行
- macOS などで Ubuntu runner 相当を固定化したい場合は `scripts/dev/run-secure-pack-smoketest-ubuntu-docker.sh` を利用する

## 例外運用（明示的に実施する場合のみ）

- `tools.lock` 更新（案B相当の操作）は、標準 smoke 手順ではなく運用作業として分離する
- 実施条件:
  - Linux/Ubuntu 環境
  - root signing key の秘密鍵が利用可能
  - `tools.lock` 差分をレビューして commit 目的が明確

参照:

- `docs/SECURE_PACK_SMOKETEST.md`
- `docs/OPERATIONS.md`
- `scripts/dev/generate-secure-pack-tools-lock.sh`
