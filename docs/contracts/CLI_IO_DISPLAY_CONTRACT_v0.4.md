# zt CLI I/O・表示契約 (v0.4 固定)

この文書は `gateway/zt` の v0.4 における CLI 契約の固定版です。  
目的は「ヘルプ表示」「引数解釈」「主要表示/JSON 出力」をテストで破壊検知できる状態にすることです。

## 1. コマンド I/O 契約 (固定)

- ルート usage: `Usage: zt <command> [args]`
- `setup`: `Usage: zt setup [--json] [--profile public|internal|confidential|regulated]`
- `send`: `Usage: zt send --client <name> [--profile public|internal|confidential|regulated] [--strict | --allow-degraded-scan] [--force-public] [--update] [--sync-now] [--no-auto-sync] [--copy-command] [--share-json] [--share-format auto|ja|en] [--share-route none|stdout|clipboard|file:<path>|command-file:<path>] <file>`
- `scan`: `Usage: zt scan [--tui] [--force-public] [--update] [--strict] [--no-auto-sync] <path>`
- `verify`: `Usage: zt verify [--receipt-out <path>] [--sync-now] [--no-auto-sync] <packet.spkg.tgz>`
- `sync`: `Usage: zt sync [--force]`
- `config doctor`: `Usage: zt config doctor [--json]`

`send` は `--client <name>` が必須です。未指定時の固定エラー:

- `zt send requires --client <name> (legacy artifact.zp path was removed)`

## 2. 表示契約 (固定)

### 2.1 Trust Status Line

- 成功: `TRUST: verified=true tamper=false policy=pass receipt=<id>`
- 失敗: `TRUST: verified=false tamper=unknown policy=fail reason=<error_code>`

### 2.2 Receiver Share Text

`stdout` text mode は以下を出力:

1. `[SHARE TEXT]`
2. ローカライズ本文 (`ja` / `en`)
3. `[SHARE] Receiver command example: zt verify -- '<packet>'`

### 2.3 `--share-json` 契約

- JSON 1 オブジェクト + 改行
- フィールド:
  - `kind` = `receiver_verify_hint`
  - `format` = `ja` or `en`
  - `command` = `zt verify ...`
  - `text` = 人間向け共有文（末尾改行を含む）

### 2.4 Verification Receipt (v1)

- `receipt_version` は固定で `v1`
- required top-level keys:
  - `receipt_id`
  - `verified_at`
  - `artifact`
  - `verification`
  - `provenance`
  - `tooling`

### 2.5 `zt config doctor --json` 契約

- required fields:
  - `ok`
  - `schema_version`
  - `generated_at`
  - `command`
  - `argv`
  - `exit_code`
  - `version`
  - `repo_root`
  - `config_source`
  - `failures`
  - `warnings`
  - `resolved`
  - `checks`
- 最小保証:
  - success: `ok=true`, `exit_code=0`, `failures=0`, 主要 check が `ok`
  - warn: `ok=true`, `exit_code=0`, `warnings>=1`（例: control-plane未設定）
  - fail: `ok=false`, `exit_code=1`, `error_code=ZT_CONFIG_DOCTOR_FAILED`, `failures>=1`

### 2.6 Failure Envelope

最低契約:

```json
{
  "error_code": "ZT_*",
  "summary": "string",
  "quick_fix_bundle": {
    "why": "string",
    "commands": ["cmd1", "cmd2"],
    "runbook": "docs/OPERATIONS.md",
    "retry": "full command"
  }
}
```

### 2.7 Flow E2E Contract

- `zt send --share-json` で出る `command` をそのまま `zt verify` に渡したとき、`receipt_version=v1` の receipt が生成されること
- 契約テストは `send -> share-json -> verify -> receipt` を1本で検証する

## 3. テストゲート (v0.4)

`go test ./gateway/zt` で以下契約テストが通ること:

- `cli_contract_test.go`: コマンド usage/ヘルプ契約
- `config_doctor_test.go`: `zt config doctor --json` required fields / fail-warn-success 最小保証
- `flow_contract_test.go`: `send -> share-json -> verify -> receipt` E2E 契約
- `share_transport_test.go`: share text / share-json 契約
- `verify_receipt_test.go`: receipt v1 契約
- `trust_contract_test.go`: failure envelope 契約

## 4. 完了条件 (このスレの終点)

1. コマンド I/O 契約をコード定数化し、`help` と `parse` が同一契約を参照
2. 表示契約を文書化し、主要経路を契約テストで固定
3. 契約テストを含む `go test ./gateway/zt` が green
4. 変更は `v0.4-*` 系で分割コミット
