
# zt-gateway AI-Edge 半年分 実装詳細設計書

作成日: 2026-05-26
期間: 6ヶ月 / 24週間
前提: 既存 `zt-gateway` コードベースを活かし、AI-Edge / Secure Model Router へ拡張する。

---

## 0. 実装方針

### 0.1 優先順位

1. モデルを安全に包む: Model Capsule / Passport
2. モデルを安全に起動する: Runtime Permit / zt-run
3. 証跡を残す: Local SoR / signed audit / Control Plane sync
4. Linuxで強くする: Kernel Shield / BPF LSM
5. ネットワークを速くする: Adaptive Dataplane / XDP / TUN
6. 企業に売れる形にする: Dashboard / policy / runbook / installer

### 0.2 やらないこと

- 分散学習時のNCCL/RDMA介入
- 完全ソフトウェアDRMの主張
- LLM safety全領域への進出
- 最初からKubernetes必須
- 最初から全ランタイム対応

### 0.3 成功条件

6ヶ月後の到達点:

```bash
zt model pack ./model.gguf --name internal-llm --version 1.0 --client edge-a
zt model run ./internal-llm.zmc --runtime llama.cpp -- ./llama-server --port 8080
zt model inventory --json
zt audit verify --require-signature
zt sync --json
```

が安定して動き、Dashboard で以下が見える。

- モデル一覧
- 配布先
- 実行中セッション
- shield tier
- permit状態
- audit status
- policy drift
- unauthorized attempt

---

## Month 1: Model Capsule / Passport MVP

目的:

- AIモデルを `zt` の扱える安全なアーティファクトにする。
- 既存 `secure-pack` の暗号化・署名・検証を活かして、`.zmc` を作る。
- eBPFやDRMにはまだ触らない。

### Week 1: Schema and command skeleton

#### Tasks

1. `gateway/zt/commands_model.go` を追加
2. CLI parse 追加
   - `zt model pack`
   - `zt model verify`
   - `zt model status`
3. `model_capsule_manifest_v1` schema 定義
4. `model_policy_v1` schema 定義
5. `model_scan_result_v1` schema 定義
6. contract tests 追加

#### Files

```text
gateway/zt/commands_model.go
gateway/zt/model_manifest.go
gateway/zt/model_policy.go
gateway/zt/model_capsule.go
gateway/zt/model_manifest_test.go
gateway/zt/model_policy_test.go
```

#### Acceptance Criteria

- `go test ./gateway/zt -run Model` が通る
- `zt model --help` が表示される
- manifest JSON のsnapshot testがある
- invalid manifest は fail-closed

### Week 2: Pack / verify implementation

#### Tasks

1. 既存 `secure-pack` adapter を流用して `.zmc` 生成
2. `manifest.json` を artifact に同梱
3. model file hash を streaming で計算
4. `zt model verify --receipt-out` 実装
5. model audit event 追加

#### Commands

```bash
zt model pack ./dummy.gguf --name demo --version 0.1 --format gguf --client local
zt model verify ./demo.zmc --receipt-out ./receipt_model_demo.json
```

#### Acceptance Criteria

- dummy 1GB file で pack/verify が動く
- hash mismatch test がある
- receipt contains `model_id`, `capsule_id`, `artifact_sha256`
- audit event `model_pack_completed`, `model_verify_completed` が出る

### Week 3: secure-model-scan MVP

#### Tasks

1. `tools/secure-model-scan` 追加
2. magic bytes / extension consistency
3. `.gguf` / `.safetensors` / `.pt` / `.pth` / `.bin` の基本判定
4. pickle系は `confidential` 以上で deny default
5. tokenizer/config のsecret-ish pattern scan
6. JSON output contract

#### Files

```text
tools/secure-model-scan/cmd/secure-model-scan/main.go
tools/secure-model-scan/internal/scan/scan.go
tools/secure-model-scan/internal/policy/policy.go
policy/model_policy.toml
policy/profiles/confidential/model_policy.toml
policy/profiles/regulated/model_policy.toml
```

#### Acceptance Criteria

- `secure-model-scan --json ./dummy.gguf` returns allow
- `.pt` returns warn/deny by profile
- secret pattern returns deny under regulated
- malformed JSON cannot pass

### Week 4: Local SoR model inventory

#### Tasks

1. Local SoR schema extension
   - model_assets
   - model_capsules
   - model_events
2. `zt model inventory --json`
3. `zt model status --json`
4. Dashboard local view stub
5. Month 1 docs update

#### Acceptance Criteria

- packするとLocal SoRにmodel assetが入る
- verifyするとlast_seen更新
- inventory JSON が安定schema
- plaintext dev mode と encrypted mode 両方test

#### Month 1 Exit Criteria

- `.zmc` を生成/検証できる
- model manifest / policy / receipt / audit の契約が固定された
- モデル用スキャンが最低限動く
- Local SoRにモデル資産が載る

---

## Month 2: Runtime Permit / zt-run MVP

目的:

- モデルを「復号して終わり」ではなく、認可されたランタイムで起動する。
- 最初は fake runtime と llama.cpp adapter を対象にする。

### Week 5: Runtime Permit schema and offline lease

#### Tasks

1. `runtime_permit_v1` schema 定義
2. local permit signer/verifier 実装
3. offline lease file 実装
4. expired / not-before / wrong model deny
5. audit events追加

#### Files

```text
gateway/zt/model_permit.go
gateway/zt/model_permit_test.go
gateway/zt/model_lease.go
gateway/zt/model_lease_test.go
```

#### Acceptance Criteria

- valid permit allows run precheck
- expired permit denies
- signature mismatch denies
- wrong capsule_id denies

### Week 6: `zt model run` fake runtime

#### Tasks

1. `commands_model_run.go` 追加
2. workspace作成
3. model decrypt/extract to workspace
4. fake runtime adapter
5. child process起動
6. cleanup on exit
7. audit session events

#### Command

```bash
zt model run ./demo.zmc --runtime fake -- ./test/fake-runtime --model {}
```

#### Acceptance Criteria

- fake runtime receives model path
- process exit captured
- workspace cleaned
- audit `runtime_started` / `runtime_stopped` generated
- fail途中でもcleanupされる

### Week 7: llama.cpp adapter

#### Tasks

1. `RuntimeAdapter` interface追加
2. `llama.cpp` adapter 実装
3. runtime binary hash計算
4. `--runtime-binary` support
5. command args validation

#### Command

```bash
zt model run ./demo.zmc \
  --runtime llama.cpp \
  --runtime-binary /usr/local/bin/llama-server \
  -- --port 8080 --ctx-size 4096
```

#### Acceptance Criteria

- model path injectionが決定論的
- binary hash mismatch denies under policy
- runtime args are preserved
- adapter unit tests cover command construction

### Week 8: Workspace hardening Tier 0

#### Tasks

1. runtime uid/gid strategy doc
2. chmod/chown hardening
3. core dump disable
4. env scrub
5. signal handling
6. cleanup reliability
7. Month 2 demo script

#### Acceptance Criteria

- workspace permission test
- env secret redaction test
- SIGINT/SIGTERM cleanup test
- Trust Status Line for model run

#### Month 2 Exit Criteria

- `zt model run` が fake runtime / llama.cpp で動く
- Runtime Permitで起動可否を決められる
- audit/Local SoRにruntime sessionが残る
- Tier 0の正直な保証表示ができる

---

## Month 3: Linux Kernel Shield PoC

目的:

- Linuxで「認可プロセス以外からの覗き見を抑止する」PoCを作る。
- BPF LSMは最小にする。最初から全ファイルI/Oを制御しない。

### Week 9: Capability Doctor

#### Tasks

1. `zt capability doctor --json`
2. kernel version detection
3. BPF availability detection
4. BPF LSM availability detection
5. AppArmor/seccomp/cgroup detection
6. JSON schema test

#### Acceptance Criteria

- Linuxで能力を正しく表示
- macOS/Windowsではfallback表示
- `require_kernel_shield` の判定に使える

### Week 10: BPF LSM skeleton

#### Tasks

1. `dataplane/ebpf/zt_lsm.c` 追加
2. bpf2go setup
3. load/unload manager
4. authorized runtime map
5. ringbuf event
6. no-op attach test

#### Files

```text
dataplane/ebpf/zt_lsm.c
gateway/zt/shield_lsm.go
gateway/zt/shield_lsm_linux_test.go
```

#### Acceptance Criteria

- supported kernelでloadできる
- unsupported kernelで明確なerror
- map write/readできる
- ringbuf event readできる

### Week 11: ptrace/proc-mem deny

#### Tasks

1. ptrace access hook
2. `/proc/<pid>/mem` file_open hook
3. `process_vm_readv` 相当の観測/制御方針
4. violation audit event
5. integration test

#### Acceptance Criteria

- unauthorized ptrace denies
- authorized runtime itself is not broken
- deny event appears in audit
- `require_kernel_shield=true` works fail-closed

### Week 12: Shield profile integration

#### Tasks

1. model policyに `shield_min_tier` 追加
2. `zt model run` と shield連携
3. AppArmor/seccomp fallback stub
4. docs: guarantee tiers
5. red-team style tests

#### Acceptance Criteria

- `shield_min_tier=audit_only` -> no LSMでもallow
- `shield_min_tier=kernel_shield` -> no LSMならdeny
- supported Linuxならkernel_shield表示
- READMEに「root完全防御ではない」と明記

#### Month 3 Exit Criteria

- Linux Kernel Shield PoCがある
- ptrace/proc-mem系の主要漏えい経路を検知/抑止できる
- shield tier を正直に出せる

---

## Month 4: Adaptive Dataplane / Egress Guard

目的:

- 推論APIへのアクセス制御とegress guardを作る。
- LinuxではXDP/TCの最小PoC、他OSではTUNまたはユーザー空間fallback設計を固める。

### Week 13: Dataplane policy schema

#### Tasks

1. `runtime_egress_policy_v1` schema
2. inbound allowlist
3. outbound allowlist
4. deny/audit/redact action model
5. Control Plane policy endpoint stub

#### Acceptance Criteria

- invalid egress policy denies
- profileごとのdefault policy
- JSON snapshot tests

### Week 14: Userspace proxy / guard MVP

#### Tasks

1. local inference proxy
2. request/response metadata audit
3. simple PII/secret pattern scan
4. allowlist by path/host/method
5. fail-closed option

#### Command

```bash
zt model run ./demo.zmc --runtime llama.cpp --guard-port 18080 -- ./llama-server --port 8080
```

#### Acceptance Criteria

- guard proxy routes to runtime
- denied request logged
- allowed request logged with no sensitive body by default
- no full prompt logging unless explicit

### Week 15: XDP pass/drop PoC

#### Tasks

1. `zt_xdp.c`
2. flow LRU map
3. stats map
4. Go loader with cilium/ebpf
5. `zt dataplane status --json`
6. integration in network namespace

#### Acceptance Criteria

- flow without grant drops in test namespace
- flow with grant passes
- stats counters update
- unload restores network

### Week 16: TUN/fallback planning + performance bench

#### Tasks

1. TUN adapter interface
2. macOS/Windows design doc
3. Linux userspace fallback prototype optional
4. benchmark harness
5. Month 4 hardening

#### Acceptance Criteria

- dataplane mode selection deterministic
- XDP unavailable -> fallback mode selected
- benchmark report generated
- no user-facing eBPF jargon in main UX

#### Month 4 Exit Criteria

- 推論APIのguard proxyが動く
- Linux XDPでflow pass/drop PoCがある
- fallback設計がある
- dataplane statusが見える

---

## Month 5: Control Plane / Dashboard / Fleet

目的:

- 企業が買える見える化を作る。
- Control Planeはpayloadを持たず、passport/permit/audit/fleetを扱う。

### Week 17: Control Plane model APIs

#### Tasks

1. `/v1/models/passports`
2. `/v1/models/inventory`
3. `/v1/models/runtime-events`
4. Postgres schema
5. OpenAPI update
6. contract tests

#### Acceptance Criteria

- model passport ingest accepts signed envelope
- idempotency works
- tenant boundary enforced
- OpenAPI gate passes

### Week 18: Runtime permit issuance

#### Tasks

1. `/v1/models/grants`
2. permit signer key management
3. policy evaluation
4. offline lease issuance
5. revoke status check

#### Acceptance Criteria

- valid request receives signed permit
- revoked model denies
- wrong tenant denies
- expired device enrollment denies

### Week 19: Edge enrollment / heartbeat

#### Tasks

1. `/v1/edge/enroll`
2. `/v1/edge/heartbeat`
3. device_id / host posture
4. shield tier reporting
5. capability drift detection

#### Acceptance Criteria

- edge device appears in dashboard data
- stale device detected
- kernel shield coverage can be computed

### Week 20: Dashboard views

#### Tasks

1. Model Inventory screen
2. Model Detail screen
3. Runtime Sessions screen
4. Edge Devices screen
5. Incidents / Revocation screen stub
6. CSV/JSON export

#### Acceptance Criteria

- demo can show “who runs what where”
- unauthorized attempts visible
- shield tier visible
- audit drilldown links available

#### Month 5 Exit Criteria

- Control Planeでモデル資産・実行・端末が見える
- runtime permitを発行できる
- Dashboardでエンタープライズ価値を説明できる

---

## Month 6: Pilot Hardening / Packaging / Enterprise Readiness

目的:

- 実証実験に出せる状態へ仕上げる。
- UX、インストール、runbook、ベンチ、セキュリティ説明を固める。

### Week 21: Installer / Nix / reproducibility

#### Tasks

1. Nix dev shell update
2. Linux install script
3. macOS audit-only installer note
4. binary release workflow
5. checksums/signatures
6. SBOM/provenance

#### Acceptance Criteria

- clean VMでinstallできる
- `zt capability doctor` runs
- release artifact signed
- install docs are one page

### Week 22: Security hardening

#### Tasks

1. threat model update
2. security non-goals update
3. red-team test matrix
4. key rotation runbook update
5. break-glass model access
6. audit verify enhancements

#### Acceptance Criteria

- root attacker limitation documented
- regulated profile fail-closed tests
- audit chain verification passes
- revoke workflow documented

### Week 23: Performance and reliability

#### Tasks

1. 1GB / 10GB / 40GB dummy model benchmark
2. cold start / warm start measurement
3. audit backlog stress
4. control plane ingest load test
5. XDP packet bench
6. dashboard query performance

#### Acceptance Criteria

- benchmark report generated
- known bottlenecks documented
- no severe data loss in audit backlog test
- startup SLOs defined

### Week 24: Pilot package

#### Tasks

1. pilot README
2. demo script
3. sales/security one-pager
4. architecture diagram
5. customer onboarding checklist
6. backlog triage for next 6 months

#### Acceptance Criteria

- 30分のpilot demoが可能
- clean customer-like machineでE2E
- known limitations are explicit
- next roadmap ready

#### Month 6 Exit Criteria

- Pilot-ready build
- Design docs updated
- Dashboard demo works
- Model capsule/run/audit/control-plane path integrated
- Kernel Shield PoC available on Linux
- No false “perfect DRM” claims

---

## 7. Weekly Milestone Table

| Week | Theme | Main Output | Exit Gate |
| --- | --- | --- | --- |
| 1 | schema/CLI | model command skeleton | schema tests pass |
| 2 | pack/verify | `.zmc` MVP | pack/verify/audit works |
| 3 | model scan | secure-model-scan | unsafe formats detected |
| 4 | inventory | Local SoR models | inventory JSON works |
| 5 | permit | runtime permit | signature/expiry tests |
| 6 | run fake | zt model run | fake runtime E2E |
| 7 | llama.cpp | runtime adapter | command build tests |
| 8 | workspace | Tier 0 hardening | cleanup/signal tests |
| 9 | doctor | capability doctor | OS capability JSON |
| 10 | LSM skeleton | BPF LSM loader | load/map/ringbuf test |
| 11 | deny hooks | ptrace/proc block | violation audit |
| 12 | shield policy | tier integration | fail-closed rules |
| 13 | egress schema | dataplane policy | schema gate |
| 14 | guard proxy | local API guard | deny/audit works |
| 15 | XDP PoC | pass/drop maps | namespace test |
| 16 | fallback/bench | mode selection | report generated |
| 17 | model APIs | CP ingest | OpenAPI gate |
| 18 | grants | permit issuance | tenant/revoke tests |
| 19 | edge | enroll/heartbeat | device inventory |
| 20 | dashboard | model/fleet UI | demo view |
| 21 | installer | release package | clean VM install |
| 22 | security | threat/runbook | red-team matrix |
| 23 | perf | benchmark | bottleneck report |
| 24 | pilot | pilot kit | demo + docs |

---

## 8. First Two Weeks: Concrete Implementation Detail

### 8.1 Week 1 pull request breakdown

#### PR 1: model command parse

- Add `model` subcommand dispatch in `main.go`
- Add parse tests
- No business logic

Files:

```text
gateway/zt/commands_model.go
gateway/zt/commands_model_test.go
gateway/zt/cli_parse_model.go
gateway/zt/cli_parse_model_test.go
```

#### PR 2: manifest schema

- Define structs
- Normalize/validate functions
- Deterministic manifest ID generation

Rules:

- No random UUID for deterministic IDs where hash can work
- Keep `schema_version`
- Fail if unknown critical fields appear

#### PR 3: model policy

- Add default `policy/model_policy.toml`
- Add profiles
- Implement loader
- Fail-closed on missing policy under `zt model pack`

### 8.2 Week 2 pull request breakdown

#### PR 4: model pack

- Hash model input
- Run `secure-model-scan` stub or scanner adapter
- Create manifest
- Call secure-pack adapter
- Rename/mark output as `.zmc`
- Emit audit

#### PR 5: model verify

- Extract manifest safely
- Verify signature/hash
- Write receipt
- Emit audit

#### PR 6: E2E contract

- `testdata/model/dummy.gguf`
- pack -> verify -> receipt
- bad hash -> deny
- missing manifest -> deny

---

## 9. Engineering Principles

1. Deterministic IDs where possible.
2. JSON contracts before UI.
3. Fail-closed on policy/signature/hash errors.
4. No implicit network dependency for local safety decisions.
5. Control Plane is async for audit, authoritative for policy/permit only when configured.
6. Every deny must have a reason code.
7. Every enterprise-facing feature must have audit evidence.
8. Every security guarantee must name its boundary.
9. Do not hide fallback; show `shield_tier` clearly.
10. Do not let eBPF complexity block model capsule/run MVP.

---

## 10. Backlog After 6 Months

- Runtime-native vLLM adapter
- Ollama deeper integration
- FUSE chunk decryptor
- memfd sealed model loader
- OCI artifact distribution
- Kubernetes admission controller
- Confidential Containers integration
- KBS integration
- Sigstore/OMS full verification
- Advanced watermarking
- SCIM group to policy mapping
- Customer-managed keys / HSM / PKCS#11
- SmartNIC / DPU investigation
- Multi-tenant SaaS hardening

---

## 11. Final Note

半年の実装で目指すべき完成形は「完璧なDRM」ではない。

目指すべきはこれ。

> 機密モデルを配布・実行・監査する導線を、顧客が嘘なく本番に置けるところまで持っていく。

この順番なら、技術の深淵に飲まれず、プロダクトとして売れる輪郭を保てる。
