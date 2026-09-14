
# zt-gateway AI-Edge 詳細設計書

作成日: 2026-05-26
対象: `zt-gateway` 既存コードベースを AI-Edge / Secure Model Router へ拡張する設計

---

## 0. Executive Summary

`zt-gateway AI-Edge` は、機密AIモデルをオンプレミス、エッジ、開発者端末へ安全に配布・実行・監査するためのゼロトラスト・モデルルーターである。

既存の `zt-gateway` は、ファイル受け渡しの検査・再構成・封緘・検証を中心に設計されている。AI-Edge 版では、その能力を「モデルアーティファクト」と「推論ランタイム」に拡張する。

本設計の核は5つ。

1. **Model Capsule**: モデルを暗号化された配布単位にする。
2. **Model Passport**: モデルの出自、署名、依存物、実行条件、配布履歴を機械可読にする。
3. **Runtime Permit**: 認可された端末・プロセス・期間だけに復号権限を与える。
4. **Adaptive Runtime Shield**: OS/カーネル/TEE能力に応じて最大防御レベルを自動選択する。
5. **Signed Audit + Local SoR**: ローカル優先で監査証跡を残し、必要に応じて Control Plane へ同期する。

重要な設計判断:

- 「ソフトウェアだけで完全DRM」は主張しない。
- root権限を持つ攻撃者に対する強保証は、Confidential Computing / TEE / remote attestation に寄せる。
- 初期の主戦場は分散学習中のGPU通信ではなく、学習済みモデルの配布・起動・監査。
- eBPF/XDPは“製品の顔”ではなく、Linux環境での高速データプレーンと runtime shield の一部として使う。
- macOS/Windowsでは TUN/ユーザー空間/監査中心のフォールバックを明示する。

---

## 1. 現行コードベースの観察

### 1.1 既存資産

リポジトリから確認できる主な資産:

```text
.
├── gateway/zt/                  # zt CLI本体
├── tools/secure-pack/           # 暗号化・署名・パッケージング
├── tools/secure-scan/           # スキャン
├── tools/secure-rebuild/        # 再構成/CDR相当
├── control-plane/api/           # イベント取り込み・ポリシー配布・Dashboard API
├── policy/                      # extension/scan/team boundary/client policy
└── docs/                        # operations / runbook / architecture / OpenAPI
```

既存 `zt` CLI は `send`, `verify`, `audit`, `sync`, `policy`, `dashboard`, `unlock`, `relay` を持つ。これは AI-Edge における以下の機能へ転用できる。

| 既存機能 | AI-Edgeでの意味 |
| --- | --- |
| `secure-pack` | Model Capsule の暗号化・署名・封緘 |
| `zt verify` | Model Passport / capsule 検証 |
| `secure-scan` | モデル形式・pickle・secret・YARA検査 |
| `secure-rebuild` | モデルでは初期利用しない。将来 tokenizer/config sanitization に転用 |
| event spool | offline audit queue |
| audit chain | モデル実行イベントの改ざん検知ログ |
| Local SoR | 端末単位のモデル資産台帳 |
| Control Plane | fleet-wide policy / dashboard / event ingest |
| Trust Profiles | public/internal/confidential/regulated のモデル運用ポリシー |

### 1.2 現行の強み

- local-first と control-plane optional の設計思想が、エッジ・オンプレに合っている。
- fail-closed の文化がすでにある。
- policy bundle と activation / last-known-good の考え方がある。
- audit chain があり、AIモデルの配布・実行証跡と相性が良い。
- SSO/WebAuthn/SCIMに寄せたControl Planeがすでにあるため、Enterprise向けに発展しやすい。

### 1.3 現行のギャップ

| Gap | 影響 | 対応 |
| --- | --- | --- |
| モデルアーティファクト用 manifest がない | `.gguf` / `.safetensors` / tokenizer / adapter を一体管理できない | `model_capsule_manifest_v1` 追加 |
| 推論ランタイムを起動・保護する導線がない | 実行時の流出対策にならない | `zt model run` / `zt-run` 追加 |
| OS能力検出がAI-Edge向けでない | eBPF/LSM/TEE fallback が曖昧 | `zt capability doctor` 追加 |
| eBPF/LSM dataplane が未実装 | Linuxでの強みが未証明 | PoCとして最小実装 |
| モデルスキャンが未整備 | pickle / unsafe loader / secret混入を検出できない | `secure-model-scan` 追加 |
| Control Planeにモデル資産APIがない | dashboardで見せる価値が不足 | `/v1/models/*`, `/v1/edge/*` 追加 |

---

## 2. Product Scope

### 2.1 MVPで解決する課題

1. 機密モデルをそのまま配布するとコピーされる。
2. 誰がどこでどのモデルを動かしているかわからない。
3. モデル配布後の監査証跡が弱い。
4. ローカル/エッジ/オンプレではクラウドMLOps前提のセキュリティが使いづらい。
5. 推論ランタイムの実行境界が曖昧。

### 2.2 MVPで解決しない課題

- 分散学習中の NCCL/RDMA 通信保護
- root完全掌握端末からのソフトウェア単独保護
- 汎用LLM safety / jailbreak detection 全部入り
- 全モデル形式への完全対応
- Kubernetes専用の大規模運用

### 2.3 対象ペルソナ

| Persona | 主な痛み | 刺さる機能 |
| --- | --- | --- |
| CISO / Security | モデルIP流出、委託先管理、監査 | Model Passport, Runtime Permit, signed audit |
| MLOps | モデルバージョン・依存物・配布履歴が散らばる | Capsule manifest, inventory, policy bundle |
| Edge/Infra | オフライン環境、拠点端末、GPUサーバー運用 | Local SoR, offline lease, capability doctor |
| Developer | セキュリティ導線が面倒 | `zt model run` one command |

---

## 3. Top-level Architecture

```text
                         ┌──────────────────────────────┐
                         │        Control Plane          │
                         │  policy / grants / dashboard  │
                         └──────────────┬───────────────┘
                                        │ signed policy, runtime permit
                                        │ async audit sync
┌───────────────────────────────────────▼───────────────────────────────────────┐
│                                  Edge Host                                    │
│                                                                               │
│  ┌──────────────┐   ┌──────────────────┐   ┌──────────────────────────────┐   │
│  │ zt CLI       │──▶│ zt-run / agent    │──▶│ inference runtime             │   │
│  │ model pack   │   │ permit broker     │   │ llama.cpp / Ollama / vLLM     │   │
│  │ model run    │   │ decrypt manager   │   │ TGI / custom                 │   │
│  └──────────────┘   └─────┬────────────┘   └──────────────┬───────────────┘   │
│                           │                               │                   │
│                           │                               │ model API traffic │
│             ┌─────────────▼──────────────┐                │                   │
│             │ Runtime Shield              │                │                   │
│             │ seccomp / namespace         │                │                   │
│             │ AppArmor / BPF LSM          │                │                   │
│             │ cgroup / proc protection    │                │                   │
│             └─────────────┬──────────────┘                │                   │
│                           │                               │                   │
│             ┌─────────────▼──────────────┐   ┌────────────▼──────────────┐    │
│             │ Model Capsule Store         │   │ Adaptive Dataplane         │    │
│             │ encrypted chunks            │   │ XDP/TC or TUN fallback     │    │
│             │ manifest/passport           │   │ policy maps / egress guard │    │
│             └─────────────┬──────────────┘   └────────────┬──────────────┘    │
│                           │                               │                   │
│             ┌─────────────▼──────────────┐                │                   │
│             │ Local SoR + Audit Spool     │◀───────────────┘                   │
│             │ SQLite + signed JSONL       │                                    │
│             └────────────────────────────┘                                    │
└───────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Component Design

### 4.1 `zt` CLI 拡張

追加コマンド:

```bash
zt model pack <model-path> --name <name> --version <version> --format gguf --client <client>
zt model verify <capsule.zmc> --receipt-out receipt.json
zt model run <capsule.zmc> --runtime llama.cpp -- <runtime args...>
zt model status --json
zt model inventory --json
zt model revoke <model-id> --reason <reason>
zt edge enroll --tenant <tenant-id>
zt capability doctor --json
zt dataplane status --json
```

既存コマンドとの関係:

- `zt send`: 通常ファイル向けとして維持
- `zt verify`: file artifact と model capsule の両対応にするか、`zt model verify` に分ける
- `zt audit`: model events も対象にする
- `zt sync`: model events も同期する
- `zt dashboard`: model inventory / runtime sessions を表示する

### 4.2 `secure-pack V2 / model capsule`

#### 4.2.1 Format

拡張子: `.zmc` (`zt model capsule`)

```text
model.zmc
├── manifest.json
├── policy.json
├── recipients.json
├── signatures/
│   ├── zt.sig
│   └── oms.sig
├── provenance/
│   └── slsa.provenance.json
├── chunks/
│   ├── 00000001.cae
│   ├── 00000002.cae
│   └── ...
└── audit_seed.json
```

Phase 1では、現行 `spkg.tgz` の上に `manifest.json` を追加するだけでもよい。Phase 2で chunk AEAD に移行する。

#### 4.2.2 Manifest schema

```json
{
  "schema_version": "zt-model-capsule-v1",
  "capsule_id": "zmc_...",
  "model": {
    "model_id": "mdl_...",
    "name": "internal-llama-3.1-q4",
    "version": "2026.05.1",
    "format": "gguf",
    "base_model": "llama-3.1",
    "quantization": "Q4_K_M",
    "declared_size_bytes": 48234567890
  },
  "artifacts": [
    {
      "path": "model.gguf",
      "kind": "weight",
      "sha256": "...",
      "size_bytes": 48234567890,
      "content_type": "application/x-gguf"
    },
    {
      "path": "tokenizer.json",
      "kind": "tokenizer",
      "sha256": "...",
      "size_bytes": 123456
    }
  ],
  "policy": {
    "profile": "confidential",
    "allowed_runtimes": ["llama.cpp", "ollama", "vllm"],
    "runtime_binary_hashes": ["sha256:..."],
    "offline_lease_seconds": 86400,
    "require_kernel_shield": false,
    "require_attestation": false,
    "egress_policy_id": "egp_..."
  },
  "provenance": {
    "slsa_provenance_sha256": "...",
    "oms_signature_sha256": "...",
    "build_id": "...",
    "source_ref": "..."
  },
  "distribution": {
    "tenant_id": "tenant-a",
    "client_id": "client-a",
    "watermark_id": "wmk_...",
    "created_at": "2026-05-26T00:00:00Z"
  }
}
```

#### 4.2.3 Encryption

Phase 1:

- `tar -> zstd -> age/GPG envelope -> signature`
- 現行 `secure-pack` の GPG 依存を活かす
- 受信者公開鍵で envelope key を wrap

Phase 2:

- per-chunk AEAD
- chunk size: 4 MiB / 16 MiB をベンチで比較
- nonce: capsule_id + chunk_index + random salt から導出
- manifest は全chunk hashを保持
- random access を意識するが、最初からFUSE必須にしない

Phase 3:

- runtime-native streaming loader
- FUSE read-only decrypted view
- `memfd_create` + sealed fd
- confidential runtime KBS key release

### 4.3 `secure-model-scan`

モデル専用スキャナを追加する。

対象:

- pickle / PyTorch `.pt`, `.pth`, `.bin`
- `.safetensors`
- `.gguf`
- tokenizer / config / adapters
- suspicious Python code / remote code references
- secrets / API keys / endpoint leakage
- license metadata
- unsafe `trust_remote_code` 相当の兆候

出力契約:

```json
{
  "schema_version": "zt-model-scan-v1",
  "result": "allow|deny|warn",
  "reason": "model.safe|model.pickle_rce_risk|model.secret_detected|...",
  "model_format": "gguf",
  "findings": [
    {
      "id": "finding_001",
      "severity": "high",
      "category": "unsafe_serialization",
      "path": "model.pt",
      "message": "pickle-based model requires explicit trust policy"
    }
  ],
  "hashes": {
    "sha256": "..."
  },
  "policy_decision": {
    "decision": "deny",
    "profile": "confidential",
    "reason_code": "model_pickle_denied"
  }
}
```

MVPでは完璧なML malware検知を目指さない。以下だけで十分価値がある。

- pickle系は `confidential` / `regulated` で deny default
- safetensors / gguf は manifest hash と magic bytes を検証
- config/tokenizer内の URL / secret / suspicious script を検査
- model signing / provenance がない場合は warning or deny

### 4.4 `zt-run` Runtime Broker

`zt model run` の中核。

責務:

1. capsule manifest 検証
2. signature / provenance / policy 検証
3. device posture 収集
4. runtime permit 取得または offline lease 検証
5. runtime binary hash 検証
6. decrypt workspace 作成
7. runtime shield 適用
8. inference runtime 起動
9. runtime health / access event 記録
10. process終了後の cleanup / audit

#### 4.4.1 Workspace design

Phase 1:

```text
$XDG_RUNTIME_DIR/zt/models/<session_id>/
├── model.gguf        # decrypted, chmod 0400, owner runtime uid
├── tokenizer.json
└── runtime.env
```

制御:

- dedicated uid/gid
- chmod 0700 directory
- no core dumps
- process namespace
- cleanup on exit
- audit on failure

Phase 2:

- private mount namespace
- tmpfs
- `unlink-after-open` where possible
- `memfd_create` for compatible runtimes
- FUSE read-only view for chunk-decrypt

#### 4.4.2 Runtime adapters

Adapter interface:

```go
type RuntimeAdapter interface {
    Name() string
    Detect(binaryPath string) RuntimeDetection
    BuildCommand(ctx RuntimeContext, modelView ModelView, args []string) (*exec.Cmd, error)
    HealthCheck(ctx context.Context, session RuntimeSession) error
    ExtractAccessLog(line string) *RuntimeAccessEvent
}
```

Initial adapters:

| Runtime | MVP方針 |
| --- | --- |
| llama.cpp | `--model <path>` の置換で対応しやすい。最初のPoC候補。 |
| Ollama | モデル管理が独自。初期は外すか、import wrapper を作る。 |
| vLLM | Python環境依存。Phase 2以降。 |
| TGI | container/K8s向け。Phase 4以降。 |

### 4.5 Runtime Shield

#### 4.5.1 Tier 0: Audit-only

対応OS:

- macOS
- Windows
- Linux without required kernel features

制御:

- encrypted-at-rest
- signature verification
- runtime binary hash check
- workspace chmod
- process owner separation where possible
- no core dump setting where possible
- local audit
- warning: `shield_tier=audit_only`

#### 4.5.2 Tier 1: Kernel Shield

Linuxで実装。

制御:

- seccomp: dangerous syscalls の制限
- namespace: mount / pid / net namespace
- cgroup: runtime session grouping
- AppArmor profile optional
- BPF LSM:
  - `ptrace_access_check`
  - `file_open`
  - `mmap_file`
  - `file_mprotect`
  - `task_kill` optional
- `/proc/<pid>/mem` access block
- `process_vm_readv` block
- core dump disable
- runtime uid isolation

BPF LSM map:

```c
typedef struct {
    __u32 pid;
    __u32 uid;
    __u64 session_id_hi;
    __u64 session_id_lo;
} runtime_subject_key_t;

typedef struct {
    __u64 expires_ns;
    __u32 allowed_flags;
    __u8 model_id_hash[32];
    __u8 runtime_hash[32];
} runtime_subject_val_t;
```

LSM方針:

- `zt-run` が子プロセス起動後に `authorized_runtime_map` へ pid/uid/session を登録
- LSM hook は、対象プロセスへのptrace/proc-mem/open/mprotectをdeny
- deny時は ringbuf に audit event を流す
- map expiry が過ぎたら deny
- LSM ロード失敗時に `require_kernel_shield=true` なら fail-closed

#### 4.5.3 Tier 2: Attested Runtime

対応環境:

- CPU TEE / confidential VM
- NVIDIA confidential GPU / confidential containers / remote attestation
- KBS / key broker

制御:

- capsule key は attestation 成功後のみ release
- runtime measurement を permit と比較
- host OS / hypervisor / infrastructure admin を trust boundary から外す
- Edge host は control plane と直接繋がらなくても、事前発行された attestation policy を利用可能にする

MVPでは実装しない。だが設計に入れておく。

### 4.6 Adaptive Dataplane

ネットワーク層は「推論APIへのアクセス制御」「モデル配布の許可」「egress guard」を担う。

#### 4.6.1 dataplane modes

| Mode | OS | 使いどころ |
| --- | --- | --- |
| XDP | Linux | 高速 drop/pass、IP/port/session allowlist |
| TC/eBPF | Linux | egress制御、socket/flow policy |
| TUN/TAP | macOS/Linux/Windows | fallback tunnel |
| gVisor netstack | Go userspace | 低依存のユーザー空間TCP/IP fallback |
| NetworkExtension | macOS | 将来の正式macOS VPN/tunnel実装 |
| Wintun | Windows | Windows userspace tunnel |

#### 4.6.2 eBPF XDP maps

```c
typedef struct {
    __u8 proto;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u32 tenant_hash;
} flow_key_t;

typedef struct {
    __u64 expires_ns;
    __u32 decision;      // 0 drop, 1 pass, 2 redirect
    __u32 policy_id;
    __u32 flags;
    __u64 bytes;
    __u64 packets;
} flow_val_t;
```

Maps:

| Map | Type | 用途 |
| --- | --- | --- |
| `zt_flow_lru` | LRU_HASH | 認可済みflowの短期cache |
| `zt_endpoint_policy` | HASH/LPM_TRIE | 宛先CIDR/portごとのpolicy |
| `zt_revoked_sessions` | HASH | 失効済み jti/session |
| `zt_stats` | PERCPU_ARRAY | packet/byte/drop counters |
| `zt_events` | RINGBUF | deny/pass anomaly event |

#### 4.6.3 Control Plane / Go daemon sync sequence

重要: XDPはJWTを直接検証する場所ではない。L7認証はGo側で行い、XDPは結果を高速に参照する。

```text
1. user/device authenticates via zt agent
2. agent obtains signed policy bundle and runtime permit
3. agent validates signature and tenant boundary
4. agent derives flow/session allow entries
5. agent writes entries to BPF maps using cilium/ebpf
6. XDP program checks tuple -> map lookup -> pass/drop
7. stats/ringbuf events are read by agent
8. agent writes audit event to Local SoR/spool
```

#### 4.6.4 XDP program pseudo-code

```c
SEC("xdp")
int zt_xdp(struct xdp_md *ctx) {
    packet p;
    if (!parse_packet(ctx, &p)) return XDP_PASS;

    flow_key_t key = build_flow_key(&p);
    flow_val_t *grant = bpf_map_lookup_elem(&zt_flow_lru, &key);
    if (!grant) {
        count_drop(REASON_NO_GRANT);
        return XDP_DROP;
    }

    if (grant->expires_ns < bpf_ktime_get_ns()) {
        count_drop(REASON_EXPIRED);
        return XDP_DROP;
    }

    count_pass();
    return XDP_PASS;
}
```

#### 4.6.5 Non-goals

- HTTP body inspection in XDP
- TLS decryption in XDP
- JWT parsing in kernel
- NCCL/RDMA path interception in MVP

### 4.7 Control Plane API additions

追加 endpoints:

```text
POST /v1/models/passports
GET  /v1/models/{model_id}
GET  /v1/models/inventory
POST /v1/models/grants
POST /v1/models/runtime-events
POST /v1/edge/enroll
POST /v1/edge/heartbeat
GET  /v1/policies/model/latest
GET  /v1/policies/runtime/latest
POST /v1/incidents/model-revoke
```

#### 4.7.1 Runtime permit response

```json
{
  "schema_version": "zt-runtime-permit-v1",
  "permit_id": "permit_...",
  "tenant_id": "tenant-a",
  "model_id": "mdl_...",
  "capsule_id": "zmc_...",
  "device_id": "dev_...",
  "runtime": {
    "name": "llama.cpp",
    "binary_sha256": "...",
    "allowed_uid": 100123
  },
  "policy": {
    "profile": "confidential",
    "shield_min_tier": "audit_only",
    "egress_policy_id": "egp_...",
    "offline_lease_seconds": 86400
  },
  "validity": {
    "not_before": "2026-05-26T00:00:00Z",
    "expires_at": "2026-05-27T00:00:00Z"
  },
  "signature": {
    "alg": "Ed25519",
    "key_id": "rtp_2026q2",
    "sig_b64": "..."
  }
}
```

### 4.8 Database schema additions

Local SoR and Postgres bothに近い構造を持たせる。

```sql
create table model_assets (
  model_id text primary key,
  tenant_id text not null,
  name text not null,
  version text not null,
  format text not null,
  capsule_id text,
  artifact_sha256 text not null,
  manifest_sha256 text not null,
  created_at text not null,
  updated_at text not null,
  status text not null
);

create table model_capsules (
  capsule_id text primary key,
  tenant_id text not null,
  model_id text not null,
  capsule_sha256 text not null,
  policy_hash text not null,
  signer_fingerprint text,
  created_at text not null,
  distribution_watermark_id text
);

create table runtime_permits (
  permit_id text primary key,
  tenant_id text not null,
  model_id text not null,
  device_id text not null,
  runtime_name text not null,
  runtime_binary_sha256 text,
  issued_at text not null,
  expires_at text not null,
  status text not null
);

create table runtime_sessions (
  session_id text primary key,
  tenant_id text not null,
  model_id text not null,
  capsule_id text not null,
  permit_id text,
  device_id text,
  runtime_name text,
  pid integer,
  shield_tier text,
  started_at text not null,
  ended_at text,
  result text
);

create table model_runtime_events (
  event_id text primary key,
  tenant_id text not null,
  session_id text,
  event_type text not null,
  occurred_at text not null,
  result text,
  reason_code text,
  payload_sha256 text,
  details_json text
);
```

---

## 5. Security Model

### 5.1 Assets

- model weights
- tokenizer/config/adapters
- capsule encryption keys
- runtime permit signing keys
- device identity keys
- audit signing keys
- policy signing keys
- Local SoR data
- model access logs

### 5.2 Adversaries

| Adversary | 対策 |
| --- | --- |
| ネットワーク盗聴者 | encrypted capsule, TLS/mTLS, signatures |
| 配布先の一般ユーザー | runtime permit, no plaintext artifact, workspace perms |
| 同一端末の別プロセス | Kernel Shield, uid isolation, proc/ptrace block |
| 誤操作する開発者 | one-command run, fail-closed, policy defaults |
| 退職者/委託先 | lease expiry, revoke, audit, watermark |
| rootを持つ攻撃者 | Tier 2 attestation 以外では完全防御しない。正直に表示。 |
| host admin / cloud operator | confidential runtime / KBS / attestation |

### 5.3 Security boundaries

- Capsule at rest: encrypted
- Runtime workspace: protected by selected shield tier
- Kernel shield: Linux host within same kernel trust boundary
- Attested runtime: host/infrastructureをuntrustedとして扱う
- Control Plane: policy and audit aggregator, payload file storageではない

### 5.4 Fail-closed rules

- manifest signature invalid -> deny
- model hash mismatch -> deny
- policy bundle expired and no LKG -> deny
- runtime binary hash mismatch -> deny
- permit expired -> deny
- `require_kernel_shield=true` and BPF LSM unavailable -> deny
- `require_attestation=true` and attestation unavailable -> deny
- audit append failed under regulated profile -> deny or terminate

---

## 6. Performance Design

### 6.1 Model capsule performance

Bottlenecks:

- 数十GBモデルの全体復号
- disk I/O
- tar/gzip overhead
- memory pressure
- mmap compatibility

対応:

- zstd or no compression for already dense model files
- streaming hash
- chunk AEAD
- tmpfs optional, disk-backed encrypted workspace default
- explicit cleanup
- zero-copyを最初から約束しない
- per-runtime benchmark

### 6.2 Dataplane performance

Bottlenecks:

- map lookup回数
- ringbuf event過多
- XDP program verifier constraints
- driver mode非対応時のskb mode劣化
- TCP stateful handlingをXDPでやりすぎること

対応:

- XDPは原則 pass/drop だけ
- stateful TCPやL7判定はGo daemon/TUN/TCに逃がす
- LRU mapでsession cache
- statsはPERCPU
- deny eventはsampling
- BPF map updateはbatch化

### 6.3 Runtime shield performance

Bottlenecks:

- LSM hook overhead
- FUSE overhead
- decrypt workspace creation time

対応:

- MVPはFUSEなし
- LSM hookは対象pid/sessionのみに近い高速判定
- large model decryptはprogress出力とresumeを検討
- runtime startup SLOを分ける
  - cold start: model decrypt含む
  - warm start: decrypted lease cache利用

---

## 7. Observability and Audit

### 7.1 Audit event types

```text
model_pack_started
model_pack_completed
model_scan_completed
model_verify_completed
runtime_permit_requested
runtime_permit_issued
runtime_start_requested
runtime_started
runtime_denied
runtime_shield_violation
runtime_stopped
model_revoke_requested
model_revoke_applied
lease_expired
break_glass_used
```

### 7.2 Trust status line

既存 Trust Status Line を model run に拡張。

成功:

```text
TRUST: model_verified=true permit=valid shield=kernel_shield audit=recorded session=<id>
```

失敗:

```text
TRUST: model_verified=false permit=invalid shield=unavailable reason=<error_code>
```

### 7.3 Dashboard views

1. Model Inventory
2. Model Detail
3. Runtime Sessions
4. Edge Devices
5. Policy Drift
6. Shield Coverage
7. Incidents / Revocations
8. Audit Timeline

---

## 8. Implementation Layout

推奨追加ディレクトリ:

```text
.
├── dataplane/
│   ├── ebpf/
│   │   ├── zt_xdp.c
│   │   ├── zt_lsm.c
│   │   ├── bpf_helpers.h
│   │   └── README.md
│   └── generated/
├── gateway/zt/
│   ├── commands_model.go
│   ├── model_capsule.go
│   ├── model_manifest.go
│   ├── model_run.go
│   ├── model_runtime_adapter.go
│   ├── model_runtime_llamacpp.go
│   ├── model_permit.go
│   ├── capability_doctor.go
│   ├── dataplane_manager.go
│   ├── dataplane_ebpf.go
│   ├── dataplane_tun.go
│   ├── shield_linux.go
│   ├── shield_lsm.go
│   └── shield_fallback.go
├── tools/
│   └── secure-model-scan/
│       ├── cmd/secure-model-scan/main.go
│       └── internal/...
└── control-plane/api/cmd/zt-control-plane/
    ├── handlers_models.go
    ├── handlers_edge.go
    ├── runtime_permits.go
    └── model_policy.go
```

### 8.1 Build tags

```text
//go:build linux
shield_lsm.go

go:build !linux
shield_fallback.go
```

### 8.2 eBPF generation

Use `cilium/ebpf/cmd/bpf2go`.

```bash
go generate ./gateway/zt
```

`gateway/zt/dataplane_ebpf.go` loads generated objects and pins maps where needed.

---

## 9. Testing Strategy

### 9.1 Contract tests

- manifest schema snapshot
- model scan JSON schema
- runtime permit schema
- audit event schema
- Trust Status Line contract
- policy fail-closed contract

### 9.2 Unit tests

- manifest parser
- policy evaluator
- runtime adapter command builder
- permit signature verification
- capsule hash verifier
- local SoR model CRUD

### 9.3 Integration tests

- pack -> verify -> run fake runtime -> audit
- expired permit -> deny
- binary hash mismatch -> deny
- missing kernel shield with `require_kernel_shield=true` -> deny
- no Control Plane with valid offline lease -> allow
- no Control Plane and expired lease -> deny

### 9.4 Linux eBPF tests

- kernel capability detection
- XDP map load/unload
- flow pass/drop
- LSM ptrace deny
- `/proc/<pid>/mem` deny
- ringbuf violation event

Use GitHub Actions self-hosted Linux runner or dedicated VM. Container-only CIではLSM/XDPの実テストが不安定になりやすいため、unit/contractとkernel integrationを分ける。

### 9.5 Performance tests

Targets:

- 7B / 13B / 70B 相当のdummy file
- pack throughput
- verify throughput
- cold decrypt time
- warm runtime start time
- XDP packet drop/pass overhead
- audit append latency

---

## 10. Product Metrics

初期KPI:

| Metric | Target |
| --- | --- |
| `zt model pack` success rate | 90%+ |
| `zt model run` first-run success | 85%+ |
| audit append success | 99%+ |
| expired permit deny correctness | 100% |
| manifest hash mismatch deny | 100% |
| Linux capability detection accuracy | 95%+ |
| llama.cpp adapter E2E | < 1 manual step |

Enterprise KPI:

- model inventory completeness
- shield coverage ratio
- stale model count
- unauthorized run attempts
- audit sync backlog
- revoke propagation time

---

## 11. Critical Risks and Mitigations

| Risk | Severity | Mitigation |
| --- | --- | --- |
| DRM過剰主張 | Critical | Tiered guaranteeを明示。root対策はTEEのみ。 |
| eBPF実装に時間を吸われる | High | 最初のMVPはmodel capsule/run/audit。eBPFはMonth 3以降のPoC。 |
| Ollama adapterが複雑 | Medium | 初期は llama.cpp を第一対象にする。 |
| 巨大モデル復号が遅い | High | chunking、workspace cache、zstdなし、progress、bench。 |
| macOSで価値が弱い | Medium | Audit-only + developer UX + model passport で価値を出す。 |
| 競合がModel Securityを広く提供 | Medium | エッジ/オンプレ/モデル実行許可/Local SoRに絞る。 |
| Control Plane肥大化 | Medium | payload file uploadを作らない。policy/audit/fleetに限定。 |

---

## 12. First PoC Scope

2週間で証明すべきことはこれだけ。

> 暗号化された `.zmc` を作り、署名検証し、認可された `llama.cpp` 風のfake runtimeだけが起動でき、実行イベントが署名付きauditに残る。

PoCでは本物のLLM推論すら不要。

Required:

- `zt model pack ./dummy.gguf --name demo --version 0.1 --client local`
- `zt model verify ./demo.zmc --receipt-out receipt.json`
- `zt model run ./demo.zmc --runtime fake -- ./fake-runtime --model <injected>`
- expired policy deny
- binary hash mismatch deny
- audit event recorded
- Local SoR model inventory updated

Optional:

- Linuxで `capability doctor` が BPF LSM availability を表示
- BPF LSM stub が ptrace deny を出す

---

## 13. Final Architecture Position

この設計は、zt-gateway を「ファイル転送セキュリティツール」から「モデル配布後リスク管理ツール」へ進化させる。

そして、長期的には次の一文に収束させる。

> zt-gateway AI-Edge は、機密モデルを“配ったら終わりのファイル”から、“認可・実行・監査される企業資産”へ変える。
