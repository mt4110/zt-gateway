
# zt-gateway AI-Edge: 追加アイディアと勝ち筋メモ

作成日: 2026-05-26
対象リポジトリ: `zt-gateway-main.zip`

---

## 0. 結論

いまの `zt-gateway` は、すでに以下の資産を持っている。

- `secure-pack`: 暗号化・署名・封緘・検証の土台
- `secure-scan` / `secure-rebuild`: ファイル検査・再構成の土台
- `zt` CLI: `send`, `verify`, `audit`, `policy`, `sync`, `dashboard`, `relay`, `unlock` などの統合入口
- Local SoR: SQLite ベースのローカル正本、client / asset / key / exchange / incident などのモデル
- Control Plane: イベント取り込み、ポリシー配布、dashboard API、SSO/WebAuthn/SCIM 周辺の実装
- 署名付き audit chain: append-only JSONL + Ed25519 署名 + external ledger の入口
- Trust Profiles / policy bundle / last-known-good activation: fail-closed 運用の核

つまり、AI-Edge ピボットで本当に必要なのは「別プロダクトを作る」ことではなく、既存の file-transfer / local-first security の能力を、**モデル配布・実行・監査**に再定義すること。

最初に掲げるべき商品名は、技術名ではなくこれ。

> **zt-gateway AI-Edge: 機密LLMを、オンプレ/エッジ/開発者端末へ安全に配布・実行・追跡するゼロトラスト・モデルルーター**

---

## 1. 追加アイディア: “マニア向け”を抜けるための強化案

### Idea 1: Model Passport

AIモデルをただの巨大ファイルとして扱わず、**配布・実行・監査の単位**として扱う。

`secure-pack` を `secure-pack V2 / model capsule` に進化させ、次の情報を持たせる。

- model_id
- model_name
- model_version
- format: `gguf`, `safetensors`, `onnx`, `pt`, `bin`, `tokenizer`, `adapter`
- artifact hashes
- tokenizer / config / adapter / quantization 情報
- creator / signing identity
- OMS / Sigstore / enterprise PKI signature
- SLSA provenance
- allowed runtime
- allowed device / tenant / group
- offline lease policy
- watermark_id / leak attribution metadata
- policy hash
- audit correlation id

価値:

- セキュリティ担当には「何が、誰に、どこへ、どういう条件で配られたか」を説明できる。
- MLOps には「モデルの依存物と実行条件が迷子にならない」メリットが出る。
- 経営層には「モデル資産台帳」として説明できる。

このプロダクトは、VPNでもDRMでもなく、**AIモデル資産のパスポート発行機関**になる。

---

### Idea 2: Runtime Permit Token

DRMという言葉を前面に出すと、セキュリティ玄人に燃やされる。なので、売り文句を変える。

ダメな言い方:

> ソフトウェアだけでモデル流出を完全阻止します。

良い言い方:

> 認可された環境・プロセス・期間だけに復号鍵を貸し出し、すべての利用を署名付き監査に残します。

`Runtime Permit Token` は、モデル実行の短期ライセンス。

含める情報:

- permit_id
- tenant_id
- model_id
- device_id
- runtime_id
- runtime_binary_hash
- allowed_uid / gid
- process_policy
- not_before / expires_at
- offline_lease_seconds
- egress_policy_id
- issued_by
- signature

使い方:

```bash
zt model run ./model.zmc --runtime llama.cpp -- ./llama-server --port 8080
```

`zt` が permit を検証し、必要な環境を作り、推論ランタイムを子プロセスとして起動する。

---

### Idea 3: Model Capsule = secure-pack + OMS + SLSA + chunk AEAD

独自形式だけで突っ走ると、顧客の既存MLOpsとぶつかる。そこで、独自形式を“閉じた箱”ではなく、既存標準を包むレイヤーにする。

推奨構造:

```text
model.zmc
├── manifest.json                 # zt model capsule manifest
├── oms.signature                 # OpenSSF Model Signing compatible detached signature, optional
├── slsa.provenance.json          # SLSA provenance, optional
├── policy.json                   # runtime / device / egress / lease policy
├── recipients.json               # key wrapping metadata
├── chunks/
│   ├── 000001.cae                # per-chunk AEAD ciphertext
│   ├── 000002.cae
│   └── ...
└── audit_seed.json               # audit correlation metadata, no secret
```

初期実装は単純でよい。

- Phase 1: tar + manifest + signature + whole-file encryption
- Phase 2: chunk encryption
- Phase 3: runtime-native streaming / FUSE / memfd optimization

重要なのは「巨大モデルだから全体復号しかない」という袋小路へ入らないこと。

---

### Idea 4: zt-run guarded runtime

既存の Ollama / llama.cpp / vLLM / TGI を無理やり改造しない。
まずは `zt-run` がプロセスの親になる。

```bash
zt model run ./llama-3.1-internal.zmc \
  --runtime llama.cpp \
  --runtime-binary /usr/local/bin/llama-server \
  --port 8080 \
  -- --ctx-size 8192
```

`zt-run` の責務:

- permit token 検証
- capsule manifest 検証
- 実行バイナリ hash 検証
- 一時復号領域作成
- namespace / cgroup / seccomp / AppArmor / BPF LSM の適用
- 子プロセス起動
- process exit 時のゼロ化・監査
- API access log / model access log の記録

これにより「ユーザーが勝手に既存ランタイムを起動してモデルファイルを読む」導線を潰す。

---

### Idea 5: Runtime Shield の3段階保証

保証を3段階に分ける。ここが超重要。

| Tier | 名前 | 保証 | 想定環境 |
| --- | --- | --- | --- |
| Tier 0 | Audit-only | 暗号化 at-rest、署名検証、実行監査。rootを持つ攻撃者には弱い。 | macOS / Windows / dev端末 |
| Tier 1 | Kernel Shield | Linux上で ptrace / proc mem / core dump / unapproved open を抑止。root完全掌握には勝てないが、通常運用の漏えい経路を強く潰す。 | Linux / WSL2 / edge server |
| Tier 2 | Attested Runtime | CPU/GPU TEE + remote attestation 後だけ鍵を解放。host admin からも守る。 | confidential VM / NVIDIA CC / CoCo |

これにより、営業でも技術でも嘘をつかずに済む。

プロダクトの美学はこう。

> ソフトウェアDRMで魔法を売らない。保証レベルを正直に表示し、顧客の環境で到達可能な最大保証を自動選択する。

---

### Idea 6: Edge Fleet Inventory

企業が本当に欲しがるのは「守りました」という感想ではなく、一覧性。

Dashboard で次を見せる。

- どのモデルが、どの拠点・端末・コンテナで動いているか
- どのバージョンが古いか
- どのモデルが未署名か
- どのモデルが期限切れ lease で動こうとしたか
- どの端末が kernel shield なしで動いているか
- どの端末が fail-open しそうか
- どのユーザーが break-glass したか

これは CISO / 情シス / MLOps の共通言語になる。

---

### Idea 7: Model Egress Guard

モデルファイルだけ守っても、推論APIから機密が漏れる可能性がある。
ただし Google Model Armor や Lakera の正面衝突を狙わない。
zt-gateway が狙うのは、**エッジ推論APIの境界制御**。

できること:

- モデルごとの inbound / outbound allowlist
- PII / secrets / internal code pattern の軽量検出
- ローカルポリシーによる deny / redact / audit only
- `secure-scan` のYARA/secret検出資産を流用
- 高度なLLM safety分類は外部サービス連携に逃がす

つまり、LLM Safety製品ではなく、**モデル利用境界の監査・遮断装置**として設計する。

---

### Idea 8: Honey Weight / Canary Adapter

完全なモデル盗難防止ではなく、漏れた時に追跡できる仕掛け。

候補:

- capsuleごとの watermark_id
- LoRA adapter に環境別の微小な署名パターンを入れる
- tokenizer / config / metadata に検証可能な canary を入れる
- 配布先ごとに異なる encrypted envelope と audit correlation id を持たせる

注意:

- モデル品質を壊さないこと
- 顧客に明示すること
- 法務・プライバシー上の説明ができること

最初は「重みそのものの電子透かし」より、manifest / adapter / distribution fingerprint から始めるべき。

---

### Idea 9: Air-gapped Edge Mode

工場、病院、自治体、製造現場では、常時SaaS接続できないことが多い。
ここは非常に刺さる。

機能:

- offline lease
- local KMS escrow
- signed policy bundle
- local SoR as source of truth
- delayed audit sync
- break-glass token
- USB / local artifact transfer with receipt

既存の Local SoR と event spool はこの方向と相性が良い。

---

### Idea 10: Kernel Capability Auto-Detector

ユーザーに eBPF / LSM / XDP / driver mode の知識を要求しない。

```bash
zt capability doctor --json
```

出力例:

```json
{
  "host": {
    "os": "linux",
    "kernel": "6.8.0",
    "arch": "amd64"
  },
  "dataplane": {
    "xdp": "available",
    "xdp_mode": "drv",
    "tc_bpf": "available",
    "fallback": "tun"
  },
  "runtime_shield": {
    "bpf_lsm": "available",
    "apparmor": "available",
    "seccomp": "available",
    "tier": "kernel_shield"
  },
  "gpu_confidential": {
    "available": false,
    "reason": "no_confidential_gpu_attestation"
  }
}
```

売り文句:

> その端末で使える最大の防御レベルを自動選択する。

---

## 2. 最も刺さる初期ユースケース

### 本命: 「開発者・拠点・委託先に機密LLMを配る企業」

例:

- 製造業: 工場内PCで検査用LLM/画像モデルを動かす
- 医療: 院内サーバーで医療文書/画像モデルを使う
- 金融: 社内専用ファインチューニングモデルを支店/開発者へ配る
- SIer: 顧客別にチューニングしたモデルを納品する
- 防衛/公共: air-gapped 環境でモデルを運用する

彼らの悩み:

- モデルを渡した瞬間にコピーされる
- どこで動いているかわからない
- 退職者・委託先・拠点PCに残る
- VPNではファイルの複製を防げない
- MLOpsツールはクラウド前提すぎる
- ランタイムの実行ログが監査向けに整理されていない

zt-gateway AI-Edge の返答:

- 暗号化されたモデル capsule だけ配布
- 認可された runtime だけ起動
- 実行ごとに署名付き監査
- 期限切れ・端末違い・runtime違いは起動不可
- Linux では kernel shield、対応環境では attestation
- SaaS接続なしでも offline lease で運用可能

---

## 3. 初期プロダクトから外すべきもの

容赦なく切る。

### 外す1: 分散学習中の NCCL/RDMA 介入

理由:

- NVIDIA ecosystem と真正面から戦う
- 遅延への要求が厳しすぎる
- PoCが重い
- 顧客の購買理由とズレやすい

最初に狙うべきは、学習後モデルの配布・起動・監査。

### 外す2: root相手にも完全に勝つソフトウェアDRM

理由:

- 嘘になる
- セキュリティ専門家に刺される
- 長期的な信用を失う

代わりに、Tiered Runtime Shield と Attested Runtime を出す。

### 外す3: LLM Safety全部入り

理由:

- Google / Lakera / Cloudflare / Kong などがいる領域
- モデル保護のコアと違う

zt-gateway は「AIモデル資産・実行境界・監査」に絞る。

### 外す4: 最初からKubernetes必須

理由:

- エッジ/ローカル/WSL2/単体サーバーに刺さらない
- 既存repoは local-first の強みがある

Kubernetesは 4〜6ヶ月目の enterprise integration として扱う。

---

## 4. 最初の営業コピー

### One-liner

> 機密LLMを、コピーされるファイルではなく、認可された環境でだけ動く監査可能な資産として配布する。

### For CISO

> VPNでは防げないモデル複製・退職者PC残存・委託先流出を、モデル単位の暗号化、実行許可、署名付き監査で管理します。

### For MLOps

> gguf / safetensors / tokenizer / config / adapter を一つの Model Passport にまとめ、誰がどのバージョンをどこで動かしたかを追えます。

### For Developer

> `zt model run` だけで、安全なモデル実行環境が立ち上がる。鍵、ポリシー、監査、復号、片付けは裏側で終わる。

---

## 5. 戦略上の命名

避ける名前:

- AI DRM
- eBPF AI Gateway
- Kernel AI Security

推奨名:

- zt-gateway AI-Edge
- Secure Model Router
- Model Capsule Gateway
- Zero-Trust Model Deployment
- Model Passport + Runtime Permit

最初の資料では、eBPF / LSM は深掘りスライドに下げる。
表の言葉は「モデルの安全な配布・実行・監査」。

---

## 6. 現時点の判定

このピボットは成立する。
ただし勝ち筋は、`eBPF × AIインフラ` ではない。

勝ち筋はこれ。

> 既存repoの local-first / secure-pack / audit / policy / control-plane を使って、機密AIモデルの配布後リスクを管理する。

深淵の技術は裏側で燃やす。顧客には、澄んだ水面だけ見せる。
