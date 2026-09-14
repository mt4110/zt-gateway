
# 参考資料メモ

この設計で参照した主な外部資料。

- Linux Kernel Documentation: LSM BPF Programs
- eBPF Docs: BPF_PROG_TYPE_XDP
- Linux Kernel Documentation: BPF maps / hash and LRU variants
- cilium/ebpf GitHub repository and docs
- gVisor Networking Guide / netstack
- Apple Developer Documentation: NEPacketTunnelProvider
- Wintun official documentation
- NVIDIA NCCL documentation
- NVIDIA Confidential Containers / Confidential AI reference material
- NVIDIA Technical Blog: Zero-Trust Architecture for Confidential AI Factories
- OpenSSF Model Signing / OMS introduction
- SLSA specification v1.2
- Sigstore model-transparency project
- Hugging Face Pickle Scanning documentation
- Google Cloud Model Armor overview
- Protect AI ModelScan overview

設計上の重要な解釈:

- XDPはL7認証やJWT検証の場所ではなく、Go側で検証済みの短期grantを高速に参照する場所として扱う。
- BPF LSMはruntime protectionの一部であり、root完全掌握に対する万能薬ではない。
- モデル署名・provenanceは独自仕様に閉じず、OMS/Sigstore/SLSAと整合させる。
- Confidential Computing/TEEは将来の強保証レイヤーであり、MVPではTier 2を設計に入れつつ実装対象から外す。
