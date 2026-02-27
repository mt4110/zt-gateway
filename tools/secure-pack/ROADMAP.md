# Roadmap

## Phase 1: Go Unification (Current) ✅
- [x] Replace `sign.sh` and `unsign.sh` with pure Go implementation.
- [x] Implement Receiver logic in Go.
- [x] TUI support for both Sender and Receiver.

## Phase 2: CLI Usability 🚧
- [x] Implement CLI flags (e.g., `secure-pack send --client clientA`, `secure-pack receive --in file.spkg.tgz`).
- [x] Support custom output/config paths via send flags (`--base-dir`, `--out-dir`, `--recipients-dir`, `--tools-lock`, `--root-pubkey`).
- [x] Add `verify` command (check signature only, no extract).

## Phase 3: Robustness & Features 📅
- [ ] **Windows Support**: Verify and fix path handling for Windows native (non-WSL).
- [ ] **Key Management**: Helper commands to import keys or list recipients.
- [ ] **Config**: Support `config.toml` for default directories.

## Phase 4: Distribution 🚀
- [ ] Release pre-built binaries via GitHub Releases (goreleaser).
- [ ] Homebrew tap support?
