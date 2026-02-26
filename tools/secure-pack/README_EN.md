# Secure-Pack

A tool for secure file transfer using encryption, signing, and packaging.
Safely share sensitive information over insecure channels like Slack.

## Overview

Automates and simplifies the GPG workflow:
1.  **Encrypt**: Protect data so only specific recipients can open it.
2.  **Sign**: Prove the sender's identity and ensure non-repudiation.
3.  **Verify**: Ensure integrity and detect tampering via detached signatures and SHA256 checksums.

It wraps these operations into a single `.spkg.tgz` packet.

## Requirements

- **REQUIRED**: Nix (Package Manager)
  - *Note*: Without Nix, you must manually ensure exact versions of Go 1.22+ and GPG. This is not recommended.

## Setup (Installing Nix)

### 1. Install Nix
If you haven't installed Nix yet, run the official installer:

```bash
# Official Installer (MacOS / Linux)
sh <(curl -L https://nixos.org/nix/install)
```

**What is Nix?**
A tool that creates isolated, reproducible development environments for each project.

**Why use Nix?**
- **Zero Inconsistency**: Guarantees that everyone uses the exact same versions of Go and GPG, regardless of OS (Mac/Linux).
- **No Conflicts**: Creates a project-specific environment that doesn't mess with your global tools.

### 2. Activate Environment
Run the following in the project directory to enter the shell with all dependencies ready:

```bash
nix develop
# You should see: 🔐 Secure-Pack Dev Environment ...
```

## Usage

### 1. Sender (Encrypt & Sign)
Bundles, encrypts, and signs the `docs` directory (default) for a specific client.

```bash
# Interactive Mode
go run ./cmd/secure-pack

# CLI Mode
go run ./cmd/secure-pack send --client <client_name>

# Output: dist/bundle_<client>_<timestamp>.spkg.tgz
```

### 2. Receiver (Verify & Decrypt)
Verifies the signature and decrypts the content.

```bash
# CLI Mode
go run ./cmd/secure-pack receive --in <packet_file> --out <output_dir>
```

### 3. Verify Only
Checks signature and checksum without extracting.
`verify` is fail-closed unless signer fingerprint allowlist is configured.

```bash
# Preferred: explicit signer pins (comma/newline separated)
export SECURE_PACK_SIGNER_FINGERPRINTS="SIGNER_FPR_40HEX[,ANOTHER_FPR]"

# Compatible with zt env naming
export ZT_SECURE_PACK_SIGNER_FINGERPRINTS="SIGNER_FPR_40HEX"
```

You can also provide signer pins via `SIGNERS_ALLOWLIST.txt` (or `tools/secure-pack/SIGNERS_ALLOWLIST.txt`),
one fingerprint per line.

```bash
go run ./cmd/secure-pack verify --in <packet_file>
```

## Directory Structure
- `cmd/secure-pack`: CLI entry point
- `internal/`: Core logic (GPG wrapper, Packaging, UI)
- `recipients/`: List of recipient GPG fingerprints
- `dist/`: Output directory

## Troubleshooting

### Build Error: Version Mismatch
If you encounter `compile: version "go1.xx" does not match go tool version "go1.yy"`, it is caused by cache conflicts between Nix and local environments (e.g., Mise). Resolve it by cleaning the cache:

```bash
# Clean cache and force rebuild
go clean -cache -modcache
go build -a -v ./cmd/secure-pack
```
