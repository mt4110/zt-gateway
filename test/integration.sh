#!/bin/sh
set -eu

# Test-only keys, policies and packets live in a separate temporary workspace.
# Use `nix develop --command ./test/integration.sh` for pinned runtime tools.
exec python3 "$(dirname "$0")/integration.py" "$@"
