#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

CLIENT="${ZT_RELAY_HOOK_CLIENT:-}"
SHARE_FORMAT="${ZT_RELAY_HOOK_SHARE_FORMAT:-auto}"
JSON_FLAG="${ZT_RELAY_HOOK_JSON:-1}"
ZT_BIN="${ZT_BIN:-}"

if [[ -z "${CLIENT}" ]]; then
  echo "ZT_RELAY_HOOK_CLIENT is required (example: export ZT_RELAY_HOOK_CLIENT=clientA)" >&2
  exit 64
fi

if [[ "$#" -eq 0 ]]; then
  echo "No files selected. Finder Quick Action requires at least one path." >&2
  exit 64
fi

cmd=("go" "run" "./gateway/zt")
if [[ -n "${ZT_BIN}" ]]; then
  cmd=("${ZT_BIN}")
fi

args=("relay" "hook" "finder-quick-action" "--client" "${CLIENT}" "--share-format" "${SHARE_FORMAT}")
if [[ "${JSON_FLAG}" == "1" || "${JSON_FLAG}" == "true" ]]; then
  args+=("--json")
fi

(
  cd "${REPO_ROOT}"
  "${cmd[@]}" "${args[@]}" "$@"
)
