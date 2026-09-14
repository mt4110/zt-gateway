#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

pack_doc="docs/V1_SALES_OPERATIONS_PACK.md"

if [[ ! -f "${pack_doc}" ]]; then
  echo "[v1.0-sales-pack-gate] missing ${pack_doc}" >&2
  exit 1
fi

required_headers=(
  "## 1. 導入チェックリスト（初回 30 分）"
  "## 2. Security Note（販売説明用）"
  "## 3. Runbook（最短運用手順）"
  "## 4. 5分デモ手順（営業同席テンプレ）"
  "## 5. デモ前の固定確認（失敗防止）"
)

for header in "${required_headers[@]}"; do
  if ! rg -F -q "${header}" "${pack_doc}"; then
    echo "[v1.0-sales-pack-gate] missing header: ${header}" >&2
    exit 1
  fi
done

echo "[v1.0-sales-pack-gate] ok"

