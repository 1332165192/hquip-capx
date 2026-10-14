#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
mkdir -p dist
for command in captured capx-desktop capx-mcp; do
  go build -mod=readonly -trimpath -ldflags="-s -w" -tags "${TAGS:-}" -o "dist/$command" "./cmd/$command"
done
echo "Built captured, capx-desktop and capx-mcp in $ROOT/dist"
# Optional Frida, Npcap and native engines are installed by the operator.
