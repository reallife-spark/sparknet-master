#!/usr/bin/env bash
# Publish a registry to an output location.
set -euo pipefail

ROLE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "$ROLE_ROOT/scripts/sparknet-master-env.sh" >/dev/null

REGISTRY=""
OUT=""

usage() {
  cat <<'USAGE'
usage: sparknet-registry-publish.sh --registry <registry.json> --out <dest>
USAGE
}
while [ $# -gt 0 ]; do
  case "$1" in
    --registry) REGISTRY="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    -h|--help)  usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done
[ -n "$REGISTRY" ] || { echo "--registry required" >&2; exit 1; }
[ -f "$REGISTRY" ] || { echo "registry not found" >&2; exit 1; }
[ -n "$OUT" ] || { echo "--out required" >&2; exit 1; }

mkdir -p "$(dirname "$OUT")"
cp "$REGISTRY" "$OUT"
echo "published $REGISTRY -> $OUT"
