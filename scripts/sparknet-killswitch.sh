#!/usr/bin/env bash
# Master KillSwitch wrapper
set -euo pipefail
ROLE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[ "$(id -u)" -eq 0 ] || { echo "root required" >&2; exit 1; }
PY="${PY:-python3}"
$PY "$ROLE_ROOT/services/sparknet-killswitch.py"
