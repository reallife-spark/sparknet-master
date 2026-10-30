#!/usr/bin/env bash
# Master KillSwitch wrapper
set -euo pipefail
# --help BEFORE the root gate: without it, this wrapper handed `--help` straight
# to sparknet-killswitch.py — as root that is the killswitch itself, not a usage
# message. A destructive script must answer a help request without becoming one.
case "${1:-}" in
  -h|--help)
    printf '%s\n' \
      'sparknet-killswitch.sh — take this node out of the overlay (Master role)' \
      '' \
      'Usage:' \
      '  sudo scripts/sparknet-killswitch.sh              dry-run (default)' \
      '  sudo scripts/sparknet-killswitch.sh --force      engage containment' \
      '  scripts/sparknet-killswitch.sh --help            print this text and exit' \
      '' \
      'Requires root even for a dry-run: this is the Master cluster KillSwitch,' \
      'not peer node-containment. It stops the fabric control planes, removes' \
      'the overlay and installs an emergency iptables drop policy.' \
      'Delegates to services/sparknet-killswitch.py; override the interpreter' \
      'with PY=<path>.'
    exit 0 ;;
esac
ROLE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[ "$(id -u)" -eq 0 ] || { echo "root required" >&2; exit 1; }
PY="${PY:-python3}"
$PY "$ROLE_ROOT/services/sparknet-killswitch.py" "$@"
