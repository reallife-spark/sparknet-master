#!/usr/bin/env python3
"""Root WireGuard observer for the nocturnal batch scheduler.

The unprivileged telemetry pusher cannot read ``wg show`` on this fleet: the
userspace WireGuard anchor reports ``Permission denied`` and sysfs reports zero.
Granting the peer service ``CAP_NET_ADMIN``, a sudo rule or a setuid helper just
to observe idleness would widen the privilege of the process that is closest to
the network. A small root-owned observer is the narrower answer.

This process only reads the Master's own view of the overlay. It does not sign,
grant, revoke, dispatch, listen, or decide that a node is idle. It appends one
sample per run to a bounded history and writes the snapshot atomically. The
scheduler owns the thresholds and the all-nodes conjunction.

Design: ``master-node/plans/NOCTURNAL_BATCH_DESIGN.md`` (Step 9C). The service
and timer are staged, not enabled, because every root timer is an operator
decision and 9G owns the live deployment.

Usage::

    sparknet-wg-observer.py --once
    sparknet-wg-observer.py --check
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "sparknet-wg-observer/1"
DEFAULT_SNAPSHOT = Path("/mnt/log/sparknet-wg.json")
DEFAULT_HISTORY = 30
DEFAULT_INTERFACES = ("wg1", "wg0")
WG_TIMEOUT = 5.0
BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")

CommandRunner = Any


class ObserverError(Exception):
    """A sample that could not be taken; the snapshot records the refusal."""


def _run(argv: Sequence[str], timeout: float = WG_TIMEOUT) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(argv), capture_output=True, text=True, check=False, timeout=timeout)


def _now_iso(now: datetime | None = None) -> str:
    moment = now or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def read_boot_id(path: Path = BOOT_ID_PATH) -> str:
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ObserverError("boot_id_unreadable") from exc
    if not value:
        raise ObserverError("boot_id_unreadable")
    return value


def resolve_interface(explicit: str | None = None) -> str:
    if explicit:
        return explicit
    env = os.environ.get("SPARKNET_WG_INTERFACE", "").strip()
    if env:
        return env
    for name in DEFAULT_INTERFACES:
        if Path(f"/sys/class/net/{name}").is_dir():
            return name
    raise ObserverError("wireguard_interface_unset")


def _valid_key(key: str) -> bool:
    try:
        raw = base64.b64decode(key, validate=True)
    except (binascii.Error, ValueError):
        return False
    return len(raw) == 32


def parse_wg_transfer(text: str) -> list[dict[str, Any]]:
    """Parse ``wg show <if> transfer`` into one row per peer.

    The first field is the peer public key; the last two are rx and tx counters.
    A malformed row is an error, never a zero. Unknown extra columns are ignored
    only after the key and both counters have been read, so a future ``wg``
    output change cannot silently turn traffic into idleness.
    """
    peers: list[dict[str, Any]] = []
    seen: set[str] = set()
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        if len(parts) < 3:
            raise ObserverError("wireguard_malformed")
        key = parts[0]
        if not _valid_key(key):
            raise ObserverError("wireguard_malformed")
        if key in seen:
            raise ObserverError("wireguard_duplicate_peer")
        try:
            rx = int(parts[-2])
            tx = int(parts[-1])
        except ValueError as exc:
            raise ObserverError("wireguard_malformed") from exc
        if rx < 0 or tx < 0:
            raise ObserverError("wireguard_malformed")
        seen.add(key)
        peers.append({"public_key_b64": key, "rx_bytes": rx, "tx_bytes": tx})
    peers.sort(key=lambda row: row["public_key_b64"])
    return peers


def sample(interface: str, run: CommandRunner = _run, now: datetime | None = None) -> dict[str, Any]:
    """Take exactly one sample. Raises :class:`ObserverError` on any refusal."""
    try:
        result = run(["wg", "show", interface, "transfer"])
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ObserverError("wireguard_unavailable") from exc
    if result.returncode != 0:
        raise ObserverError("wireguard_unreadable")
    peers = parse_wg_transfer(result.stdout)
    return {
        "sampled_at": _now_iso(now),
        "interface": interface,
        "peers": peers,
    }


def _load_history(path: Path, boot_id: str, interface: str) -> list[dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, dict):
        return []
    if data.get("schema_version") != SCHEMA_VERSION:
        return []
    if data.get("boot_id") != boot_id or data.get("interface") != interface:
        return []
    history = data.get("history")
    if not isinstance(history, list):
        return []
    return [row for row in history if isinstance(row, dict)][-DEFAULT_HISTORY:]


def build_snapshot(
    *,
    boot_id: str,
    interface: str,
    current: dict[str, Any] | None,
    previous: list[dict[str, Any]],
    error: str | None,
    history_limit: int = DEFAULT_HISTORY,
) -> dict[str, Any]:
    history = list(previous)
    if current is not None:
        history.append(current)
        history = history[-history_limit:]
    latest = current or (history[-1] if history else None)
    return {
        "schema_version": SCHEMA_VERSION,
        "boot_id": boot_id,
        "sampled_at": latest.get("sampled_at") if latest else _now_iso(),
        "interface": interface,
        "peers": latest.get("peers", []) if latest else [],
        "history": history,
        "errors": [error] if error else [],
    }


def write_snapshot(path: Path, snapshot: dict[str, Any]) -> None:
    """Atomic 0644 write: public keys and byte counters are not secrets."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(snapshot, sort_keys=True, indent=2) + "\n"
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temp = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp, 0o644)
        os.replace(temp, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError:
        temp.unlink(missing_ok=True)
        raise


def observe(
    *,
    snapshot_path: Path = DEFAULT_SNAPSHOT,
    interface: str | None = None,
    run: CommandRunner = _run,
    now: datetime | None = None,
    boot_id_path: Path = BOOT_ID_PATH,
    history_limit: int = DEFAULT_HISTORY,
) -> dict[str, Any]:
    """Sample, merge history and write. A failed sample is recorded, not hidden."""
    boot = read_boot_id(boot_id_path)
    iface = interface or resolve_interface()
    previous = _load_history(snapshot_path, boot, iface)
    try:
        current = sample(iface, run=run, now=now)
        error = None
    except ObserverError as exc:
        current = None
        error = str(exc)
    snapshot = build_snapshot(
        boot_id=boot,
        interface=iface,
        current=current,
        previous=previous,
        error=error,
        history_limit=history_limit,
    )
    write_snapshot(snapshot_path, snapshot)
    if error:
        raise ObserverError(error)
    return snapshot


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Root WireGuard observer for the nocturnal scheduler")
    parser.add_argument("--once", action="store_true", help="take one sample and write the snapshot (default)")
    parser.add_argument("--check", action="store_true", help="print one sample without writing the snapshot")
    parser.add_argument("--interface", default=None, help="WireGuard interface; auto-detect wg1 then wg0")
    parser.add_argument("--snapshot", default=os.environ.get("SPARKNET_WG_SNAPSHOT", str(DEFAULT_SNAPSHOT)))
    parser.add_argument("--history", type=int, default=DEFAULT_HISTORY, help="samples retained (default 30)")
    parser.add_argument("--now", default=None, help="fixed ISO timestamp for tests")
    args = parser.parse_args(argv)

    now = None
    if args.now:
        try:
            now = datetime.fromisoformat(args.now.replace("Z", "+00:00"))
        except ValueError:
            print("sparknet-wg-observer: --now must be ISO-8601", file=sys.stderr)
            return 2
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)

    try:
        if args.check:
            iface = args.interface or resolve_interface()
            current = sample(iface, now=now)
            print(json.dumps({"boot_id": read_boot_id(), **current}, sort_keys=True, indent=2))
            return 0
        observe(
            snapshot_path=Path(args.snapshot),
            interface=args.interface,
            now=now,
            history_limit=max(1, args.history),
        )
    except ObserverError as exc:
        print(f"sparknet-wg-observer: {exc}", file=sys.stderr)
        return 1
    print(f"wrote {args.snapshot}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
