#!/usr/bin/env python3
"""Master-side offline-repair reviewer.

Reads a peer's `offline-repair` spool, verifies each node-signed record against
the Registry-attested node key and fingerprint, and writes a review file. It
never applies the change and never turns a record into a capability, grant,
registry entry or approval: an isolated node may report a local repair, not
widen authority.

The envelope refusal rules live in `shared/sparknet-authz.py`; the policy
verifier lives in `shared/sparknet-sso.py`.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROLE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROLE_ROOT.parent / "shared"))

try:
    from sparknet_loader import load_shared
except ImportError as exc:  # pragma: no cover - the bundle always carries the loader
    raise SystemExit(f"cannot load shared/sparknet_loader.py: {exc}") from exc

DEFAULT_REGISTRY = ROLE_ROOT / "manifests" / "node-authorizations.json"


def _load_sso() -> Any:
    return load_shared(
        "sparknet-sso.py",
        "sparknet_sso_offline_review",
        required=("sparknet-authz.py", "sparknet-sso.py"),
        error=RuntimeError,
        message="cannot find shared/sparknet-sso.py; the reviewer carries no policy copy",
    )


def _state_dir(explicit: str | Path | None) -> Path:
    if explicit:
        return Path(explicit)
    env = os.environ.get("SPARKNET_STATE_DIR", "").strip()
    if env:
        return Path(env)
    return Path.home() / ".local" / "state" / "sparknet" / "master-node"


def _registry_entry(registry: Path, node_id: str) -> dict[str, Any]:
    data = json.loads(registry.read_text(encoding="utf-8"))
    for entry in data.get("authorizations") or []:
        identity = entry.get("identity") or {}
        if identity.get("node_id") == node_id:
            return entry
    raise ValueError(f"no registry entry for {node_id!r}")


def _load_records(spool: Path) -> list[dict[str, Any]]:
    if not spool.exists():
        return []
    records: list[dict[str, Any]] = []
    with spool.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                records.append(row)
    return records


def review(
    *,
    registry: Path,
    spool: Path,
    node_id: str,
    node_pubkey_b64: str | None,
    output: Path,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    sso = _load_sso()
    entry = _registry_entry(registry, node_id)
    fingerprint = str(entry.get("fingerprint") or "")
    public_b64 = node_pubkey_b64 or entry.get("node_pubkey_b64")
    if not public_b64:
        raise ValueError(f"registry entry for {node_id!r} carries no node_pubkey_b64; pass --node-pubkey")
    public_key = sso.public_key_from_b64(str(public_b64))
    instant = (now or datetime.now(timezone.utc)).isoformat().replace("+00:00", "Z")
    reviewed: list[dict[str, Any]] = []
    for record in _load_records(spool):
        ok, reason = sso.verify_offline_repair(
            record,
            public_key,
            expected_node_id=node_id,
            expected_fingerprint=fingerprint,
            now=now,
        )
        reviewed.append(
            {
                "reviewed_at": instant,
                "node_id": node_id,
                "repair_id": record.get("repair_id"),
                "action": record.get("action"),
                "ok": ok,
                "reason": reason or None,
                "record": record,
                "applied": False,
                "note": "review evidence only; local repair state is preserved, authority is never propagated",
            }
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(output, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
    try:
        for row in reviewed:
            os.write(fd, (json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"))
    finally:
        os.close(fd)
    return reviewed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Master offline-repair reviewer (evidence, never authority)")
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--spool", type=Path, required=True)
    parser.add_argument("--node-id", required=True)
    parser.add_argument("--node-pubkey", default=None)
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--state-dir", type=Path, default=None)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    output = args.out or (_state_dir(args.state_dir) / "admin-events" / "offline-repair-review.jsonl")
    try:
        reviewed = review(
            registry=args.registry,
            spool=args.spool,
            node_id=args.node_id,
            node_pubkey_b64=args.node_pubkey,
            output=output,
        )
    except (OSError, ValueError) as exc:
        print(f"[offline-review] {exc}", file=sys.stderr)
        return 1
    accepted = sum(1 for row in reviewed if row["ok"])
    summary = {
        "node_id": args.node_id,
        "records": len(reviewed),
        "accepted": accepted,
        "refused": len(reviewed) - accepted,
        "output": str(output),
        "applied": False,
    }
    print(json.dumps(summary, indent=2, sort_keys=True) if args.json else _human(summary, reviewed))
    return 0 if accepted == len(reviewed) else 2


def _human(summary: dict[str, Any], reviewed: list[dict[str, Any]]) -> str:
    lines = [
        f"node:     {summary['node_id']}",
        f"records:  {summary['records']} ({summary['accepted']} accepted, {summary['refused']} refused)",
        f"review:   {summary['output']}",
    ]
    for row in reviewed:
        if not row["ok"]:
            lines.append(f"  refused {row.get('repair_id')}: {row.get('reason')}")
    lines.append("No record was applied. Authority changes stay held for a human.")
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
