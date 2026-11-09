#!/usr/bin/env python3
"""Write a sanitized snapshot of the Master's distillation runs.

The distill state is root-only (`/srv/sparknet/distill`, 0700). The read-only
console runs as the operator and must not read datasets or artifacts directly.
This root-side snapshot exposes only run ids, states, metrics and digests; it
never includes prompts, responses, traces or artifact content.

Run from a root systemd timer. Output is 0644 so the operator can read it inside
the role's 0700 state directory; the directory still controls traversal.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROLE_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = ROLE_ROOT / "configs" / "distill.json"
DEFAULT_STATE = Path("/srv/sparknet/distill")
DEFAULT_OUT = Path.home() / "sparknet" / "master-node" / ".state" / "webui" / "distill-status.json"
DEFAULT_SHARE_OUT = Path("/srv/sparknet/share/learning/status.json")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def snapshot(config_path: Path, state: Path) -> dict[str, Any]:
    config = read_json(config_path)
    runs = []
    errors: list[str] = []
    runs_dir = state / "runs"
    try:
        run_dirs = sorted(runs_dir.glob("*"))[-50:] if runs_dir.is_dir() else []
    except OSError as exc:
        run_dirs = []
        errors.append(f"distill state is not readable: {exc}")
    for run_dir in run_dirs:
        plan = read_json(run_dir / "plan.json")
        run = read_json(run_dir / "run.json")
        evaluation = read_json(run_dir / "eval.json")
        card = read_json(run_dir / "model-card.json")
        runs.append(
            {
                "run_id": run_dir.name,
                "state": (plan or {}).get("state") if isinstance(plan, dict) else None,
                "approved": (run or {}).get("approved") if isinstance(run, dict) else None,
                "eval": (evaluation or {}).get("metrics") if isinstance(evaluation, dict) else None,
                "artifact_sha256": (run or {}).get("artifact_sha256") if isinstance(run, dict) else None,
                "signed": bool((run or {}).get("signature_b64")) if isinstance(run, dict) else False,
                "model_card": bool(card),
            }
        )
    return {
        "schema": "sparknet-distill-status/1",
        "generated_at": now_iso(),
        "config": config if isinstance(config, dict) else None,
        "runs": runs,
        "state_dir": str(state),
        "errors": errors,
        "read_only": True,
    }


def shared_snapshot(value: dict[str, Any]) -> dict[str, Any]:
    """Strip host paths and error detail before the snapshot crosses 4221."""
    shared = {
        "schema": value.get("schema"),
        "generated_at": value.get("generated_at"),
        "config": value.get("config"),
        "runs": value.get("runs") or [],
        "read_only": True,
        "source": "master:distill-status",
    }
    return shared


def write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload = json.dumps(value, indent=2, sort_keys=True) + "\n"
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temp = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp, 0o644)
        os.replace(temp, path)
    except Exception:
        temp.unlink(missing_ok=True)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="write a sanitized Master distillation status snapshot")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--share-out", type=Path, default=None, help="sanitized copy for the 4221 read-only file share")
    args = parser.parse_args(argv)
    try:
        value = snapshot(args.config, args.state)
        write(args.out, value)
        print(f"sparknet-distill-status: wrote {args.out}", file=sys.stderr)
        if args.share_out:
            write(args.share_out, shared_snapshot(value))
            print(f"sparknet-distill-status: wrote {args.share_out}", file=sys.stderr)
        return 0
    except Exception as exc:
        print(f"sparknet-distill-status: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
