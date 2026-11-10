#!/usr/bin/env python3
"""Record one local Master triage transition.

The ledger is append-only and the JSON view is derived. This writes state only:
it does not sign, grant authority, install knowledge or send anything to a peer.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
ROLE_ROOT = SCRIPT_DIR.parent
FABRIC_ROOT = ROLE_ROOT.parent
SHARED = FABRIC_ROOT / "shared"
sys.path.insert(0, str(SHARED))
from sparknet_loader import load_shared  # noqa: E402 - shared/ is added by path above

issue = load_shared(
    "sparknet-issue.py",
    "sparknet_issue_triage_cli",
    dirs=[SHARED],
    error=RuntimeError,
    message="cannot find shared/sparknet-issue.py; the triage CLI carries no fallback",
)


def default_state_dir() -> Path:
    configured = os.environ.get("SPARKNET_STATE_DIR", "").strip()
    return Path(configured) if configured else ROLE_ROOT / ".state"


def transition(
    *,
    state_dir: Path,
    node_id: str,
    issue_id: str,
    status: str | None,
    labels: list[str] | None,
    actor: str,
    note: str,
) -> dict:
    return issue.TriageStore(state_dir).transition(
        node_id,
        issue_id,
        status=status,
        labels=labels,
        actor=actor,
        note=note,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Record a local Master issue triage transition")
    parser.add_argument("--state-dir", type=Path, default=default_state_dir())
    parser.add_argument("--node-id", required=True)
    parser.add_argument("--issue-id", required=True)
    parser.add_argument("--status")
    parser.add_argument("--label", action="append", default=[])
    parser.add_argument("--actor", default="operator")
    parser.add_argument("--note", default="")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    labels = args.label or None
    if args.status is None and labels is None:
        parser.error("choose --status or --label")
    try:
        row = transition(
            state_dir=args.state_dir,
            node_id=args.node_id,
            issue_id=args.issue_id,
            status=args.status,
            labels=labels,
            actor=args.actor,
            note=args.note,
        )
    except issue.IssueError as exc:
        print(f"issue-triage: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(row, indent=2, sort_keys=True))
    else:
        changed = []
        if "status" in row:
            changed.append(row["status"])
        if "labels" in row:
            changed.append(",".join(row["labels"]))
        print(f"issue-triage: {args.node_id}:{args.issue_id} -> {' · '.join(changed)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
