#!/usr/bin/env python3
"""The elected Master's hash-chained ledger.

Records the agreement events a peer cannot observe: an election outcome, a
cluster trust root being formed or re-formed, a trust-level change, and every
signature the isolated signer produced.

A peer's ledger records what happened *to that peer*. Only the Master's can record
who decided what — which is why the Master keeps its own rather than reading a
peer's.

The chain rules and the block schema are the peer's, defined once in
``peer-node/blockchain/ledger.schema.json`` and not restated here. What this
service adds is the block *content* for Master-side events.

Currently it can only ``verify`` the chain. There is no ``append`` yet: appending
requires the signer (Step 17), because election and root events must be signed by
the operational key rather than written by an unsigned process. An unsigned append
would let anyone with write access rewrite history, which is precisely what a
hash chain exists to prevent — so the honest state is "verifies, does not yet
append".
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROLE_ROOT = Path(__file__).resolve().parent.parent
LEDGER_PATH = ROLE_ROOT / "blockchain" / "ledger.json"

#: Block fields the schema requires. Mirrors peer-node/blockchain/ledger.schema.json.
REQUIRED_FIELDS = ("block_id", "prev_hash", "timestamp", "signature", "data")

#: Event kinds only the Master records. A peer never writes these, because a peer
#: cannot observe them.
MASTER_EVENTS = (
    "election_outcome",
    "trust_root_formed",
    "trust_root_reformed",
    "trust_level_changed",
    "signature_issued",
    "share_ratified",
)


def load_ledger(path: Path = LEDGER_PATH) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"ledger not found: {path}")
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise ValueError(f"ledger is not valid JSON: {exc}") from exc


def block_hash(block: dict[str, Any]) -> str:
    """The chain hash of a block: sha256 over everything except the hash itself.

    Excluding nothing else matters. A field that was not covered would be freely
    editable without breaking the chain, which would make the chain decorative.
    """
    payload = {k: v for k, v in block.items() if k != "hash"}
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def verify_chain(ledger: dict[str, Any]) -> tuple[bool, str]:
    """Walk the chain and check every link.

    Returns ``(ok, detail)`` rather than raising: a ledger that is merely invalid
    is an operational fact, not a crash. The genesis block's ``prev_hash`` is the
    empty string, so there is no sentinel value to special-case.
    """
    blocks = ledger.get("blocks")
    if not isinstance(blocks, list):
        return False, "ledger has no blocks array"
    previous = ""
    for index, block in enumerate(blocks):
        if not isinstance(block, dict):
            return False, f"block {index} is not an object"
        missing = [f for f in REQUIRED_FIELDS if f not in block]
        if missing:
            return False, f"block {index} missing {', '.join(missing)}"
        if block["prev_hash"] != previous:
            return False, (
                f"block {index} ({block['block_id']}) links to "
                f"{block['prev_hash']!r}, expected {previous!r}"
            )
        if "hash" in block and block["hash"] != block_hash(block):
            return False, (
                f"block {index} ({block['block_id']}) has been altered: its "
                f"contents do not hash to its recorded hash"
            )
        previous = block["hash"] if "hash" in block else block_hash(block)
    return True, f"{len(blocks)} block(s), chain intact"


def describe(ledger: dict[str, Any] | None = None) -> dict[str, Any]:
    data = ledger if ledger is not None else load_ledger()
    ok, detail = verify_chain(data)
    return {
        "path": str(LEDGER_PATH),
        "blocks": len(data.get("blocks", [])),
        "chain_valid": ok,
        "detail": detail,
        "can_append": False,
        "can_append_note": (
            "append is deliberately absent: a block must be signed by the "
            "operational key, and the signer lands in build plan Step 17. An "
            "unsigned append would let anyone with write access rewrite the "
            "history a hash chain exists to protect."
        ),
        "master_only_events": list(MASTER_EVENTS),
    }


def main(argv: list[str] | None = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    command = args[0] if args else "verify"
    if command not in {"verify", "describe"}:
        print(f"[ledger] unknown command {command!r}; expected verify or describe",
              file=sys.stderr)
        return 2
    try:
        report = describe()
    except (FileNotFoundError, ValueError) as exc:
        print(f"[ledger] {exc}", file=sys.stderr)
        return 1
    if command == "verify":
        print(f"[ledger] {report['detail']}")
        return 0 if report["chain_valid"] else 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
