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

This service can **verify** the chain, and only that. Appending lives in the
signer (`sparknet-signer.py record_event`), because every Master event must be
signed by the operational key rather than written by an unsigned process: an
unsigned append would let anyone with write access rewrite the history a hash
chain exists to prevent. One process writes, and it is the one holding the key.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROLE_ROOT = Path(__file__).resolve().parent.parent

# --- the one by-path loader (D10) --------------------------------------------
# This service lives in master-node/services/, so it puts the fabric's shared/
# on sys.path (the same directory its authz candidates resolve to) before
# importing the fabric's single loader. These lines are deliberately the same
# shape as every shared module; tests/contracts/test_shared_implementation.py
# pins the pattern.
sys.path.insert(0, str(ROLE_ROOT.parent / "shared"))
from sparknet_loader import load_shared  # noqa: E402 - import after the loader path shim

LEDGER_PATH = ROLE_ROOT / "blockchain" / "ledger.json"

#: Block fields the schema requires. Mirrors peer-node/blockchain/ledger.schema.json.
REQUIRED_FIELDS = ("block_id", "prev_hash", "timestamp", "node_pubkey_b64", "signature", "data")


def _load_authz() -> Any:
    """Load sparknet-authz.py by path, never by import.

    The block header canonical form lives there once, shared with the peer's
    provenance module and the signer. Loading by path is what proves there is one
    implementation; an import would let this role quietly carry a private copy
    whose hash and signature rules could drift. The resolve-and-cache mechanics
    live once in ``shared/sparknet_loader.py``.
    """
    return load_shared(
        "sparknet-authz.py",
        "sparknet_authz",
        dirs=[ROLE_ROOT.parent / "shared", ROLE_ROOT / "shared"],
        error=RuntimeError,
        message=("cannot locate sparknet-authz.py; this module refuses to reimplement the ledger block canonical form"),
    )


#: Event kinds only the Master records. A peer never writes these, because a peer
#: cannot observe them.
MASTER_EVENTS = (
    "election_outcome",
    "trust_root_formed",
    "trust_root_reformed",
    "trust_level_changed",
    "signature_issued",
    "share_ratified",
    "share_evidence",
)


def trusted_pubkey_from_state() -> str | None:
    """Read the operational key named by the node's trust root, if one exists.

    The ledger verifier is run by operators and by the signer's preflight. A
    ledger whose blocks are self-signed by an arbitrary key must not be called
    valid merely because every block verifies against its own header. The trust
    root is the local anchor; when it is absent (a development checkout) the
    caller must supply ``--pubkey`` or explicitly accept an unpinned check.
    """
    import os

    state = os.environ.get("SPARKNET_STATE_DIR")
    candidates = []
    if state:
        candidates.append(Path(state) / "trust-root.json")
    candidates.append(Path.home() / ".local" / "state" / "sparknet" / "master-node" / "trust-root.json")
    for path in candidates:
        if not path.is_file():
            continue
        try:
            document = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        value = document.get("master_pubkey") if isinstance(document, dict) else None
        if isinstance(value, str) and value:
            return value
    return None


def load_ledger(path: Path = LEDGER_PATH) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"ledger not found: {path}")
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise ValueError(f"ledger is not valid JSON: {exc}") from exc


def block_hash(block: dict[str, Any]) -> str:
    """The chain hash of a block: sha256 over everything except the hash itself.

    Delegates to the one implementation in shared/sparknet-authz.py so the peer,
    this verifier and the signer cannot disagree about the canonical form.
    """
    return _load_authz().ledger_block_hash(block)


def verify_chain(ledger: dict[str, Any], expected_pubkey_b64: str | None = None) -> tuple[bool, str]:
    """Walk the chain and check every link.

    Returns ``(ok, detail)`` rather than raising: a ledger that is merely invalid
    is an operational fact, not a crash. Every block's *header* is signed (the
    whole block minus ``hash`` and ``signature``), so this verifies the header
    signature against the block's own ``node_pubkey_b64`` in addition to the
    hash chain; a deleted, reordered or edited block fails. The genesis link comes
    from the ledger's ``genesis_hash`` rather than a hard-coded empty string.
    """
    authz = _load_authz()
    blocks = ledger.get("blocks")
    if not isinstance(blocks, list):
        return False, "ledger has no blocks array"
    previous = str(ledger.get("genesis_hash", ""))
    seen_expected = False
    for index, block in enumerate(blocks):
        if not isinstance(block, dict):
            return False, f"block {index} is not an object"
        missing = [f for f in REQUIRED_FIELDS if f not in block]
        if missing:
            return False, f"block {index} missing {', '.join(missing)}"
        expected_id = f"{index:08d}"
        if block["block_id"] != expected_id:
            return False, (
                f"block {index} has block_id {block['block_id']!r}, expected "
                f"{expected_id!r}: the chain has been reordered or a block removed"
            )
        if not str(block["signature"] or ""):
            return False, f"block {index} ({block['block_id']}) carries no signature"
        if block["prev_hash"] != previous:
            return False, (
                f"block {index} ({block['block_id']}) links to {block['prev_hash']!r}, expected {previous!r}"
            )
        if expected_pubkey_b64:
            if block["node_pubkey_b64"] == expected_pubkey_b64:
                seen_expected = True
            elif seen_expected:
                return False, (
                    f"block {index} ({block['block_id']}) returns to an old key after the "
                    "trusted operational key took over"
                )
        try:
            node_pub = authz.public_key_from_b64(str(block["node_pubkey_b64"] or ""))
        except Exception as exc:
            return False, f"block {index} ({block['block_id']}) has an unusable node_pubkey_b64: {exc}"
        if not authz.verify_signature(node_pub, str(block["signature"]), authz.ledger_block_signable(block)):
            return False, (
                f"block {index} ({block['block_id']}) header signature does not "
                f"verify: the block was edited, reordered or forged"
            )
        if "hash" in block and block["hash"] != block_hash(block):
            return False, (
                f"block {index} ({block['block_id']}) has been altered: its contents do not hash to its recorded hash"
            )
        previous = block["hash"] if "hash" in block else block_hash(block)
    if expected_pubkey_b64 and not seen_expected:
        return False, "no block is signed by the trusted operational key"
    return True, f"{len(blocks)} block(s), chain intact"


def describe(ledger: dict[str, Any] | None = None, expected_pubkey_b64: str | None = None) -> dict[str, Any]:
    data = ledger if ledger is not None else load_ledger()
    ok, detail = verify_chain(data, expected_pubkey_b64)
    return {
        "path": str(LEDGER_PATH),
        "blocks": len(data.get("blocks", [])),
        "chain_valid": ok,
        "detail": detail,
        "can_append": False,
        "can_append_note": (
            "append is deliberately absent from this verifier: a block must be "
            "signed by the operational key, and only the isolated signer holds it "
            "(`sparknet-signer.py record_event`). An unsigned append would let "
            "anyone with write access rewrite the history a hash chain exists to "
            "protect."
        ),
        "master_only_events": list(MASTER_EVENTS),
    }


def main(argv: list[str] | None = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    command = args[0] if args else "verify"
    expected_pubkey_b64 = None
    if "--pubkey" in args:
        position = args.index("--pubkey")
        if position + 1 >= len(args):
            print("[ledger] --pubkey requires a value", file=sys.stderr)
            return 2
        expected_pubkey_b64 = args[position + 1]
        args = args[:position] + args[position + 2 :]
    if command not in {"verify", "describe"}:
        print(f"[ledger] unknown command {command!r}; expected verify or describe", file=sys.stderr)
        return 2
    expected_pubkey_b64 = expected_pubkey_b64 or trusted_pubkey_from_state()
    if expected_pubkey_b64 is None:
        try:
            existing = load_ledger()
        except (FileNotFoundError, ValueError):
            existing = {"blocks": []}
        if existing.get("blocks"):
            print(
                "[ledger] no pinned operational key and the ledger is non-empty; refusing an unpinned verify",
                file=sys.stderr,
            )
            return 2
    try:
        report = describe(expected_pubkey_b64=expected_pubkey_b64)
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
