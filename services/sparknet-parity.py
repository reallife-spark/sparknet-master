#!/usr/bin/env python3
"""Master node parity: this role runs the peer's node services, not a copy of them.

A Master is a peer that won an election. It has the same guard, the same
dispatch bridge, the same overlay anchor, the same ledger — the only difference is
that its node state also holds an operational key, and that key lives in a
separate signer this module deliberately does not reach.

So this module **loads the peer's services by path** rather than carrying its own
copies. The pattern is the one already proven in production at
``peer-node/services/sparknet-guard-d.py:293`` (``_load_authz_module``): resolve a
candidate path, register it in ``sys.modules``, then execute. Following a pattern
that already ships is deliberate — inventing a second loader is how two roles end
up disagreeing about how a shared module was resolved.

**Why not copy the files.** Two copies of a service that verifies signatures would
drift, and the failure would be silent and intermittent: correct on the node that
produced the copy, wrong on the other. ``tests/test_master_parity.py`` asserts that
this module resolves each peer service to the same file the peer itself uses, so a
copy appearing here fails the build.

What this module is *not*: a place to add master-specific logic. Anything only the
Master does belongs in this role's own service, not smuggled into a re-export.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from types import ModuleType

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "shared"))
from sparknet_loader import load_by_path

ROLE_ROOT = Path(__file__).resolve().parent.parent

#: Peer services this role runs. Each is resolved to the peer's file, never copied.
PEER_SERVICES = (
    "sparknet-guard-d.py",
    "sparknet-dispatch-bridge.py",
)


def _candidate_service_dirs() -> list[Path]:
    """Directories the peer's services may live in, most specific first.

    Entries are *role roots*; each is probed both directly and under
    ``services/``, so a bundle that flattens the tree and one that keeps the
    layout both resolve. ``SPARKNET_PEER_NODE`` exists so a master bundle that
    ships the peer alongside it resolves without guessing, and so a test can point
    this at a fixture.
    """
    roots: list[Path] = []
    env = os.environ.get("SPARKNET_PEER_NODE")
    if env:
        roots.append(Path(env))
    roots.append(ROLE_ROOT.parent / "peer-node")  # sibling role
    roots.append(ROLE_ROOT)  # a bundle that flattened the tree
    roots.append(Path("/srv/sparknet/peer-node"))  # container image layout
    seen: set[Path] = set()
    dirs: list[Path] = []
    for root in roots:
        for candidate in (root / "services", root):
            resolved = candidate.resolve() if candidate.exists() else candidate
            if resolved not in seen:
                seen.add(resolved)
                dirs.append(resolved)
    return dirs


def peer_services_dir() -> Path:
    """The directory the peer's services are loaded from.

    Raises rather than falling back to a local copy: if the peer is not reachable
    the honest answer is that parity is unavailable, not that this role should
    quietly run something subtly different from what the peer runs.
    """
    for directory in _candidate_service_dirs():
        if all((directory / name).is_file() for name in PEER_SERVICES):
            return directory
    raise ParityError(
        "cannot find the peer's services; looked in "
        + ", ".join(str(p) for p in _candidate_service_dirs())
        + ". Set SPARKNET_PEER_NODE to the peer's role root. This role will not "
        "fall back to a private copy: two copies of a signature-verifying "
        "service would drift, and the failure would be silent."
    )


def load_peer_service(name: str) -> ModuleType:
    """Load one peer service by path, once.

    The ``sys.modules`` registration before ``exec_module`` is not optional:
    ``@dataclass`` resolves its own module through ``sys.modules`` and fails with
    an AttributeError about ``__dict__`` that says nothing about the cause.
    """
    if name not in PEER_SERVICES:
        raise ParityError(f"{name!r} is not a peer service this role runs; expected one of {', '.join(PEER_SERVICES)}")
    directory = peer_services_dir()
    module_name = "sparknet_peer_" + name.removesuffix(".py").replace("-", "_")
    if module_name in sys.modules:
        return sys.modules[module_name]
    path = directory / name
    return load_by_path(module_name, path)


def resolved_paths() -> dict[str, str]:
    """Where each peer service actually resolves to, for the bundle's own records."""
    directory = peer_services_dir()
    return {name: str((directory / name).resolve()) for name in PEER_SERVICES}


class ParityError(Exception):
    """Raised when parity cannot be established."""


def parity_report() -> dict:
    """What parity this role currently has, for `make parity` and for tests."""
    paths = resolved_paths()
    return {
        "peer_services_dir": str(peer_services_dir()),
        "services": paths,
        "one_copy": True,
        "rule": "each path above is the peer's own file, loaded by path",
        "not_reachable_from_here": [
            "services/sparknet-signer.py — the operational key is loaded by that "
            "process alone, and no peer service may load it"
        ],
    }


def main(argv: list[str] | None = None) -> int:
    import json

    try:
        print(json.dumps(parity_report(), indent=2))
    except ParityError as exc:
        print(f"[parity] {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
