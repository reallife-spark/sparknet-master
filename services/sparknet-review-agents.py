#!/usr/bin/env python3
"""Review agents and trust decisions (Step 12).

Produce a finding for each evidence event without modifying the evidence, and
emit a reversible trust belief. The belief is signed by the isolated signer and
recorded in the Master ledger; it never writes the registry or a grant, because
a trust level is a belief and only permissions live in signed registry entries.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROLE_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REPO = ROLE_ROOT / "evidence-repo"
DEFAULT_REGISTRY = ROLE_ROOT / "state" / "registry.json"
TRUST_LEVELS = ("authenticated", "unauthenticated", "flagged")


def _iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class ReviewAgent:
    def __init__(
        self,
        evidence_repo: str | Path = "master-node/evidence-repo",
        registry_path: str | Path = "master-node/state/registry.json",
    ):
        self.evidence_repo = Path(evidence_repo)
        self.registry_path = Path(registry_path)

    def produce_finding(self, event: dict[str, Any]) -> dict[str, Any]:
        return {
            "finding_id": f"f-{event.get('event_type')}-{_iso()}",
            "event_type": event.get("event_type"),
            "finding": "reviewed",
            "evidence_preserved": True,
            "created_at": _iso(),
        }

    def review_repo(self) -> list[dict[str, Any]]:
        """One finding per evidence event; the event files are only read."""
        events_dir = self.evidence_repo / "events"
        if not events_dir.is_dir():
            return []
        findings: list[dict[str, Any]] = []
        for event_file in sorted(events_dir.glob("*.json")):
            try:
                event = json.loads(event_file.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if isinstance(event, dict):
                finding = self.produce_finding(event)
                finding["evidence_file"] = event_file.name
                findings.append(finding)
        return findings

    def transition_trust(
        self,
        node_id: str,
        level: str,
        reason: str,
        *,
        previous_level: str | None = "flagged",
        signer: Any | None = None,
    ) -> dict[str, Any]:
        if level not in TRUST_LEVELS:
            raise ValueError("invalid trust level")
        if previous_level is not None and previous_level not in TRUST_LEVELS:
            raise ValueError("invalid previous trust level")
        transition = {
            "schema_version": "1.0",
            "node_id": node_id,
            "level": level,
            "previous_level": previous_level,
            "reason": reason,
            "decided_at": _iso(),
            "reversible": True,
            "flag_preserved": True,
        }
        if signer is None:
            return transition
        signed = signer(transition)
        if not isinstance(signed, dict):
            raise ValueError("signer returned no trust transition")
        return signed


def _read_event(path: str) -> Any:
    if path == "-":
        return json.load(sys.stdin)
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _default_signer_socket() -> Path:
    env = os.environ.get("SPARKNET_STATE_DIR")
    if env:
        return Path(env) / "signer" / "signer.sock"
    xdg = os.environ.get("XDG_STATE_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "state"
    return base / "sparknet" / "master-node" / "signer" / "signer.sock"


def _recv_line(connection: socket.socket, max_bytes: int = 1 << 20) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = connection.recv(4096)
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > max_bytes:
            raise ValueError("signer response too large")
        if b"\n" in chunk:
            break
    return b"".join(chunks).split(b"\n", 1)[0]


class SignerClient:
    def __init__(self, socket_path: str | Path, *, timeout: float = 30.0):
        self.socket_path = Path(socket_path)
        self.timeout = timeout

    def call(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not self.socket_path.exists():
            raise ValueError(f"signer socket {self.socket_path} does not exist")
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(self.timeout)
        try:
            connection.connect(str(self.socket_path))
            connection.sendall(json.dumps(payload).encode("utf-8") + b"\n")
            line = _recv_line(connection)
        finally:
            connection.close()
        return json.loads(line.decode("utf-8"))

    def root_id(self) -> str:
        response = self.call({"op": "root-id"})
        if not response.get("ok"):
            raise ValueError(str(response.get("error")))
        return str(response["root_id"])

    def sign_transition(self, transition: dict[str, Any]) -> dict[str, Any]:
        response = self.call({"op": "sign-trust-transition", "root_id": self.root_id(), "transition": transition})
        if not response.get("ok"):
            raise ValueError(str(response.get("error")))
        return response["transition"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event", default="-", help="JSON event file, or - for stdin")
    parser.add_argument("--review-repo", action="store_true", help="Produce findings for every evidence event")
    parser.add_argument("--evidence-repo", default=str(DEFAULT_REPO), help="Evidence repository root")
    parser.add_argument("--registry", default=str(DEFAULT_REGISTRY), help="Registry path")
    parser.add_argument("--trust-node", default=None, help="Emit a trust transition for this node")
    parser.add_argument("--level", choices=TRUST_LEVELS, default=None, help="Trust level for --trust-node")
    parser.add_argument("--previous-level", choices=TRUST_LEVELS, default="flagged")
    parser.add_argument("--reason", default="", help="Reason for the trust transition")
    parser.add_argument("--signer-socket", default=str(_default_signer_socket()))
    args = parser.parse_args(argv)

    agent = ReviewAgent(evidence_repo=args.evidence_repo, registry_path=args.registry)
    try:
        if args.review_repo:
            print(json.dumps(agent.review_repo(), sort_keys=True, indent=2))
            return 0
        if args.trust_node:
            if not args.level:
                print(json.dumps({"error": "--trust-node requires --level"}), file=sys.stderr)
                return 2
            client = SignerClient(args.signer_socket)
            transition = agent.transition_trust(
                args.trust_node,
                args.level,
                args.reason,
                previous_level=args.previous_level,
                signer=client.sign_transition,
            )
            print(json.dumps(transition, sort_keys=True, indent=2))
            return 0
        payload = _read_event(args.event)
        if not isinstance(payload, dict):
            print(json.dumps({"error": "event must be a JSON object"}), file=sys.stderr)
            return 2
        print(json.dumps(agent.produce_finding(payload), sort_keys=True))
        return 0
    except (OSError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
