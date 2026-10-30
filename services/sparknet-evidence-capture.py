#!/usr/bin/env python3
"""Evidence capture service (Step 11).

Validate one share-evidence event, write it under the review repository's
``events/`` directory, record its digest in the Master's signed ledger, and
commit it to the evidence git repository — in that order. The ledger append is
the authority record; the git commit makes the file reviewable.

The service holds no key. It asks the isolated signer for
``record-share-evidence``; a ledger failure removes the just-written file so the
chain and the repository cannot disagree silently.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROLE_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REPO = ROLE_ROOT / "evidence-repo"


def _iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class EvidenceError(Exception):
    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


class EvidenceCapture:
    def __init__(
        self,
        evidence_repo: str | Path = "master-node/evidence-repo",
        *,
        signer: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
        git_commit: bool = True,
    ):
        self.evidence_repo = Path(evidence_repo)
        self.signer = signer
        self.git_commit = git_commit
        self.events_dir = self.evidence_repo / "events"
        self.events_dir.mkdir(parents=True, exist_ok=True)

    def _payload(self, event: dict[str, Any]) -> tuple[dict[str, Any], bytes]:
        required = ["event_type", "who", "what", "when", "grant_id", "node_pair", "share_type"]
        missing = [key for key in required if key not in event]
        if missing:
            raise EvidenceError("malformed", f"missing {', '.join(missing)}")
        now = _iso()
        safe_type = re.sub(r"[^A-Za-z0-9._-]+", "-", str(event["event_type"])).replace("..", "-").strip(".-")
        payload = {**event, "captured_at": now, "event_type": safe_type[:64] or "event"}
        body = (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode("utf-8")
        return payload, body

    def _commit(self, event_file: Path, event_type: str) -> None:
        for command in (
            ["git", "-C", str(self.evidence_repo), "add", str(event_file)],
            ["git", "-C", str(self.evidence_repo), "commit", "-m", f"evidence: {event_type}"],
        ):
            try:
                subprocess.run(command, check=True, capture_output=True, text=True)
            except (OSError, subprocess.CalledProcessError) as exc:
                detail = getattr(exc, "stderr", "") or str(exc)
                raise EvidenceError(
                    "git-failed", f"{command[3] if len(command) > 3 else command[0]}: {detail.strip()}"
                ) from exc

    def verify_repo(self, ledger_path: str | Path) -> dict[str, Any]:
        """Compare every event file's hash with the ledger's share_evidence blocks.

        A clone of the evidence repository therefore needs only the ledger to be
        checked: a missing file or an unrecorded file is a discrepancy, not a
        silent success.
        """
        try:
            ledger = json.loads(Path(ledger_path).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise EvidenceError("ledger-unavailable", str(exc)) from exc
        blocks = ledger.get("blocks") if isinstance(ledger, dict) else None
        if not isinstance(blocks, list):
            raise EvidenceError("ledger-invalid", "ledger has no blocks array")
        recorded = {
            str(block.get("data", {}).get("content_sha256"))
            for block in blocks
            if isinstance(block, dict) and block.get("data", {}).get("event") == "share_evidence"
        }
        files = sorted(self.events_dir.glob("*.json"))
        hashed = {hashlib.sha256(path.read_bytes()).hexdigest(): path.name for path in files}
        missing = sorted(digest for digest in recorded if digest not in hashed)
        unrecorded = sorted(name for digest, name in hashed.items() if digest not in recorded)
        return {
            "ok": not missing and not unrecorded,
            "recorded": len(recorded),
            "files": len(files),
            "missing": missing,
            "unrecorded": unrecorded,
        }

    def capture_event(self, event: dict[str, Any]) -> dict[str, Any]:
        payload, body = self._payload(event)
        digest = hashlib.sha256(body).hexdigest()
        event_file = self.events_dir / f"{payload['event_type']}-{payload['captured_at'].replace(':', '')}.json"
        event_file.write_bytes(body)
        if self.signer is None:
            event_file.unlink(missing_ok=True)
            raise EvidenceError("no-signer", "evidence capture requires the isolated signer")
        try:
            receipt = self.signer(
                {
                    "event_type": payload["event_type"],
                    "grant_id": str(payload["grant_id"]),
                    "node_pair": str(payload["node_pair"]),
                    "share_type": str(payload["share_type"]),
                    "content_sha256": digest,
                    "captured_at": payload["captured_at"],
                }
            )
        except Exception as exc:
            event_file.unlink(missing_ok=True)
            raise EvidenceError("ledger-failed", str(exc)) from exc
        if not isinstance(receipt, dict) or not receipt.get("ledger_block"):
            event_file.unlink(missing_ok=True)
            raise EvidenceError("ledger-failed", "signer returned no ledger block")
        if self.git_commit:
            self._commit(event_file, payload["event_type"])
        return {
            "ok": True,
            "path": str(event_file),
            "content_sha256": digest,
            "ledger_block": receipt["ledger_block"],
            "committed": self.git_commit,
        }


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
            raise EvidenceError("signer-protocol", "signer response too large")
        if b"\n" in chunk:
            break
    return b"".join(chunks).split(b"\n", 1)[0]


class SignerClient:
    def __init__(self, socket_path: str | Path, *, timeout: float = 30.0):
        self.socket_path = Path(socket_path)
        self.timeout = timeout

    def call(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not self.socket_path.exists():
            raise EvidenceError("no-signer", f"signer socket {self.socket_path} does not exist")
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(self.timeout)
        try:
            connection.connect(str(self.socket_path))
            connection.sendall(json.dumps(payload).encode("utf-8") + b"\n")
            line = _recv_line(connection)
        except OSError as exc:
            raise EvidenceError("signer-error", str(exc)) from exc
        finally:
            connection.close()
        try:
            return json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise EvidenceError("signer-protocol", str(exc)) from exc

    def root_id(self) -> str:
        response = self.call({"op": "root-id"})
        if not response.get("ok"):
            raise EvidenceError("signer-refused", str(response.get("error")))
        return str(response["root_id"])

    def record_evidence(self, evidence: dict[str, Any]) -> dict[str, Any]:
        response = self.call({"op": "record-share-evidence", "root_id": self.root_id(), "evidence": evidence})
        if not response.get("ok"):
            raise EvidenceError("signer-refused", str(response.get("error")))
        return response


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event", default="-", help="JSON event file, or - for stdin")
    parser.add_argument("--evidence-repo", default=str(DEFAULT_REPO), help="Evidence repository root")
    parser.add_argument("--signer-socket", default=str(_default_signer_socket()))
    parser.add_argument("--no-commit", action="store_true", help="Record the ledger entry but skip git commit")
    parser.add_argument("--dry-run", action="store_true", help="Validate and print the digest; write nothing")
    parser.add_argument(
        "--verify", action="store_true", help="Compare event files with the ledger's share_evidence blocks"
    )
    parser.add_argument(
        "--ledger", default=str(ROLE_ROOT / "blockchain" / "ledger.json"), help="Master ledger path for --verify"
    )
    args = parser.parse_args(argv)

    try:
        if args.verify:
            report = EvidenceCapture(args.evidence_repo, signer=None, git_commit=False).verify_repo(args.ledger)
            print(json.dumps(report, sort_keys=True, indent=2))
            return 0 if report["ok"] else 1
        payload = _read_event(args.event)
        if not isinstance(payload, dict):
            raise EvidenceError("malformed", "event must be a JSON object")
        if args.dry_run:
            probe = EvidenceCapture(args.evidence_repo, signer=None, git_commit=False)
            normalized, body = probe._payload(payload)
            print(
                json.dumps(
                    {
                        "ok": True,
                        "dry_run": True,
                        "event_type": normalized["event_type"],
                        "content_sha256": hashlib.sha256(body).hexdigest(),
                    },
                    sort_keys=True,
                )
            )
            return 0
        client = SignerClient(args.signer_socket)
        capture = EvidenceCapture(args.evidence_repo, signer=client.record_evidence, git_commit=not args.no_commit)
        receipt = capture.capture_event(payload)
    except (OSError, ValueError, EvidenceError) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 2
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
