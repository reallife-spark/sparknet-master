#!/usr/bin/env python3
"""Share ratification — the Master authority side (Step 10).

Accept a share request only when the peer's grant verifies against the signed
registry, then issue a Master-signed, time-boxed ratification. The 2 h clock is
the Master's; the peers enforce it locally, so silence is a refusal and an
unreachable Master can never keep a share alive.

The service holds no key. It asks the isolated signer for
``sign-share-ratification`` over the canonical envelope in
``shared/sparknet-authz.py``; a signed approval or refusal is returned, never a
placeholder. A live listener on 4203 is a deployment leg (`DoD: confirm: user`).
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROLE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROLE_ROOT.parent / "shared"))
from sparknet_loader import load_shared  # noqa: E402 - import after the loader path shim

DEFAULT_REGISTRY = ROLE_ROOT / "manifests" / "node-authorizations.json"
DEFAULT_DEADLINE_SECONDS = 2 * 60 * 60
DECISIONS = ("approve", "approved", "ratify", "ratified", "refuse", "refused")


def _load_authz() -> Any:
    return load_shared(
        "sparknet-authz.py",
        "sparknet_authz",
        dirs=[ROLE_ROOT.parent / "shared"],
        error=RuntimeError,
        message="cannot locate sparknet-authz.py; share ratification refuses to reimplement grant verification",
    )


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _parse_iso(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


class ShareRatifyError(Exception):
    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


class ShareRatifier:
    """Verify an accepted share and sign the Master's answer."""

    def __init__(
        self,
        registry_path: str | os.PathLike[str] | None = None,
        *,
        signer: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
        authz: Any | None = None,
        clock: Callable[[], datetime] | None = None,
        deadline_seconds: int = DEFAULT_DEADLINE_SECONDS,
    ):
        self.registry_path = Path(registry_path) if registry_path else DEFAULT_REGISTRY
        self.signer = signer
        self.authz = authz or _load_authz()
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.deadline_seconds = deadline_seconds
        self.pending: dict[str, dict[str, Any]] = {}
        self.ratifications: dict[str, dict[str, Any]] = {}

    def _load_registry(self) -> dict[str, Any]:
        try:
            registry = json.loads(self.registry_path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise ShareRatifyError("registry-unavailable", str(exc)) from exc
        except ValueError as exc:
            raise ShareRatifyError("registry-invalid", str(exc)) from exc
        if not isinstance(registry, dict) or not isinstance(registry.get("authorizations"), list):
            raise ShareRatifyError("registry-invalid", "registry needs an authorizations[] list")
        return registry

    def _master_key(self, registry: dict[str, Any]) -> Any:
        encoded = registry.get("master_public_key_b64")
        if not isinstance(encoded, str) or not encoded:
            raise ShareRatifyError("registry-invalid", "registry has no master_public_key_b64")
        try:
            return self.authz.public_key_from_b64(encoded)
        except Exception as exc:
            raise ShareRatifyError("registry-invalid", f"master_public_key_b64 is unusable: {exc}") from exc

    def _verify_acceptance(self, request: dict[str, Any], registry: dict[str, Any], now: datetime) -> dict[str, Any]:
        if not isinstance(request, dict):
            raise ShareRatifyError("malformed", "request must be an object")
        node_id = request.get("node_id") or request.get("requesting_node")
        grant = request.get("grant")
        if not isinstance(node_id, str) or not node_id:
            raise ShareRatifyError("malformed", "node_id required")
        if not isinstance(grant, dict):
            raise ShareRatifyError("invalid-grant", "grant object required")
        if grant.get("node_id") != node_id:
            raise ShareRatifyError("invalid-grant", "grant names a different node")
        fingerprint = grant.get("node_fingerprint")
        entries = registry["authorizations"]
        entry = next(
            (
                candidate
                for candidate in entries
                if isinstance(candidate, dict) and candidate.get("fingerprint") == fingerprint
            ),
            None,
        )
        if entry is None:
            raise ShareRatifyError("unauthorized", "grant node is not in the registry")
        decision = self.authz.verify_grant(
            grant,
            master_public_key=self._master_key(registry),
            registry=registry,
            node_identity=entry.get("identity"),
            consumed_nonces=set(),
            now=now,
        )
        if not decision.allowed:
            raise ShareRatifyError("invalid-grant", decision.reason)
        return {
            "node_id": node_id,
            "node_fingerprint": str(fingerprint),
            "grant_id": str(grant["grant_id"]),
            "grant": grant,
            "share_type": request.get("share_type"),
        }

    def accept_share_request(self, request: dict[str, Any]) -> dict[str, Any]:
        now = self.clock()
        registry = self._load_registry()
        verified = self._verify_acceptance(request, registry, now)
        accepted_at = _parse_iso(request.get("accepted_at"))
        if accepted_at is None:
            accepted_at = now
        if accepted_at > now + timedelta(minutes=5):
            raise ShareRatifyError("accepted-at-future", "accepted_at is beyond the clock-skew allowance")
        share_id = request.get("share_id")
        if not isinstance(share_id, str) or not share_id:
            share_id = f"shr-{verified['node_id']}-{int(now.timestamp())}"
        if share_id in self.pending or share_id in self.ratifications:
            raise ShareRatifyError("duplicate-share", f"share {share_id} was already accepted")
        deadline = accepted_at + timedelta(seconds=self.deadline_seconds)
        record = {
            "share_id": share_id,
            "node_id": verified["node_id"],
            "node_fingerprint": verified["node_fingerprint"],
            "grant_id": verified["grant_id"],
            "grant": verified["grant"],
            "share_type": verified["share_type"],
            "accepted_at": _iso(accepted_at),
            "deadline": _iso(deadline),
            "status": "pending",
            "flag_retained": True,
        }
        self.pending[share_id] = record
        return {"ok": True, "share_id": share_id, "status": "pending", "deadline": record["deadline"]}

    def _sign(self, ratification: dict[str, Any], registry: dict[str, Any]) -> dict[str, Any]:
        if self.signer is None:
            raise ShareRatifyError("no-signer", "share ratification requires the isolated signer")
        signed = self.signer(ratification)
        if not isinstance(signed, dict):
            raise ShareRatifyError("bad-signature", "signer returned no ratification object")
        if not self.authz.verify_share_ratification(signed, self._master_key(registry)):
            raise ShareRatifyError("bad-signature", "signer returned a ratification that does not verify")
        return signed

    def ratify(self, share_id: str, decision: str = "approve", reason: str = "") -> dict[str, Any]:
        if decision not in DECISIONS:
            raise ShareRatifyError("invalid-decision", f"expected one of {', '.join(DECISIONS)}")
        record = self.pending.get(share_id) or self.ratifications.get(share_id)
        if record is None:
            raise ShareRatifyError("not-found", f"share {share_id} was not accepted here")
        if record.get("status") != "pending":
            raise ShareRatifyError("already-decided", f"share {share_id} is already {record.get('status')}")
        now = self.clock()
        deadline = _parse_iso(record["deadline"])
        approved = decision in ("approve", "approved", "ratify", "ratified")
        if deadline is None or now > deadline:
            approved = False
            reason = "deadline-exceeded"
        final = "ratified" if approved else "refused"
        ratification = {
            "schema_version": self.authz.SHARE_RATIFICATION_SCHEMA,
            "share_id": record["share_id"],
            "node_id": record["node_id"],
            "node_fingerprint": record["node_fingerprint"],
            "grant_id": record["grant_id"],
            "decision": final,
            "reason": reason or ("approved" if approved else "refused"),
            "accepted_at": record["accepted_at"],
            "deadline": record["deadline"],
            "ratified_at": _iso(now),
            "flag_retained": True,
        }
        registry = self._load_registry()
        signed = self._sign(ratification, registry)
        stored = {
            **record,
            "status": final,
            "ratified_at": ratification["ratified_at"],
            "reason": ratification["reason"],
            "ratification": signed,
        }
        self.pending.pop(share_id, None)
        self.ratifications[share_id] = stored
        return {
            "ok": approved,
            "share_id": share_id,
            "status": final,
            "deadline": record["deadline"],
            "flag_retained": True,
            "ratification": signed,
        }


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
            raise ShareRatifyError("signer-protocol", "signer response too large")
        if b"\n" in chunk:
            break
    return b"".join(chunks).split(b"\n", 1)[0]


class SignerClient:
    """The narrow signer client this service needs: root-id + share ratification."""

    def __init__(self, socket_path: str | Path, *, timeout: float = 30.0):
        self.socket_path = Path(socket_path)
        self.timeout = timeout

    def call(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not self.socket_path.exists():
            raise ShareRatifyError("no-signer", f"signer socket {self.socket_path} does not exist")
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(self.timeout)
        try:
            connection.connect(str(self.socket_path))
            connection.sendall(json.dumps(payload).encode("utf-8") + b"\n")
            line = _recv_line(connection)
        except OSError as exc:
            raise ShareRatifyError("signer-error", str(exc)) from exc
        finally:
            connection.close()
        try:
            return json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise ShareRatifyError("signer-protocol", str(exc)) from exc

    def root_id(self) -> str:
        response = self.call({"op": "root-id"})
        if not response.get("ok"):
            raise ShareRatifyError("signer-refused", str(response.get("error")))
        return str(response["root_id"])

    def sign_ratification(self, ratification: dict[str, Any]) -> dict[str, Any]:
        response = self.call({"op": "sign-share-ratification", "root_id": self.root_id(), "ratification": ratification})
        if not response.get("ok"):
            raise ShareRatifyError("signer-refused", str(response.get("error")))
        return response["ratification"]


def _read_request(path: str) -> Any:
    if path == "-":
        return json.load(sys.stdin)
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", default="-", help="Share request JSON file, or - for stdin")
    parser.add_argument("--decision", default="approve", choices=DECISIONS)
    parser.add_argument("--reason", default="")
    parser.add_argument("--registry", default=str(DEFAULT_REGISTRY))
    parser.add_argument("--signer-socket", default=str(_default_signer_socket()))
    args = parser.parse_args(argv)

    try:
        request = _read_request(args.request)
        client = SignerClient(args.signer_socket)
        ratifier = ShareRatifier(args.registry, signer=client.sign_ratification)
        accepted = ratifier.accept_share_request(request)
        result = ratifier.ratify(accepted["share_id"], args.decision, args.reason)
    except (OSError, ValueError, ShareRatifyError) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
