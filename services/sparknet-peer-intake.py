#!/usr/bin/env python3
"""The Master's peer-intake listener — telemetry evidence and RFI requests.

Phase 4 is Master observability *without touching the data path*: peers talk to each
other directly and the Master is authority-plane only, so monitoring means evidence
the peer **pushes**, never a Master that sits in the middle. This is the socket that
receives it. Design: ``MASTER_OBSERVABILITY_DESIGN.md`` (fabric Step 69);
``RFI_REQUEST_DESIGN.md`` (fabric Step 68A); contracts:
``contracts/telemetry-schema.json`` and ``contracts/rfi-schema.json``.

It re-scopes **8090**, which ``contracts/ports.json`` recorded as the superseded
``master-instant-push`` listener. That question is closed: Master Step 7 was
re-scoped and closed by fabric Step 69C. The instant-push purpose is retired — Step 6
pushes the signed registry to each peer's guard on 9090, so a Master-side ACL-push
listener was never needed. What 8090 becomes is the one **peer→Master intake**
surface, carrying message *families* as routes exactly as the peer's guard 9090
carries three: ``POST /api/v1/telemetry`` and, from fabric Step 70B,
``POST /api/v1/rfi-request``.

The service is named ``sparknet-peer-intake`` rather than ``sparknet-telemetry-intake``
for that reason: it is the surface, and telemetry is one route on it. It carries no
authority on either route — a request is queued for the composer, never answered here.

Attribution is the authenticated overlay (Step 68A's Option B), not a signature
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Nothing in the fabric binds a peer fingerprint to a node signing public key, so a
peer→Master body is *not* signed — a signature the Master cannot verify is theatre.
WireGuard already authenticates each peer: the Master's ``wg0`` holds one stanza per
node, keyed by ``wireguard_public_key_b64``, ``AllowedIPs`` = its overlay ``/32``. So
the source address of a packet the Master receives **is** an authenticated identity,
and the Master's registry maps ``overlay_ipv4 → fingerprint``. This listener derives
the sender's fingerprint from the source address and refuses a report whose
``peer_fingerprint`` field disagrees — a peer cannot report as another peer.

The ``telemetry`` capability is enforced **here**, on receipt
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Phase 4's "wire the existing telemetry capability" is concrete: a source is accepted
only if its registry entry is present, **not revoked**, and **holds ``telemetry``**.
A peer the registry does not grant it gets ``403 capability_missing`` before the body
is parsed. This is the push complement to the admin console's *pull* feed
(``list_events`` over ``admin-supervise``); the capability split is the point —
``telemetry`` is peer-held, ``admin-supervise`` is Master-held.

The request route adds no capability
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
``POST /api/v1/rfi-request`` shares the same source gate — registered, not revoked —
but deliberately does **not** require ``telemetry``: asking a question is not
reporting evidence, and an operator should not have to grant observability to let a
peer ask for a document. Like the answer transport, this is information the Master
addressed to the node; the question is *from* the node, and the registry is the
whole gate. A request is verified by ``authz.verify_rfi_request`` (shape, overlay
fingerprint match, freshness, nonce replay — there is no signature to check, per
Step 68A), then written as one queue artifact for the composer that Step 70C wires.
It is not answered here and cannot widen a scope.

Neither route carries authority
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
A report is recorded as evidence and acknowledged; a request is queued for a human
composer. Nothing here signs, grants, revokes, escalates, widens a permission or
approves anything, and the telemetry ``kind`` vocabulary (``status``, ``metrics``,
``liveness``, ``checkpoint_anchor``, ``inbox_alert``) has no authority verb in it.
The Master observes and queues; it does not act.

Usage::

    sparknet-peer-intake.py --serve --bind 10.100.0.1 --port 8090
    sparknet-peer-intake.py --check
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

ROLE_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = ROLE_ROOT.parent
AUTHZ_PATH = REPO_ROOT / "shared" / "sparknet-authz.py"

DEFAULT_BIND = "10.100.0.1"
DEFAULT_PORT = 8090
DEFAULT_REGISTRY = ROLE_ROOT / "manifests" / "node-authorizations.json"
DEFAULT_REQUEST_DIR = "/mnt/log/sparknet-rfi-requests"
MAX_BODY = 256 * 1024

#: Refusal reason -> HTTP status. `off_overlay`, `revoked` and `capability_missing`
#: are the source gate's; the rest come from ``authz.verify_telemetry_report``.
#: Fixed strings, so an operator greps a log for a stable code.
REFUSAL_STATUS = {
    "off_overlay": 403,
    "revoked": 403,
    "capability_missing": 403,
    "malformed": 400,
    "wrong_peer": 403,
    "expired": 403,
    "not_yet_valid": 403,
    "replayed_nonce": 409,
}


def _load_authz() -> Any:
    if "sparknet_intake_authz" in sys.modules:
        return sys.modules["sparknet_intake_authz"]
    spec = importlib.util.spec_from_file_location("sparknet_intake_authz", AUTHZ_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load the authz implementation from {AUTHZ_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["sparknet_intake_authz"] = module
    spec.loader.exec_module(module)
    return module


authz = _load_authz()


class IntakeError(Exception):
    """A refusal the listener can report without echoing report content."""


# --- the peer directory: overlay source -> fingerprint ------------------------


def _bare(address: str) -> str:
    """`10.100.0.9/32` -> `10.100.0.9`; a URL wants the bare address."""
    return str(address or "").split("/", 1)[0].strip()


def load_registry(path: Path | str) -> list[dict[str, Any]]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    entries = data.get("authorizations") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        raise IntakeError(f"{path} has no authorizations[] list")
    return entries


class PeerDirectory:
    """Maps an overlay source address to the registered peer that holds it.

    Built from the Master's own signed registry, so attribution is only as current
    as the registry the Master signed — a revoked peer is refused by the same read
    that would otherwise attribute it.
    """

    def __init__(self, entries: list[dict[str, Any]]) -> None:
        self._by_address: dict[str, dict[str, Any]] = {}
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            address = _bare(entry.get("overlay_ipv4"))
            fingerprint = entry.get("fingerprint")
            if address and isinstance(fingerprint, str) and fingerprint:
                self._by_address[address] = entry

    @classmethod
    def from_registry(cls, path: Path | str) -> PeerDirectory:
        return cls(load_registry(path))

    def attribute(self, client_address: str, *, capability: str | None = "telemetry") -> tuple[str | None, str]:
        """(fingerprint, "") for an accepted source, else (None, reason).

        The order is the contract's: is this a registered peer at all, is it still
        trusted, may it use this route. Each refusal is a distinct code so an
        operator can tell an unknown source from a revoked one from an ungranted one.

        ``capability=None`` is the RFI request route: registered and not revoked,
        nothing more. It is not a bypass — the overlay still authenticates the
        source and the literal fingerprint still has to match the body.
        """
        entry = self._by_address.get(_bare(client_address))
        if entry is None:
            return None, "off_overlay"
        if entry.get("revoked"):
            return None, "revoked"
        if capability is not None:
            capabilities = entry.get("capabilities")
            if not isinstance(capabilities, list) or capability not in capabilities:
                return None, "capability_missing"
        return str(entry["fingerprint"]), ""


# --- the evidence spool -------------------------------------------------------


def default_spool() -> Path:
    """Where received telemetry is recorded. Telemetry goes to ``/mnt/log`` per the
    fabric's canonical placement (not the vault, not ``~/``), beside the reflex
    broker's audit; ``SPARKNET_TELEMETRY_SPOOL`` overrides it."""
    env = os.environ.get("SPARKNET_TELEMETRY_SPOOL", "").strip()
    return Path(env) if env else Path("/mnt/log/sparknet-telemetry.jsonl")


def record_report(spool: Path, report: dict[str, Any], *, source: str) -> bool:
    """Append one accepted report (0600, one object per line). Never raises.

    The spool is the evidence the admin console's feed surfaces (69G); a report the
    Master cannot spool is still acknowledged, because refusing an arrived report
    over a disk fault would punish the peer for the Master's problem.
    """
    row = {"source": _bare(source), **report}
    try:
        spool.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with spool.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        with contextlib.suppress(OSError):
            os.chmod(spool, 0o600)
    except OSError as exc:
        print(f"peer-intake: spool write failed: {exc}", file=sys.stderr)
        return False
    return True


def spool_nonces(spool: Path) -> set[str]:
    """The nonces already recorded, so a re-pushed report is a replay not a dupe.

    Read once at start and kept in memory thereafter; a corrupt row is skipped.
    Rotating the spool is a future concern — telemetry is evidence, not authority,
    so the cost of growth is disk, not trust.
    """
    seen: set[str] = set()
    if not spool.exists():
        return seen
    try:
        lines = spool.read_text(encoding="utf-8").splitlines()
    except OSError:
        return seen
    for line in lines:
        line = line.strip()
        if not line:
            continue
        with contextlib.suppress(json.JSONDecodeError):
            row = json.loads(line)
            nonce = row.get("nonce") if isinstance(row, dict) else None
            if isinstance(nonce, str) and nonce:
                seen.add(nonce)
    return seen


# --- the request queue --------------------------------------------------------


def default_request_dir() -> Path:
    """Where verified RFI requests wait for the composer.

    ``/mnt/log`` per the canonical placement, beside the telemetry spool:
    ``SPARKNET_RFI_REQUEST_DIR`` overrides it. A leak of this directory reveals
    questions, not keys, but it is still 0700/0600.
    """
    env = os.environ.get("SPARKNET_RFI_REQUEST_DIR", "").strip()
    return Path(env) if env else Path(DEFAULT_REQUEST_DIR)


class RequestQueue:
    """One artifact per verified request, named by its content digest.

    A single JSON file is what Step 70C's ``--request`` consumes; using the digest
    rather than the peer-chosen ``request_id`` means a hostile string cannot choose
    a path. The nonce set is read once at start, so a replayed request is refused
    before it can add a second artifact.
    """

    def __init__(self, directory: Path | str, *, seen_nonces: set[str] | None = None) -> None:
        self.directory = Path(directory)
        self.seen = seen_nonces if seen_nonces is not None else self.load_nonces()

    def load_nonces(self) -> set[str]:
        seen: set[str] = set()
        if not self.directory.is_dir():
            return seen
        for path in sorted(self.directory.glob("*.json")):
            with contextlib.suppress(OSError, json.JSONDecodeError):
                row = json.loads(path.read_text(encoding="utf-8"))
                nonce = row.get("nonce") if isinstance(row, dict) else None
                if isinstance(nonce, str) and nonce:
                    seen.add(nonce)
        return seen

    def record(self, request: dict[str, Any]) -> Path:
        """Write one accepted request atomically (0600) and return its path."""
        canonical = json.dumps(request, sort_keys=True, separators=(",", ":")).encode("utf-8")
        digest = hashlib.sha256(canonical).hexdigest()
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        with contextlib.suppress(OSError):
            os.chmod(self.directory, 0o700)
        target = self.directory / f"{digest}.json"
        with tempfile.NamedTemporaryFile("wb", dir=self.directory, prefix=".request-", delete=False) as handle:
            temporary = Path(handle.name)
            try:
                handle.write(canonical)
                handle.flush()
                os.fsync(handle.fileno())
                with contextlib.suppress(OSError):
                    os.chmod(temporary, 0o600)
                os.replace(temporary, target)
            finally:
                with contextlib.suppress(OSError):
                    temporary.unlink()
        return target


# --- HTTP surface -------------------------------------------------------------


def _json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":")).encode("utf-8")


class _Handler(BaseHTTPRequestHandler):
    server_version = "sparknet-peer-intake"
    sys_version = ""

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"peer-intake: {self.address_string()} {fmt % args}", file=sys.stderr)

    def _send(self, status: int, body: dict[str, Any]) -> None:
        data = _json_bytes(body)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._send(200, {"ok": True})
            return
        self._send(404, {"error": "not_found"})

    def do_POST(self) -> None:
        if self.path == "/api/v1/telemetry":
            self._telemetry()
        elif self.path == "/api/v1/rfi-request":
            self._rfi_request()
        else:
            self._send(404, {"error": "not_found"})

    def _read_body(self) -> tuple[dict[str, Any] | None, str, int]:
        """Read one JSON object, or (None, reason, status) before any work is done."""
        try:
            length = int(self.headers.get("Content-Length", "0") or 0)
        except ValueError:
            return None, "malformed", 400
        if length <= 0 or length > MAX_BODY:
            return None, "malformed", 413 if length > MAX_BODY else 400
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None, "malformed", 400
        if not isinstance(body, dict):
            return None, "malformed", 400
        return body, "", 0

    def _telemetry(self) -> None:
        client = self.client_address[0]
        # Attribution first, before the body is read: an unregistered, revoked or
        # ungranted source is refused without parsing anything it sent.
        fingerprint, reason = self.server.directory.attribute(client)  # type: ignore[attr-defined]
        if fingerprint is None:
            self._send(REFUSAL_STATUS.get(reason, 403), {"error": reason})
            return

        report, reason, status = self._read_body()
        if report is None:
            self._send(status, {"error": reason})
            return

        seen = self.server.seen_nonces  # type: ignore[attr-defined]
        ok, verify_reason = authz.verify_telemetry_report(report, expected_fingerprint=fingerprint, seen_nonces=seen)
        if not ok:
            self._send(REFUSAL_STATUS.get(verify_reason, 400), {"error": verify_reason})
            return

        spool = self.server.spool  # type: ignore[attr-defined]
        spooled = record_report(spool, report, source=client)
        seen.add(str(report["nonce"]))
        self._send(
            200,
            {"status": "recorded", "kind": report["kind"], "nonce": report["nonce"], "spooled": spooled},
        )

    def _rfi_request(self) -> None:
        client = self.client_address[0]
        # Registered and not revoked, but no telemetry capability: asking is not
        # reporting. The overlay is still the attribution.
        fingerprint, reason = self.server.directory.attribute(client, capability=None)  # type: ignore[attr-defined]
        if fingerprint is None:
            self._send(REFUSAL_STATUS.get(reason, 403), {"error": reason})
            return

        request, reason, status = self._read_body()
        if request is None:
            self._send(status, {"error": reason})
            return

        queue = self.server.request_queue  # type: ignore[attr-defined]
        ok, verify_reason = authz.verify_rfi_request(request, expected_fingerprint=fingerprint, seen_nonces=queue.seen)
        if not ok:
            self._send(REFUSAL_STATUS.get(verify_reason, 400), {"error": verify_reason})
            return

        try:
            artifact = queue.record(request)
        except OSError as exc:
            # A request the Master cannot queue is not accepted; unlike telemetry
            # (evidence), silently acking would tell the peer a question is waiting
            # when no composer can find it. The peer may retry the same nonce.
            print(f"peer-intake: request queue write failed: {exc}", file=sys.stderr)
            self._send(503, {"error": "queue_unavailable"})
            return

        queue.seen.add(str(request["nonce"]))
        print(f"peer-intake: queued RFI request {request['request_id']} -> {artifact.name}", file=sys.stderr)
        self._send(202, {"status": "queued", "request_id": request["request_id"]})


def serve(
    bind: str,
    port: int,
    *,
    directory: PeerDirectory,
    spool: Path,
    request_dir: Path | str | None = None,
    seen_nonces: set[str] | None = None,
    request_queue: RequestQueue | None = None,
) -> None:
    if bind != DEFAULT_BIND and bind not in {"127.0.0.1", "::1"}:
        raise IntakeError("refuse to bind a non-overlay address (the intake is overlay-only)")
    server = ThreadingHTTPServer((bind, port), _Handler)
    server.directory = directory  # type: ignore[attr-defined]
    server.spool = spool  # type: ignore[attr-defined]
    server.seen_nonces = seen_nonces if seen_nonces is not None else spool_nonces(spool)  # type: ignore[attr-defined]
    server.request_queue = (  # type: ignore[attr-defined]
        request_queue if request_queue is not None else RequestQueue(request_dir or default_request_dir())
    )
    print(f"peer-intake: listening on {bind}:{port}", file=sys.stderr)
    server.serve_forever()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sparknet Master peer-intake listener (telemetry + RFI requests)")
    parser.add_argument("--serve", action="store_true", help="run the HTTP listener")
    parser.add_argument("--check", action="store_true", help="print posture and exit")
    parser.add_argument("--bind", default=os.environ.get("SPARKNET_TELEMETRY_BIND", DEFAULT_BIND))
    parser.add_argument("--port", type=int, default=int(os.environ.get("SPARKNET_TELEMETRY_PORT", DEFAULT_PORT)))
    parser.add_argument("--registry", default=os.environ.get("SPARKNET_TELEMETRY_REGISTRY", str(DEFAULT_REGISTRY)))
    parser.add_argument("--spool", default=os.environ.get("SPARKNET_TELEMETRY_SPOOL", ""))
    parser.add_argument("--request-dir", default=os.environ.get("SPARKNET_RFI_REQUEST_DIR", ""))
    args = parser.parse_args(argv)

    spool = Path(args.spool) if args.spool else default_spool()
    request_dir = Path(args.request_dir) if args.request_dir else default_request_dir()

    if args.check:
        print(
            json.dumps(
                {
                    "service": "peer-intake",
                    "bind": args.bind,
                    "port": args.port,
                    "registry": args.registry,
                    "spool": str(spool),
                    "request_dir": str(request_dir),
                    "routes": ["/api/v1/telemetry", "/api/v1/rfi-request"],
                    "authority": "none — records evidence and queues requests, never signs/grants/revokes",
                },
                indent=2,
            )
        )
        return 0

    if not args.serve:
        parser.error("choose --serve or --check")

    try:
        directory = PeerDirectory.from_registry(args.registry)
    except (IntakeError, OSError, json.JSONDecodeError) as exc:
        print(f"peer-intake: cannot load the registry: {exc}", file=sys.stderr)
        return 2
    try:
        serve(args.bind, args.port, directory=directory, spool=spool, request_dir=request_dir)
    except (IntakeError, OSError) as exc:
        print(f"peer-intake: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
