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

The issue route is signed and capability-gated
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
``POST /api/v1/issues`` (fabric Step 91) carries a peer work item. It requires the
peer-held ``issue-report`` capability, a registered non-revoked overlay source, a
node-key signature over the raw body (``shared/sparknet-http.py``), a trusted key
for the named node, and ``authz.verify_issue_report`` for shape, digest, expiry and
nonce replay. It stores the item append-only; it never executes it, installs it into
a vault or serves it as knowledge.

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
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "shared"))
from sparknet_loader import load_by_path

ROLE_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = ROLE_ROOT.parent
AUTHZ_PATH = REPO_ROOT / "shared" / "sparknet-authz.py"
HTTP_PATH = REPO_ROOT / "shared" / "sparknet-http.py"
ISSUE_PATH = REPO_ROOT / "shared" / "sparknet-issue.py"

DEFAULT_BIND = "10.100.0.1"
DEFAULT_PORT = 8090
DEFAULT_REGISTRY = ROLE_ROOT / "manifests" / "node-authorizations.json"
DEFAULT_REQUEST_DIR = "/mnt/log/sparknet-rfi-requests"
MAX_BODY = 256 * 1024
ISSUE_MAX_AGE_SECONDS = 300

#: Refusal reason -> HTTP status. `off_overlay`, `revoked` and `capability_missing`
#: are the source gate's; the rest come from ``authz.verify_telemetry_report``.
#: Fixed strings, so an operator greps a log for a stable code.
REFUSAL_STATUS = {
    "off_overlay": 403,
    "revoked": 403,
    "capability_missing": 403,
    "unsigned_entry": 403,
    "malformed": 400,
    "wrong_peer": 403,
    "expired": 403,
    "not_yet_valid": 403,
    "replayed_nonce": 409,
    "digest_mismatch": 400,
    "secret_shaped": 400,
    "unknown_key": 403,
    "unsigned": 401,
    "bad_signature": 401,
    "stale": 401,
}


def _load_authz() -> Any:
    if "sparknet_intake_authz" in sys.modules:
        return sys.modules["sparknet_intake_authz"]
    return load_by_path("sparknet_intake_authz", AUTHZ_PATH)


authz = _load_authz()


def _load_http() -> Any:
    if "sparknet_intake_http" in sys.modules:
        return sys.modules["sparknet_intake_http"]
    return load_by_path("sparknet_intake_http", HTTP_PATH)


http = _load_http()


def _load_issue() -> Any:
    if "sparknet_intake_issue" in sys.modules:
        return sys.modules["sparknet_intake_issue"]
    return load_by_path("sparknet_intake_issue", ISSUE_PATH)


issue = _load_issue()
IssueStore = issue.IssueStore


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

    def __init__(self, entries: list[dict[str, Any]], master_key: Any | None = None) -> None:
        self._by_address: dict[str, dict[str, Any]] = {}
        self._master_key = master_key
        self._path: Path | None = None
        self._mtime_ns = 0
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            address = _bare(entry.get("overlay_ipv4"))
            fingerprint = entry.get("fingerprint")
            if address and isinstance(fingerprint, str) and fingerprint:
                self._by_address[address] = entry

    @classmethod
    def from_registry(cls, path: Path | str) -> PeerDirectory:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
        encoded = document.get("master_public_key_b64") if isinstance(document, dict) else None
        if not isinstance(encoded, str) or not encoded:
            raise IntakeError("registry has no master_public_key_b64")
        directory = cls(load_registry(path), authz.public_key_from_b64(encoded))
        directory._path = Path(path)
        directory._mtime_ns = directory._path.stat().st_mtime_ns
        return directory

    def _refresh(self) -> None:
        if self._path is None:
            return
        try:
            mtime = self._path.stat().st_mtime_ns
            if mtime == self._mtime_ns:
                return
            document = json.loads(self._path.read_text(encoding="utf-8"))
            encoded = document.get("master_public_key_b64") if isinstance(document, dict) else None
            if not isinstance(encoded, str) or not encoded:
                raise IntakeError("registry has no master_public_key_b64")
            fresh = PeerDirectory(load_registry(self._path), authz.public_key_from_b64(encoded))
            self._by_address = fresh._by_address
            self._master_key = fresh._master_key
            self._mtime_ns = mtime
        except (OSError, ValueError, json.JSONDecodeError, IntakeError) as exc:
            raise IntakeError(f"registry reload failed: {exc}") from exc

    def entry_for(self, client_address: str) -> dict[str, Any] | None:
        """The registry entry for a source address, after a fresh load."""
        try:
            self._refresh()
        except IntakeError:
            return None
        return self._by_address.get(_bare(client_address))

    def attribute(self, client_address: str, *, capability: str | None = "telemetry") -> tuple[str | None, str]:
        """(fingerprint, "") for an accepted source, else (None, reason).

        The order is the contract's: is this a registered peer at all, is it still
        trusted, may it use this route. Each refusal is a distinct code so an
        operator can tell an unknown source from a revoked one from an ungranted one.

        ``capability=None`` is the RFI request route: registered and not revoked,
        nothing more. It is not a bypass — the overlay still authenticates the
        source and the literal fingerprint still has to match the body.
        """
        try:
            self._refresh()
        except IntakeError:
            return None, "off_overlay"
        entry = self._by_address.get(_bare(client_address))
        if entry is None:
            return None, "off_overlay"
        if self._master_key is not None:
            try:
                if not authz.verify_signature(
                    self._master_key,
                    str(entry.get("signature_b64") or ""),
                    authz.authorization_message(entry),
                ):
                    return None, "unsigned_entry"
            except Exception:
                return None, "unsigned_entry"
        if entry.get("revoked"):
            return None, "revoked"
        try:
            from datetime import datetime, timezone

            now = datetime.now(timezone.utc)
            issued = datetime.fromisoformat(str(entry.get("issued_at") or "").replace("Z", "+00:00"))
            expires = datetime.fromisoformat(str(entry.get("expires_at") or "").replace("Z", "+00:00"))
            if issued.tzinfo is None:
                issued = issued.replace(tzinfo=timezone.utc)
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            if now < issued:
                return None, "not_yet_valid"
            if now >= expires:
                return None, "expired"
        except ValueError:
            return None, "malformed"
        if capability is not None:
            capabilities = entry.get("capabilities")
            if not isinstance(capabilities, list) or capability not in capabilities:
                return None, "capability_missing"
        return str(entry["fingerprint"]), ""


# --- the evidence spool -------------------------------------------------------


def default_issue_store() -> Path:
    return issue.default_issue_store()


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


def _telemetry(directory: Any, spool: Path, seen_nonces: set[str], request: Any) -> tuple[int, dict[str, Any]]:
    client = request.client[0]
    # Attribution first: an unregistered, revoked or ungranted source is refused
    # without parsing anything it sent.
    fingerprint, reason = directory.attribute(client)
    if fingerprint is None:
        return REFUSAL_STATUS.get(reason, 403), {"error": reason}
    report = request.json
    if not isinstance(report, dict):
        return 400, {"error": "malformed"}
    ok, verify_reason = authz.verify_telemetry_report(report, expected_fingerprint=fingerprint, seen_nonces=seen_nonces)
    if not ok:
        return REFUSAL_STATUS.get(verify_reason, 400), {"error": verify_reason}
    spooled = record_report(spool, report, source=client)
    seen_nonces.add(str(report["nonce"]))
    return 200, {"status": "recorded", "kind": report["kind"], "nonce": report["nonce"], "spooled": spooled}


def _rfi_request(directory: Any, queue: RequestQueue, request: Any) -> tuple[int, dict[str, Any]]:
    client = request.client[0]
    # Registered and not revoked, but no telemetry capability: asking is not
    # reporting. The overlay is still the attribution.
    fingerprint, reason = directory.attribute(client, capability=None)
    if fingerprint is None:
        return REFUSAL_STATUS.get(reason, 403), {"error": reason}
    payload = request.json
    if not isinstance(payload, dict):
        return 400, {"error": "malformed"}
    ok, verify_reason = authz.verify_rfi_request(payload, expected_fingerprint=fingerprint, seen_nonces=queue.seen)
    if not ok:
        return REFUSAL_STATUS.get(verify_reason, 400), {"error": verify_reason}
    try:
        artifact = queue.record(payload)
    except OSError as exc:
        # A request the Master cannot queue is not accepted; unlike telemetry
        # (evidence), silently acking would tell the peer a question is waiting
        # when no composer can find it. The peer may retry the same nonce.
        print(f"peer-intake: request queue write failed: {exc}", file=sys.stderr)
        return 503, {"error": "queue_unavailable"}
    queue.seen.add(str(payload["nonce"]))
    print(f"peer-intake: queued RFI request {payload['request_id']} -> {artifact.name}", file=sys.stderr)
    return 202, {"status": "queued", "request_id": payload["request_id"]}


def _issues(
    directory: Any, issue_keys: dict[str, Any], issue_store: IssueStore, request: Any
) -> tuple[int, dict[str, Any]]:
    """Accept one signed work item. The route carries no authority.

    Order: source/capability gate, raw body, key lookup, signature, freshness,
    redaction, schema/digest/expiry/replay, store. The overlay identifies the
    source; the trusted key identifies the signer; the registry entry ties the
    two node ids together, so a valid key for one node cannot post as another.
    """
    client = request.client[0]
    fingerprint, reason = directory.attribute(client, capability="issue-report")
    if fingerprint is None:
        return REFUSAL_STATUS.get(reason, 403), {"error": reason}
    report = request.json
    if not isinstance(report, dict):
        return 400, {"error": "malformed"}
    node_id = str(report.get("node_id") or "")
    entry = directory.entry_for(client)
    if entry is None:
        return 403, {"error": "off_overlay"}
    entry_identity = entry.get("identity") if isinstance(entry.get("identity"), dict) else {}
    entry_node = str(entry_identity.get("node_id") or entry.get("node_id") or "")
    if not node_id or entry_node != node_id:
        return 403, {"error": "wrong_peer"}
    key = issue_keys.get(node_id)
    if key is None:
        return 403, {"error": "unknown_key"}
    timestamp = request.headers.get("X-Sparknet-Timestamp", "")
    signature = request.headers.get("X-Sparknet-Signature", "")
    if not timestamp or not signature:
        return 401, {"error": "unsigned"}
    try:
        message = http.request_message("POST", "/api/v1/issues", request.body, timestamp)
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return 400, {"error": "malformed"}
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    if abs((datetime.now(timezone.utc) - parsed).total_seconds()) > ISSUE_MAX_AGE_SECONDS:
        return 401, {"error": "stale"}
    try:
        signed = authz.verify_signature(key, signature, message)
    except Exception:
        signed = False
    if not signed:
        return 401, {"error": "bad_signature"}
    body = report.get("body")
    try:
        issue.redact(
            {"title": report.get("title", ""), "links": report.get("links", [])},
            body if isinstance(body, str) else "",
        )
    except issue.IssueError as exc:
        return 400, {"error": exc.reason if exc.reason == "secret_shaped" else "malformed"}
    ok, verify_reason = authz.verify_issue_report(
        report, expected_fingerprint=fingerprint, seen_nonces=issue_store.seen_nonces
    )
    if not ok:
        return REFUSAL_STATUS.get(verify_reason, 400), {"error": verify_reason}
    try:
        outcome = issue_store.record(report, source=client)
    except OSError as exc:
        print(f"peer-intake: issue store write failed: {exc}", file=sys.stderr)
        return 503, {"error": "store_unavailable"}
    return 200, {"status": outcome, "issue_id": report["issue_id"], "node_id": node_id}


def build_listener(
    *,
    bind: str,
    port: int,
    directory: PeerDirectory,
    spool: Path,
    request_dir: Path | str | None = None,
    seen_nonces: set[str] | None = None,
    request_queue: RequestQueue | None = None,
    issue_keys: dict[str, Any] | None = None,
    issue_store: IssueStore | None = None,
) -> Any:
    """Build the route-table listener; the caller owns start/stop."""
    queue = request_queue if request_queue is not None else RequestQueue(request_dir or default_request_dir())
    seen = seen_nonces if seen_nonces is not None else spool_nonces(spool)
    keys = dict(issue_keys or {})
    store = issue_store if issue_store is not None else IssueStore(default_issue_store())

    def refusal(exc: BaseException) -> tuple[int, dict[str, Any]]:
        status = getattr(exc, "status", 500)
        reason = getattr(exc, "reason", "internal")
        return status, {"error": reason}

    return http.listen(
        [
            http.Route(
                "/api/v1/telemetry",
                lambda request: _telemetry(directory, spool, seen, request),
                method="POST",
                max_body=MAX_BODY,
            ),
            http.Route(
                "/api/v1/rfi-request",
                lambda request: _rfi_request(directory, queue, request),
                method="POST",
                max_body=MAX_BODY,
            ),
            http.Route(
                "/api/v1/issues",
                lambda request: _issues(directory, keys, store, request),
                method="POST",
                max_body=MAX_BODY,
            ),
        ],
        name="peer-intake",
        bind=bind,
        port=port,
        refusal=refusal,
    )


def serve(
    bind: str,
    port: int,
    *,
    directory: PeerDirectory,
    spool: Path,
    request_dir: Path | str | None = None,
    seen_nonces: set[str] | None = None,
    request_queue: RequestQueue | None = None,
    issue_keys: dict[str, Any] | None = None,
    issue_store: IssueStore | None = None,
) -> Any:
    if bind != DEFAULT_BIND and bind not in {"127.0.0.1", "::1"}:
        raise IntakeError("refuse to bind a non-overlay address (the intake is overlay-only)")
    listener = build_listener(
        bind=bind,
        port=port,
        directory=directory,
        spool=spool,
        request_dir=request_dir,
        seen_nonces=seen_nonces,
        request_queue=request_queue,
        issue_keys=issue_keys,
        issue_store=issue_store,
    )
    print(f"peer-intake: listening on {bind}:{port}", file=sys.stderr)
    return listener


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sparknet Master peer-intake listener (telemetry + RFI requests)")
    parser.add_argument("--serve", action="store_true", help="run the HTTP listener")
    parser.add_argument("--check", action="store_true", help="print posture and exit")
    parser.add_argument("--bind", default=os.environ.get("SPARKNET_TELEMETRY_BIND", DEFAULT_BIND))
    parser.add_argument("--port", type=int, default=int(os.environ.get("SPARKNET_TELEMETRY_PORT", DEFAULT_PORT)))
    parser.add_argument("--registry", default=os.environ.get("SPARKNET_TELEMETRY_REGISTRY", str(DEFAULT_REGISTRY)))
    parser.add_argument("--spool", default=os.environ.get("SPARKNET_TELEMETRY_SPOOL", ""))
    parser.add_argument("--request-dir", default=os.environ.get("SPARKNET_RFI_REQUEST_DIR", ""))
    parser.add_argument(
        "--issue-key",
        action="append",
        default=[],
        metavar="NODE_ID=PATH",
        help="trusted node public key for the signed issue route (repeatable)",
    )
    parser.add_argument("--issue-store", default=os.environ.get("SPARKNET_ISSUE_STORE", ""))
    parser.add_argument(
        "--issue-keyring",
        default=os.environ.get("SPARKNET_ISSUE_KEYRING", ""),
        help="JSON object {node_id: public_key_b64} for the signed issue route",
    )
    args = parser.parse_args(argv)

    spool = Path(args.spool) if args.spool else default_spool()
    request_dir = Path(args.request_dir) if args.request_dir else default_request_dir()
    issue_store = Path(args.issue_store) if args.issue_store else default_issue_store()

    issue_keys: dict[str, Any] = {}
    if args.issue_keyring:
        try:
            keyring = json.loads(Path(args.issue_keyring).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            parser.error(f"--issue-keyring {args.issue_keyring}: {exc}")
        if not isinstance(keyring, dict):
            parser.error("--issue-keyring must be a JSON object {node_id: public_key_b64}")
        for key_node, encoded in keyring.items():
            try:
                issue_keys[str(key_node)] = authz.public_key_from_b64(str(encoded))
            except Exception as exc:
                parser.error(f"--issue-keyring {key_node}: {exc}")
    for item in args.issue_key:
        key_node, separator, key_path = item.partition("=")
        if not separator or not key_node or not key_path:
            parser.error(f"--issue-key expects NODE_ID=PATH, got {item!r}")
        try:
            issue_keys[key_node] = authz.load_public_key(Path(key_path))
        except Exception as exc:
            parser.error(f"--issue-key {key_node}: cannot load {key_path}: {exc}")

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
                    "issue_store": str(issue_store),
                    "issue_keys": sorted(issue_keys),
                    "issue_keyring": args.issue_keyring,
                    "routes": ["/api/v1/telemetry", "/api/v1/rfi-request", "/api/v1/issues"],
                    "authority": "none — records evidence and work items; never signs/grants/revokes",
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
        listener = serve(
            args.bind,
            args.port,
            directory=directory,
            spool=spool,
            request_dir=request_dir,
            issue_keys=issue_keys,
            issue_store=IssueStore(issue_store),
        )
        listener.wait()
    except (IntakeError, OSError) as exc:
        print(f"peer-intake: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
