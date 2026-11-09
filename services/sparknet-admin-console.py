#!/usr/bin/env python3
"""The Master's admin console: compose, sign, dispatch, and watch.

This is the operator's seat in front of the fabric. It is the only component
that both holds no key of its own *and* can cause a peer to act: it asks the
isolated signer to sign an admin-request, then posts that signed request to the
peer's own `/admin/*` route, where the peer's bridge verifies the Master's
signature and executes against the peer's own Open WebUI with the peer's own
service-account token.

The separation is the whole point. This process is LLM-adjacent and reads
configuration as input, so it is deliberately given **no signing key** — it can
only *ask*. The signer holds the key and signs what it is asked; the peer holds
its own WebUI token and decides whether the signature authorises the action. No
single process in the chain can both authorise and execute, which is what keeps
a prompt injection at the console from becoming a privilege escalation.

## What one request is

1. **Compose** an unsigned admin-request naming the target node, fingerprint,
   action and entity fields, with a fresh `request_id` and `nonce` and a short
   `expires_at` (default 120 s). The projection is the one implementation in
   `../../shared/sparknet-authz.py` — this file never re-derives the canonical
   bytes, it imports them. A second copy of that rule is exactly how signing and
   verification diverged before.
2. **Sign** it over the isolated signer's unix socket (`sign-admin-request`).
   The console speaks the signer's line-JSON protocol and nothing else; it has
   no key material and no path by which to obtain any.
3. **Dispatch** a `POST <peer>/admin/<action>` with the signed envelope. The
   peer answers `{ok, action, webui_status, result}` or a refusal. A 4xx from
   the peer's own WebUI (`webui-refused`) is the peer's answer, handed through
   verbatim rather than reparsed.

## The feed

`list_events` is the one action answered from the peer's own file rather than
its WebUI: the node's 0600 auth-event spool. That is how the console shows
signups and successful logins — de-duplicated across nodes — without any peer
handing over database access. New events can be pushed to paired KDE Connect
devices, exactly as the fabric-root notify plugin does.

The console also reads the Master's *received-telemetry* spool (written by the
8090 intake) and surfaces flagged peers with their retained share evidence. That
is a read-only view: a flag is held for a human, and only a Master-signed registry
event moves a trust level. The console never auto-remediates one.

## What it deliberately is not

It is not a signing service (it has no key), not a policy engine (the peer's
registry decides what it may do), and not a bypass of the loopback guard — the
admin route rides the peer's plain surface *because* the request is
Master-signed, and the peer enforces that, not this file.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, NamedTuple

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "shared"))
from sparknet_loader import load_by_path


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_NO_REDIRECT_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())

ROLE_ROOT = Path(__file__).resolve().parent.parent

#: The peer bridge's admin HTTP port (contracts/ports.json). Loopback today;
#: Phase 5 flips the bridge onto the overlay, at which point the host in the URL
#: changes but this port does not.
BACKING_PORT = 4096

#: The path prefix the peer's bridge serves signed admin requests under.
ADMIN_PATH_PREFIX = "/admin/"

#: How long a composed request stays valid. Short on purpose: the operator is at
#: the keyboard, the signer is local, and a request that cannot be delivered
#: within two minutes should be reissued rather than linger as a replayable token.
DEFAULT_ADMIN_TTL_SECONDS = 120

#: The default registry the console resolves node ids against. Absent on an
#: un-elected node, which is honest: with no registry there is nobody to address.
DEFAULT_REGISTRY = ROLE_ROOT / "manifests" / "node-authorizations.json"


def default_telemetry_spool() -> Path:
    """The Master's received-telemetry evidence, written by the 8090 intake."""
    env = os.environ.get("SPARKNET_TELEMETRY_SPOOL", "").strip()
    return Path(env) if env else Path("/mnt/log/sparknet-telemetry.jsonl")


#: The default isolated-signer socket, resolved the way the signer's own unit
#: resolves it so a live console and a live signer agree without extra flags.
def _default_signer_socket() -> Path:
    env = os.environ.get("SPARKNET_STATE_DIR")
    if env:
        return Path(env) / "signer" / "signer.sock"
    xdg = os.environ.get("XDG_STATE_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "state"
    return base / "sparknet" / "master-node" / "signer" / "signer.sock"


#: Which entity fields each action must carry, checked here so an operator gets
#: a usage error instead of a peer round-trip. `test_admin_console.py` asserts
#: this equals the peer bridge's `ADMIN_ENTITY_FIELDS`, so the console's idea of
#: what an action needs cannot drift from the peer's idea of what it enforces.
REQUIRED_ENTITY: dict[str, tuple[str, ...]] = {
    "list_users": (),
    "get_user": ("user_id",),
    "approve_user": ("user_id",),
    "set_user_role": ("user_id", "role"),
    "list_knowledge": (),
    "get_user_chats": ("user_id",),
    "list_events": (),
    "memory_status": (),
    "memory_policy_set": ("policy",),
    "memory_read": (),
    "memory_purge": ("memory_ids",),
}

#: CLI verb -> admin action. `feed` is handled separately (it fans out over nodes).
VERB_ACTIONS: dict[str, str] = {
    "users": "list_users",
    "user": "get_user",
    "approve": "approve_user",
    "role": "set_user_role",
    "knowledge": "list_knowledge",
    "chats": "get_user_chats",
    "events": "list_events",
    "memory": "memory_status",
    "memory-policy": "memory_policy_set",
    "memory-read": "memory_read",
    "memory-purge": "memory_purge",
}


class ConsoleError(Exception):
    """A refusal the operator can act on."""


class Target(NamedTuple):
    """A resolved peer: what to call and who it claims to be."""

    node_id: str | None
    fingerprint: str | None
    url: str


# --- loading the one implementation ------------------------------------------


def _load(name: str, path: Path):
    """Load a shared module by path, registering it in sys.modules first."""
    return load_by_path(name, path)


def _shared_dir() -> Path:
    candidates = [
        Path(os.environ["SPARKNET_SHARED_DIR"]) if os.environ.get("SPARKNET_SHARED_DIR") else None,
        ROLE_ROOT.parent / "shared",
        ROLE_ROOT / "shared",
        Path("/srv/sparknet/shared"),
    ]
    for candidate in candidates:
        if candidate and (candidate / "sparknet-authz.py").is_file():
            return candidate.resolve()
    raise ConsoleError("cannot find shared/; set SPARKNET_SHARED_DIR")


def load_authz(shared_dir: Path | None = None):
    """Load the one signed-authorization implementation, never a copy of it."""
    shared = shared_dir or _shared_dir()
    return _load("sparknet_console_authz", shared / "sparknet-authz.py")


# --- composing a request ------------------------------------------------------


def _json_list(value: Any) -> list[Any]:
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return value
    try:
        parsed = json.loads(str(value))
        if isinstance(parsed, list):
            return parsed
    except json.JSONDecodeError:
        pass
    return [part.strip() for part in str(value).split(",") if part.strip()]


def _json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if not value:
        return {}
    try:
        parsed = json.loads(str(value))
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        return {}


def compose_request(
    authz,
    *,
    action: str,
    master_node_id: str,
    target_node_id: str,
    target_fingerprint: str,
    entity: dict[str, Any] | None = None,
    ttl: int = DEFAULT_ADMIN_TTL_SECONDS,
    clock: Any = None,
    request_id: str | None = None,
    nonce: str | None = None,
    conversation_id: str | None = None,
) -> dict[str, Any]:
    """Build the unsigned admin-request envelope, projected to the shared fields.

    The field set and the required-field rule are the shared module's, not a
    local list: the request is validated by asking `authz` to canonicalise it,
    so an action this file forgot about, or a field the shared projection added,
    fails here rather than being signed into something a peer refuses.
    """
    if action not in authz.ADMIN_REQUEST_ACTIONS:
        raise ConsoleError(f"unknown action {action!r}; expected one of {', '.join(authz.ADMIN_REQUEST_ACTIONS)}")
    entity = entity or {}
    missing = [f for f in REQUIRED_ENTITY[action] if not entity.get(f)]
    if missing:
        raise ConsoleError(f"{action} requires {', '.join(missing)}")

    now = (clock or (lambda: datetime.now(timezone.utc)))()
    request = {
        "request_id": request_id or uuid.uuid4().hex,
        "conversation_id": conversation_id,
        "master_node_id": master_node_id,
        "target_node_id": target_node_id,
        "target_fingerprint": target_fingerprint,
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(seconds=ttl)).isoformat(),
        "nonce": nonce or uuid.uuid4().hex,
        "action": action,
        "user_id": entity.get("user_id"),
        "user_email": entity.get("user_email"),
        "role": entity.get("role"),
        "kb_id": entity.get("kb_id"),
        "chat_id": entity.get("chat_id"),
        "memory_query": entity.get("memory_query"),
        "memory_types": _json_list(entity.get("memory_types")),
        "memory_ids": _json_list(entity.get("memory_ids")),
        "project_id": entity.get("project_id"),
        "policy": _json_object(entity.get("policy")),
        "reason": entity.get("reason"),
    }
    try:
        authz.admin_request_message(request)
    except Exception as exc:  # AuthzError and friends — all mean "not signable"
        raise ConsoleError(f"request is not canonicalisable: {exc}") from exc
    return request


# --- talking to the isolated signer ------------------------------------------


def _recv_line(connection: socket.socket, max_bytes: int = 1 << 20) -> bytes:
    """Read one newline-terminated line, bounded, so a silent signer cannot hang us."""
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = connection.recv(4096)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise ConsoleError("signer response exceeds the size limit")
        chunks.append(chunk)
        if b"\n" in chunk:
            break
    return b"".join(chunks).split(b"\n", 1)[0]


class SignerClient:
    """A thin line-JSON client for the isolated signer's unix socket.

    The console sends exactly two operations: `root-id` (to learn the pinned
    root the signer will accept) and `sign-admin-request`. There is deliberately
    no generic "call the signer" method — a console that could send arbitrary
    operations would be a console that could ask the signer to sign something it
    should not.
    """

    def __init__(self, socket_path: Path | str, *, timeout: float = 30.0):
        self.socket_path = Path(socket_path)
        self.timeout = timeout

    def call(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not self.socket_path.exists():
            raise ConsoleError(f"signer socket {self.socket_path} does not exist — is the signer running?")
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(self.timeout)
        try:
            connection.connect(str(self.socket_path))
            connection.sendall(json.dumps(payload).encode("utf-8") + b"\n")
            line = _recv_line(connection)
        except OSError as exc:
            raise ConsoleError(f"signer socket error: {exc}") from exc
        finally:
            connection.close()
        try:
            return json.loads(line.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ConsoleError(f"signer returned unparseable data: {exc}") from exc

    def root_id(self) -> str:
        response = self.call({"op": "root-id"})
        if not response.get("ok"):
            raise ConsoleError(f"signer refused root-id: {response.get('error')}")
        return response["root_id"]

    def sign(self, request: dict[str, Any]) -> dict[str, Any]:
        response = self.call({"op": "sign-admin-request", "root_id": self.root_id(), "request": request})
        if not response.get("ok"):
            raise ConsoleError(f"signer refused to sign: {response.get('error')}")
        return response["admin_request"]


# --- reaching a peer ----------------------------------------------------------


def overlay_host(overlay_ipv4: str) -> str:
    """`10.100.0.2/32` -> `10.100.0.2`. A peer address carries its prefix length."""
    return overlay_ipv4.split("/", 1)[0]


def bridge_url(overlay_ipv4: str, port: int = BACKING_PORT) -> str:
    return f"http://{overlay_host(overlay_ipv4)}:{port}"


def load_registry(path: Path | str) -> list[dict[str, Any]]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    entries = data.get("authorizations")
    if not isinstance(entries, list):
        raise ConsoleError(f"{path} has no authorizations[] list")
    return entries


def resolve_target(spec: str, entries: list[dict[str, Any]], *, port: int = BACKING_PORT) -> Target:
    """Resolve a node id, fingerprint, or URL to a callable target.

    A URL is taken as given (the operator names the host). Otherwise the registry
    copy is the source: an entry carries the node's id, its fingerprint and its
    overlay address, and the console refuses to invent any of them.
    """
    if spec.startswith(("http://", "https://")):
        return Target(node_id=None, fingerprint=None, url=spec.rstrip("/"))
    for entry in entries:
        identity = entry.get("identity") or {}
        if identity.get("node_id") == spec or entry.get("fingerprint") == spec:
            overlay = identity.get("overlay_ipv4")
            if not overlay:
                raise ConsoleError(f"registry entry for {spec!r} has no overlay_ipv4")
            return Target(
                node_id=identity.get("node_id"),
                fingerprint=entry.get("fingerprint"),
                url=bridge_url(overlay, port),
            )
    raise ConsoleError(f"no registry entry matches {spec!r}")


def dispatch(
    target: Target,
    action: str,
    signed_request: dict[str, Any],
    *,
    timeout: float = 15.0,
    opener: Any = None,
) -> dict[str, Any]:
    """POST the signed request to the peer's admin route.

    A peer that answers with a 4xx (its own WebUI refusing, a capability missing,
    a replay) is a *result*, not a transport failure: the body is the peer's
    answer and is handed back. Only a connection that never answers raises.
    """
    endpoint = target.url.rstrip("/") + ADMIN_PATH_PREFIX + action
    body = json.dumps(signed_request).encode("utf-8")
    request = urllib.request.Request(endpoint, data=body, headers={"Content-Type": "application/json"}, method="POST")
    open_url = opener or _NO_REDIRECT_OPENER.open
    try:
        with open_url(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8")
            return {"ok": True, "status": response.status, "payload": json.loads(raw)}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8") if exc.fp else ""
        try:
            payload = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            payload = {"raw": raw}
        return {"ok": False, "status": exc.code, "payload": payload}
    except urllib.error.URLError as exc:
        raise ConsoleError(f"cannot reach {endpoint}: {exc.reason}") from exc


# --- pushing to KDE Connect ---------------------------------------------------
#
# The implementation lives once in shared/sparknet-notify.py, which the peer's
# inbox-arrival path (fabric Step 67B) also calls. These are thin delegations so
# `console.notify_kde` keeps resolving for callers and tests while there is a
# single copy of "how a node pings a device" — a second copy here would drift from
# the one the guard uses, which is the same failure the repo forbids for authz.

_notify_module = None


def load_notify(shared_dir: Path | None = None):
    """The one node-local notification implementation, never a copy of it."""
    global _notify_module
    if _notify_module is None:
        shared = shared_dir or _shared_dir()
        _notify_module = _load("sparknet_console_notify", shared / "sparknet-notify.py")
    return _notify_module


def kde_devices_from_env(env: dict[str, str] | None = None) -> list[str]:
    return load_notify().kde_devices_from_env(env)


def discover_kde_devices(*, which: Any = None, run: Any = None) -> list[str]:
    return load_notify().discover_kde_devices(which=which, run=run)


def notify_kde(
    body: str,
    *,
    devices: list[str] | None = None,
    which: Any = None,
    run: Any = None,
    timeout: float = 10.0,
) -> bool:
    """Ping paired devices; a no-op when the binary or a device is absent.

    Delegates to shared/sparknet-notify.py so the console and a peer's inbox
    arrival ping through one implementation. A notification is a courtesy and must
    not block the console.
    """
    return load_notify().notify_kde(body, devices=devices, which=which, run=run, timeout=timeout)


# --- the console --------------------------------------------------------------


class Console:
    """Compose, sign and dispatch admin requests; collect the event feed."""

    def __init__(
        self,
        *,
        master_node_id: str,
        signer_socket: Path | str | None = None,
        registry: Path | str | None = None,
        ttl: int = DEFAULT_ADMIN_TTL_SECONDS,
        clock: Any = None,
        dry_run: bool = False,
        authz: Any = None,
        client: SignerClient | None = None,
        opener: Any = None,
        telemetry_spool: Path | str | None = None,
    ):
        self.master_node_id = master_node_id
        self.authz = authz or load_authz()
        self.ttl = ttl
        self.clock = clock
        self.dry_run = dry_run
        self.client = client or SignerClient(signer_socket or _default_signer_socket())
        self.opener = opener
        self.registry_path = Path(registry) if registry else None
        self.telemetry_spool = Path(telemetry_spool) if telemetry_spool else default_telemetry_spool()
        self._entries: list[dict[str, Any]] | None = None

    @property
    def entries(self) -> list[dict[str, Any]]:
        if self._entries is None:
            if self.registry_path is None:
                self._entries = []
            elif self.registry_path.is_file():
                self._entries = load_registry(self.registry_path)
            else:
                raise ConsoleError(f"registry {self.registry_path} not found")
        return self._entries

    def resolve(self, spec: str) -> Target:
        return resolve_target(spec, self.entries)

    def node_ids(self) -> list[str]:
        return [
            (entry.get("identity") or {}).get("node_id")
            for entry in self.entries
            if (entry.get("identity") or {}).get("node_id")
        ]

    def request(self, action: str, target: Target, entity: dict[str, Any] | None = None) -> dict[str, Any]:
        if not target.node_id or not target.fingerprint:
            # A URL-only target has no identity in the registry to bind to. The
            # signature covers target_node_id and target_fingerprint, so we cannot
            # simply omit them; the operator must resolve through the registry.
            raise ConsoleError(
                f"target {target.url} has no node id/fingerprint to bind the request to; "
                f"resolve it through the registry instead of a bare URL"
            )
        return compose_request(
            self.authz,
            action=action,
            master_node_id=self.master_node_id,
            target_node_id=target.node_id,
            target_fingerprint=target.fingerprint,
            entity=entity,
            ttl=self.ttl,
            clock=self.clock,
        )

    def send(self, action: str, *, spec: str, entity: dict[str, Any] | None = None) -> dict[str, Any]:
        target = self.resolve(spec)
        unsigned = self.request(action, target, entity)
        if self.dry_run:
            return {"ok": True, "dry_run": True, "target": target._asdict(), "request": unsigned}
        signed = self.client.sign(unsigned)
        return dispatch(target, action, signed, opener=self.opener)

    def trust_feed(self) -> list[dict[str, Any]]:
        """Surface flagged peers from the Master's telemetry spool, newest per peer.

        The spool is evidence the 8090 intake already recorded; this method only
        reads it. A status report carries the peer's current belief and retained
        share evidence, so the latest report for a fingerprint wins. Nothing here
        writes a registry, moves a trust level or clears a flag: a human decides,
        and only the Master's signed registry event changes the belief.
        """
        spool = self.telemetry_spool
        if not spool.is_file():
            return []
        latest: dict[str, dict[str, Any]] = {}
        try:
            lines = spool.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        reports: list[dict[str, Any]] = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                report = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(report, dict) and report.get("kind") == "status":
                reports.append(report)
        # Arrival order is not belief order: a delayed report must not overwrite
        # a newer status that arrived first. The issued timestamp is the tie-break.
        for report in sorted(reports, key=lambda row: str(row.get("issued_at") or "")):
            payload = report.get("payload")
            if not isinstance(payload, dict):
                continue
            trust = payload.get("trust")
            if not isinstance(trust, dict):
                continue
            level = str(trust.get("level") or "")
            retained = [str(flag) for flag in trust.get("retained_flags") or []]
            fingerprint = str(report.get("peer_fingerprint") or "")
            node = str(payload.get("node_id") or fingerprint or "unknown")
            key = fingerprint or node
            latest[key] = {
                "ts": str(report.get("issued_at") or ""),
                "node": node,
                "fingerprint": fingerprint or None,
                "event": "trust.flagged",
                "trust_level": level or "flagged",
                "retained_flags": retained,
                "evidence": list(trust.get("flagged_shares") or []),
                "source": report.get("source"),
            }
        rows = [row for row in latest.values() if row["trust_level"] == "flagged" or row["retained_flags"]]
        return sorted(rows, key=lambda row: row["ts"])

    def feed(self, specs: list[str]) -> list[dict[str, Any]]:
        """Fan out `list_events` over nodes, plus flagged telemetry, time-ordered.

        De-duplication is by the whole record: a node that restarts and re-reads
        its spool, or a request retried, must not make an event appear twice. The
        spool is append-only and may already hold a repeated row, so identity is
        the record's content, not its position. Flagged telemetry rows are added
        from the Master's own spool; they are evidence for a human, not an action.
        """
        collected: list[dict[str, Any]] = []
        seen: set[str] = set()
        for spec in specs:
            result = self.send("list_events", spec=spec)
            payload = result.get("payload") or {}
            node = payload.get("node") or spec
            for event in payload.get("events", []):
                key = json.dumps({"node": node, **event}, sort_keys=True, default=str)
                if key in seen:
                    continue
                seen.add(key)
                collected.append({"node": node, **event})
        for event in self.trust_feed():
            key = json.dumps(event, sort_keys=True, default=str)
            if key not in seen:
                seen.add(key)
                collected.append(event)
        collected.sort(key=lambda row: str(row.get("ts", "")))
        return collected


# --- CLI ----------------------------------------------------------------------


def build_entity(action: str, tokens: list[str], extras: list[str] | None = None) -> dict[str, Any]:
    fields = REQUIRED_ENTITY[action]
    if len(tokens) < len(fields):
        raise ConsoleError(f"{action} needs {', '.join(fields)}")
    entity = dict(zip(fields, tokens, strict=False))
    for item in extras or []:
        key, sep, value = item.partition("=")
        if not sep or not key:
            raise ConsoleError(f"--entity must be key=value, got {item!r}")
        entity[key] = value
    return entity


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Sparknet Master admin console: sign admin requests and dispatch them to peers."
    )
    parser.add_argument("verb", choices=sorted([*VERB_ACTIONS, "feed", "trust"]))
    parser.add_argument("target", nargs="?", help="node id, fingerprint, or http(s) URL")
    parser.add_argument("entity", nargs="*", help="entity fields for the action (user_id, role, ...)")
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--telemetry-spool", type=Path, default=None)
    parser.add_argument("--signer-socket", default=None)
    parser.add_argument("--master-node-id", default=os.environ.get("SPARKNET_NODE_ID", ""))
    parser.add_argument("--ttl", type=int, default=DEFAULT_ADMIN_TTL_SECONDS)
    parser.add_argument("--node", action="append", default=[], help="feed target (repeatable)")
    parser.add_argument(
        "--entity", dest="entity_extra", action="append", default=[], help="extra entity field key=value"
    )
    parser.add_argument("--dry-run", action="store_true", help="compose but do not sign or send")
    parser.add_argument("--ping", action="store_true", help="ping KDE devices with the feed summary")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not args.master_node_id:
        print("[console] --master-node-id (or SPARKNET_NODE_ID) is required", file=sys.stderr)
        return 1
    if args.verb not in ("feed", "trust") and not args.target:
        print(f"[console] {args.verb} requires a target node", file=sys.stderr)
        return 1

    console = Console(
        master_node_id=args.master_node_id,
        signer_socket=args.signer_socket,
        registry=args.registry,
        ttl=args.ttl,
        dry_run=args.dry_run,
        telemetry_spool=args.telemetry_spool,
    )
    try:
        if args.verb == "trust":
            rows = console.trust_feed()
            result: dict[str, Any] = {"ok": True, "count": len(rows), "trust": rows}
        elif args.verb == "feed":
            specs = args.node or console.node_ids()
            if not specs:
                raise ConsoleError("no feed targets: pass --node or a registry with nodes")
            events = console.feed(specs)
            result = {"ok": True, "count": len(events), "events": events}
            if args.ping:
                result["notified"] = notify_kde(f"{len(events)} admin event(s)", devices=kde_devices_from_env() or None)
        else:
            action = VERB_ACTIONS[args.verb]
            # The target names the node to talk to; it is NOT an entity field.
            # Prepending it here sent `user_id: "<node>"` and the peer refused
            # every user_id action as an unknown user (found live 2026-10-12).
            entity = build_entity(action, args.entity, args.entity_extra)
            result = console.send(action, spec=args.target, entity=entity)
    except ConsoleError as exc:
        print(f"[console] {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True, default=str))
    else:
        _print_human(args.verb, result)
    return 0 if result.get("ok", True) else 1


def _print_human(verb: str, result: dict[str, Any]) -> None:
    if verb == "trust":
        for row in result.get("trust", []):
            flags = ",".join(row.get("retained_flags") or []) or "-"
            print(
                f"{row.get('ts', '')}  {row.get('node', ''):<12}  trust={row.get('trust_level', '')}  "
                f"retained={flags}  evidence={len(row.get('evidence') or [])}"
            )
        print(f"{result.get('count', 0)} flagged node(s)")
        return
    if verb == "feed":
        for event in result.get("events", []):
            ts = event.get("ts", "")
            node = event.get("node", "")
            name = event.get("event", "")
            if name == "trust.flagged":
                flags = ",".join(event.get("retained_flags") or []) or "-"
                print(
                    f"{ts}  {node:<12}  {name}  trust={event.get('trust_level', '')}  "
                    f"retained={flags}  evidence={len(event.get('evidence') or [])}"
                )
                continue
            actor = event.get("actor", "")
            print(f"{ts}  {node:<12}  {name}  {actor}")
        print(f"{result.get('count', 0)} event(s)")
        return
    print(json.dumps(result, indent=2, sort_keys=True, default=str))


if __name__ == "__main__":
    raise SystemExit(main())
