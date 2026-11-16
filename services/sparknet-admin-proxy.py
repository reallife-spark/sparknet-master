#!/usr/bin/env python3
"""Master admin proxy — one origin to every node auth gateway.

The proxy holds **no** operational key and no node secret. It takes the human
admin identity the Master ingress already verified, resolves the target from
the signed registry (never from a caller-supplied URL), signs a short-lived
``sso-assertion`` with the Master node identity key, and forwards the request
over mTLS to that node's auth gateway. The node verifies the assertion against
the Master public key and then injects its own trusted headers.

The signed assertion is an envelope in ``shared/sparknet-authz.py``; the policy
and refusal vocabulary are in ``shared/sparknet-sso.py``. This service adds
routing and transport, not a second signing implementation.
"""

from __future__ import annotations

import argparse
import base64
import json
import ssl
import sys
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any, NamedTuple

ROLE_ROOT = Path(__file__).resolve().parent.parent
SHARED_DIR = ROLE_ROOT.parent / "shared"
sys.path.insert(0, str(SHARED_DIR))

try:
    from sparknet_loader import load_shared
except ImportError as exc:  # pragma: no cover - the bundle always carries the loader
    raise SystemExit(f"cannot load shared/sparknet_loader.py: {exc}") from exc

DEFAULT_REGISTRY = ROLE_ROOT / "manifests" / "node-authorizations.json"
DEFAULT_GATEWAY_PORT = 8182
ASSERTION_TTL_SECONDS = 120


class ProxyError(Exception):
    """A refusal the operator can act on."""


class Target(NamedTuple):
    node_id: str
    fingerprint: str
    url: str


def _load_sso() -> Any:
    return load_shared(
        "sparknet-sso.py",
        "sparknet_sso_admin_proxy",
        required=("sparknet-authz.py", "sparknet-sso.py"),
        error=ProxyError,
        message="cannot find shared/sparknet-sso.py; the proxy carries no policy copy",
    )


def load_registry(path: str | Path) -> list[dict[str, Any]]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProxyError(f"cannot read registry {path}: {exc}") from exc
    entries = data.get("authorizations")
    if not isinstance(entries, list):
        raise ProxyError(f"{path} has no authorizations[] list")
    return entries


def resolve_target(spec: str, entries: list[dict[str, Any]], *, gateway_port: int = DEFAULT_GATEWAY_PORT) -> Target:
    """Resolve a node id or fingerprint; a URL is refused.

    The Master proxy is not an open proxy. A caller naming an arbitrary host
    could turn the Master's admin session into a request forwarder, so the
    registry is the only allow-list.
    """
    if not isinstance(spec, str) or not spec.strip():
        raise ProxyError("a node id or fingerprint is required")
    if spec.startswith(("http://", "https://")):
        raise ProxyError("the admin proxy accepts a registry node id or fingerprint, never a URL")
    for entry in entries:
        identity = entry.get("identity") or {}
        if identity.get("node_id") == spec or entry.get("fingerprint") == spec:
            overlay = identity.get("overlay_ipv4")
            if not overlay:
                raise ProxyError(f"registry entry for {spec!r} has no overlay_ipv4")
            host = str(overlay).split("/", 1)[0]
            return Target(
                node_id=str(identity.get("node_id") or spec),
                fingerprint=str(entry.get("fingerprint") or ""),
                url=f"https://{host}:{gateway_port}",
            )
    raise ProxyError(f"no registry entry matches {spec!r}")


def build_assertion(
    target: Target,
    *,
    master_node_id: str,
    admin_email: str,
    admin_role: str,
    groups: list[str],
    now: float | None = None,
) -> dict[str, Any]:
    """Build the unsigned assertion; the caller signs it with the Master node key."""
    instant = int(now if now is not None else time.time())
    if admin_role not in ("admin", "user"):
        raise ProxyError(f"unknown admin role {admin_role!r}")
    return {
        "schema": "sparknet-sso-assertion/1",
        "assertion_id": uuid.uuid4().hex,
        "master_node_id": master_node_id,
        "target_node_id": target.node_id,
        "target_fingerprint": target.fingerprint,
        "subject": admin_email,
        "email": admin_email,
        "role": admin_role,
        "groups": list(groups),
        "issued_at": instant,
        "expires_at": instant + ASSERTION_TTL_SECONDS,
        "nonce": uuid.uuid4().hex,
    }


def forward(
    target: Target,
    path: str,
    *,
    private_key: Any,
    master_node_id: str,
    admin_email: str,
    admin_role: str = "admin",
    groups: list[str] | None = None,
    method: str = "GET",
    body: bytes | None = None,
    extra_headers: dict[str, str] | None = None,
    timeout: float = 30.0,
    opener: Callable[[urllib.request.Request], Any] | None = None,
    ssl_context: ssl.SSLContext | None = None,
    now: float | None = None,
) -> tuple[int, dict[str, str], bytes]:
    """Sign one assertion and forward one request to a node auth gateway."""
    sso = _load_sso()
    assertion = build_assertion(
        target,
        master_node_id=master_node_id,
        admin_email=admin_email,
        admin_role=admin_role,
        groups=groups or ([sso.ADMIN_GROUP] if admin_role == "admin" else [sso.USER_GROUP]),
        now=now,
    )
    signed = sso.sign_assertion(assertion, private_key)
    packed = base64.b64encode(json.dumps(signed, sort_keys=True, separators=(",", ":")).encode("utf-8")).decode("ascii")
    headers = {"Accept": "application/json", "X-Sparknet-Assertion": packed}
    for name, value in (extra_headers or {}).items():
        lowered = name.lower()
        if lowered.startswith(("x-user-", "x-auth-request-", "x-client-", "x-sparknet-assertion")):
            continue
        headers[name] = value
    url = target.url.rstrip("/") + "/" + path.lstrip("/")
    request = urllib.request.Request(url, data=body, headers=headers, method=method.upper())
    if opener is None and ssl_context is not None:
        open_url = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl_context)).open
    elif opener is None:
        open_url = lambda request: urllib.request.urlopen(request, timeout=timeout)  # noqa: E731
    else:
        open_url = opener
    try:
        with open_url(request) as response:
            status = int(getattr(response, "status", 200))
            response_headers = {name: value for name, value in getattr(response, "headers", {}).items()}
            payload = response.read()
    except urllib.error.HTTPError as exc:
        return int(exc.code), {name: value for name, value in exc.headers.items()}, exc.read()
    except urllib.error.URLError as exc:
        raise ProxyError(f"target {target.node_id} did not answer: {exc}") from exc
    return status, response_headers, payload


def _load_http() -> Any:
    return load_shared(
        "sparknet-http.py",
        "sparknet_http_admin_proxy",
        required=("sparknet-authz.py", "sparknet-http.py"),
        error=ProxyError,
        message="cannot find shared/sparknet-http.py; the proxy carries no second listener",
    )


def parse_node_path(path: str) -> tuple[str, str]:
    """Split ``/nodes/<node_id>/<rest>`` into the registry id and the rest."""
    prefix = "/nodes/"
    if not path.startswith(prefix):
        raise ProxyError("the proxy path must start with /nodes/<node id>/")
    rest = path[len(prefix) :]
    node_id, _, subpath = rest.partition("/")
    if not node_id:
        raise ProxyError("a node id is required after /nodes/")
    return node_id, "/" + subpath


def _header(headers: Any, name: str) -> str:
    wanted = name.lower()
    for key, value in headers.items():
        if str(key).lower() == wanted:
            return str(value)
    return ""


def build_server(
    *,
    registry: str | Path,
    private_key: Any,
    master_node_id: str,
    bind: str = "127.0.0.1",
    port: int = 8191,
    gateway_port: int = DEFAULT_GATEWAY_PORT,
    ssl_context: ssl.SSLContext | None = None,
    forward_fn: Callable[..., tuple[int, dict[str, str], bytes]] | None = None,
) -> Any:
    """Build the loopback listener the Master nginx routes ``/nodes/`` to."""
    http = _load_http()
    send = forward_fn or forward

    def handle(request: Any) -> Any:
        if request.source != "loopback":
            return http.Response(status=403, payload={"ok": False, "reason": "not-loopback"})
        email = _header(request.headers, "X-User-Email").strip()
        role = _header(request.headers, "X-User-Role").strip()
        if not email or role != "admin":
            return http.Response(status=403, payload={"ok": False, "reason": "admin-required"})
        try:
            node_id, subpath = parse_node_path(request.path)
            target = resolve_target(node_id, load_registry(registry), gateway_port=gateway_port)
        except ProxyError as exc:
            return http.Response(status=404, payload={"ok": False, "reason": "unknown-target", "detail": str(exc)})
        from urllib.parse import urlencode

        query = urlencode([(key, value) for key, values in request.query.items() for value in values])
        forward_path = subpath + (f"?{query}" if query else "")
        groups = [part.strip() for part in _header(request.headers, "X-User-Groups").split(",") if part.strip()]
        try:
            status, headers, body = send(
                target,
                forward_path,
                private_key=private_key,
                master_node_id=master_node_id,
                admin_email=email,
                admin_role="admin",
                groups=groups,
                method=request.method,
                body=request.body or None,
                extra_headers=dict(request.headers),
                ssl_context=ssl_context,
            )
        except ProxyError as exc:
            return http.Response(status=502, payload={"ok": False, "reason": "target-unreachable", "detail": str(exc)})
        hop_by_hop = {"content-length", "transfer-encoding", "connection"}
        clean_headers = {name: value for name, value in headers.items() if name.lower() not in hop_by_hop}
        content_type = next(
            (value for name, value in headers.items() if name.lower() == "content-type"),
            "application/octet-stream",
        )
        return http.Response(status=status, raw=body, headers=clean_headers, content_type=content_type)

    return http.listen(
        [http.Route("/nodes/", handle, method="*", auth="plain", source="loopback", prefix=True)],
        name="master-admin-proxy",
        bind=bind,
        port=port,
        health=False,
    )


def _tls_context(ca: Path | None) -> ssl.SSLContext:
    if ca is None:
        return ssl.create_default_context()
    context = ssl.create_default_context(cafile=str(ca))
    return context


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sparknet Master admin proxy (registry-only, signed assertion)")
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--node", default=None, help="registry node id or fingerprint (one-shot mode)")
    parser.add_argument("--path", default="/", help="path to forward after the node gateway")
    parser.add_argument("--method", default="GET")
    parser.add_argument("--admin-email", default=None)
    parser.add_argument("--admin-role", default="admin", choices=["admin", "user"])
    parser.add_argument("--groups", default="", help="comma-separated IdP groups")
    parser.add_argument("--master-node-id", default="")
    parser.add_argument("--key", type=Path, required=True, help="Master node identity private key (0600)")
    parser.add_argument("--gateway-port", type=int, default=DEFAULT_GATEWAY_PORT)
    parser.add_argument("--ca", type=Path, default=None, help="CA bundle for node gateway TLS")
    parser.add_argument("--serve", action="store_true", help="listen on loopback for the Master ingress")
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8191)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        sso = _load_sso()
        private_key = sso.load_private_key(args.key)
        context = _tls_context(args.ca)
        if args.serve:
            if not args.master_node_id:
                parser.error("--master-node-id is required with --serve")
            server = build_server(
                registry=args.registry,
                private_key=private_key,
                master_node_id=args.master_node_id,
                bind=args.bind,
                port=args.port,
                gateway_port=args.gateway_port,
                ssl_context=context,
            )
            server.start()
            print(f"[admin-proxy] listening on {args.bind}:{args.port}", file=sys.stderr)
            try:
                server.wait()
            except KeyboardInterrupt:
                pass
            finally:
                server.stop()
            return 0
        if not args.node or not args.admin_email:
            parser.error("--node and --admin-email are required unless --serve is used")
        target = resolve_target(args.node, load_registry(args.registry), gateway_port=args.gateway_port)
        groups = [part.strip() for part in args.groups.split(",") if part.strip()]
        status, headers, payload = forward(
            target,
            args.path,
            private_key=private_key,
            master_node_id=args.master_node_id,
            admin_email=args.admin_email,
            admin_role=args.admin_role,
            groups=groups,
            ssl_context=context,
        )
    except (ProxyError, ValueError) as exc:
        print(f"[admin-proxy] {exc}", file=sys.stderr)
        return 1
    result = {
        "ok": 200 <= status < 300,
        "node": target.node_id,
        "status": status,
        "headers": headers,
        "body": payload.decode("utf-8", "replace"),
    }
    print(json.dumps(result, indent=2, sort_keys=True) if args.json else result["body"])
    return 0 if result["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
