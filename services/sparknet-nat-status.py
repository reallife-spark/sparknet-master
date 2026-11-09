#!/usr/bin/env python3
"""The 4222 NAT administration surface: status and dry-run only.

The service reports the overlay's current NAT/routing state and can describe a
proposed check, but it contains no command that changes a route, a rule, a
sysctl or an interface. A signed request from a node holding `admin-supervise`
may read it; no request can make it write.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import signal
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

ROLE_ROOT = Path(__file__).resolve().parent.parent
FABRIC_ROOT = ROLE_ROOT.parent
DEFAULT_REGISTRY = ROLE_ROOT / "manifests" / "node-authorizations.json"
READ_COMMANDS = {
    "wireguard": ("wg", "show"),
    "addresses": ("ip", "-4", "addr", "show"),
    "routes": ("ip", "route", "show"),
    "forwarding": ("sysctl", "-n", "net.ipv4.ip_forward"),
    "nat": ("iptables", "-t", "nat", "-S"),
}


def _load(name: str, path: Path) -> Any:
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _load_http() -> Any:
    path = Path(os.environ.get("SPARKNET_SHARED_DIR", "").strip() or FABRIC_ROOT / "shared")
    return _load("sparknet_http_nat_status", path / "sparknet-http.py")


class NatError(Exception):
    def __init__(self, status: int, reason: str, detail: str = "") -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason
        self.detail = detail


class NatStatus:
    def __init__(self, registry: Path, trusted_keys: dict[str, Any], authz: Any):
        self.registry_path = Path(registry)
        self.trusted_keys = dict(trusted_keys)
        self.authz = authz

    def _registry(self) -> dict[str, Any]:
        try:
            document = json.loads(self.registry_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise NatError(503, "registry-unavailable", str(exc)) from exc
        return document if isinstance(document, dict) else {}

    def authorize(self, node_id: str) -> None:
        if node_id not in self.trusted_keys:
            raise NatError(403, "no-key", "caller has no trusted transport key")
        registry = self._registry()
        entry = next(
            (
                item
                for item in registry.get("authorizations") or []
                if isinstance(item, dict) and str((item.get("identity") or {}).get("node_id") or "") == node_id
            ),
            None,
        )
        if entry is None:
            raise NatError(403, "unauthorized", "caller is not in the registry")
        encoded = registry.get("master_public_key_b64")
        if not isinstance(encoded, str) or not encoded:
            raise NatError(503, "registry-invalid", "no master_public_key_b64")
        decision = self.authz.evaluate(entry.get("identity") or {}, registry, self.authz.public_key_from_b64(encoded))
        if not decision.allowed or "admin-supervise" not in decision.capabilities:
            raise NatError(403, "no-capability", "caller needs admin-supervise")

    @staticmethod
    def _run(command: tuple[str, ...]) -> dict[str, Any]:
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=5, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"ok": False, "error": str(exc)}
        return {
            "ok": result.returncode == 0,
            "exit": result.returncode,
            "stdout": result.stdout[:8192],
            "stderr": result.stderr[:1024],
        }

    def status(self) -> dict[str, Any]:
        return {name: self._run(command) for name, command in READ_COMMANDS.items()}

    def dry_run(self, proposal: dict[str, Any]) -> dict[str, Any]:
        return {
            "ok": True,
            "dry_run": True,
            "proposal": proposal,
            "changes": [],
            "note": "4222 is status/dry-run only; no route, rule, sysctl or interface is changed",
            "status": self.status(),
        }


def router_for(status: NatStatus):
    def router(method: str, path: str, body: dict[str, Any], identity: dict[str, Any]):
        caller = str(identity.get("verified_key_id") or "")
        try:
            status.authorize(caller)
            if method == "GET" and path == "/v1/status":
                return 200, {"ok": True, "status": status.status()}
            if method == "POST" and path == "/v1/dry-run":
                return 200, status.dry_run(body.get("proposal") if isinstance(body.get("proposal"), dict) else {})
            if method == "GET" and path == "/v1/dry-run":
                return 200, status.dry_run({})
        except NatError as exc:
            return exc.status, {"ok": False, "reason": exc.reason, "detail": exc.detail}
        return 404, {"ok": False, "reason": "not-found"}

    return router


def _keyring(values: list[str], authz: Any) -> dict[str, Any]:
    keys: dict[str, Any] = {}
    for item in values:
        node_id, separator, path = item.partition("=")
        if not separator:
            raise NatError(400, "bad-key", item)
        keys[node_id] = authz.load_public_key(Path(path))
    if not keys:
        raise NatError(500, "no-verifier", "at least one --trusted-key is required")
    return keys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="read-only 4222 NAT status and dry-run")
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4222)
    parser.add_argument("--trusted-key", action="append", default=[], metavar="NODE_ID=PATH")
    args = parser.parse_args(argv)
    try:
        http = _load_http()
        authz = http._load_authz()
        status = NatStatus(args.registry, _keyring(args.trusted_key, authz), authz)
    except (OSError, ValueError, NatError) as exc:
        print(f"sparknet-nat-status: {exc}", file=sys.stderr)
        return 2
    server = http.serve(router_for(status), bind=args.bind, port=args.port, public_keys=status.trusted_keys)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True)
    thread.start()
    stopping = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopping.set())
    signal.signal(signal.SIGINT, lambda *_: stopping.set())
    print(f"sparknet-nat-status: 4222 on {args.bind}:{args.port} (read-only)", flush=True)
    try:
        while not stopping.wait(1.0):
            pass
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
