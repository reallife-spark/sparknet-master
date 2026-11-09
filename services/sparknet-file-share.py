#!/usr/bin/env python3
"""The 4221 read-only file share: signed list and fetch, no write route.

The Master hosts a directory of shared fabric artifacts. A peer on the overlay
with `p2p-sync` may list it and fetch one file per signed request. Paths are
resolved under the configured root, symlinks are skipped, and there is no POST
handler that writes anything.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
import signal
import sys
import threading
import urllib.parse
from pathlib import Path, PurePosixPath
from typing import Any

ROLE_ROOT = Path(__file__).resolve().parent.parent
FABRIC_ROOT = ROLE_ROOT.parent
DEFAULT_REGISTRY = ROLE_ROOT / "manifests" / "node-authorizations.json"
MAX_BYTES = 2 * 1024 * 1024


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
    return _load("sparknet_http_file_share", path / "sparknet-http.py")


class ShareError(Exception):
    def __init__(self, status: int, reason: str, detail: str = "") -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason
        self.detail = detail


class FileShare:
    def __init__(self, root: Path, registry: Path, trusted_keys: dict[str, Any], authz: Any, *, capability="p2p-sync"):
        self.root = Path(root)
        self.registry_path = Path(registry)
        self.trusted_keys = dict(trusted_keys)
        self.authz = authz
        self.capability = capability

    def _registry(self) -> dict[str, Any]:
        try:
            document = json.loads(self.registry_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ShareError(503, "registry-unavailable", str(exc)) from exc
        return document if isinstance(document, dict) else {}

    def authorize(self, node_id: str) -> None:
        if node_id not in self.trusted_keys:
            raise ShareError(403, "no-key", "caller has no trusted transport key")
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
            raise ShareError(403, "unauthorized", "caller is not in the registry")
        encoded = registry.get("master_public_key_b64")
        if not isinstance(encoded, str) or not encoded:
            raise ShareError(503, "registry-invalid", "no master_public_key_b64")
        decision = self.authz.evaluate(entry.get("identity") or {}, registry, self.authz.public_key_from_b64(encoded))
        if not decision.allowed or self.capability not in decision.capabilities:
            raise ShareError(403, "no-capability", f"caller needs {self.capability}")

    def _safe(self, relative: str) -> Path:
        path = PurePosixPath(relative)
        if path.is_absolute() or not path.parts or any(part in ("", ".", "..") for part in path.parts):
            raise ShareError(400, "unsafe-path", relative)
        candidate = self.root / path
        try:
            candidate.resolve().relative_to(self.root.resolve())
        except ValueError as exc:
            raise ShareError(400, "unsafe-path", relative) from exc
        if candidate.is_symlink() or not candidate.is_file():
            raise ShareError(404, "not-found", relative)
        return candidate

    def listing(self) -> list[dict[str, Any]]:
        if not self.root.is_dir():
            raise ShareError(503, "share-unavailable", str(self.root))
        entries: list[dict[str, Any]] = []
        for path in sorted(self.root.rglob("*")):
            if len(entries) >= 1000:
                break
            if path.is_symlink() or not path.is_file():
                continue
            relative = path.relative_to(self.root).as_posix()
            entries.append({"path": relative, "size": path.stat().st_size})
        return entries

    def fetch(self, relative: str) -> dict[str, Any]:
        path = self._safe(relative)
        content = path.read_bytes()
        if len(content) > MAX_BYTES:
            raise ShareError(413, "too-large", f"{len(content)} bytes")
        return {
            "path": PurePosixPath(relative).as_posix(),
            "size": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
            "content_b64": base64.b64encode(content).decode("ascii"),
        }


def router_for(share: FileShare):
    def router(method: str, path: str, body: dict[str, Any], identity: dict[str, Any]):
        caller = str(identity.get("verified_key_id") or "")
        try:
            share.authorize(caller)
            if method == "GET" and path == "/v1/health":
                return 200, {"ok": True, "root": str(share.root), "files": len(share.listing())}
            if method == "GET" and path == "/v1/files":
                return 200, {"ok": True, "files": share.listing()}
            if method == "GET" and path.startswith("/v1/file/"):
                return 200, {"ok": True, **share.fetch(urllib.parse.unquote(path[len("/v1/file/") :]))}
        except ShareError as exc:
            return exc.status, {"ok": False, "reason": exc.reason, "detail": exc.detail}
        return 404, {"ok": False, "reason": "not-found"}

    return router


def _keyring(values: list[str], authz: Any) -> dict[str, Any]:
    keys: dict[str, Any] = {}
    for item in values:
        node_id, separator, path = item.partition("=")
        if not separator:
            raise ShareError(400, "bad-key", item)
        keys[node_id] = authz.load_public_key(Path(path))
    if not keys:
        raise ShareError(500, "no-verifier", "at least one --trusted-key is required")
    return keys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="read-only 4221 file share")
    parser.add_argument("--root", type=Path, default=Path("/srv/sparknet/share"))
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4221)
    parser.add_argument("--trusted-key", action="append", default=[], metavar="NODE_ID=PATH")
    args = parser.parse_args(argv)
    try:
        http = _load_http()
        authz = http._load_authz()
        share = FileShare(args.root, args.registry, _keyring(args.trusted_key, authz), authz)
    except (OSError, ValueError, ShareError) as exc:
        print(f"sparknet-file-share: {exc}", file=sys.stderr)
        return 2
    server = http.serve(router_for(share), bind=args.bind, port=args.port, public_keys=share.trusted_keys)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True)
    thread.start()
    stopping = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopping.set())
    signal.signal(signal.SIGINT, lambda *_: stopping.set())
    print(f"sparknet-file-share: 4221 on {args.bind}:{args.port} root={share.root}", flush=True)
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
