#!/usr/bin/env python3
"""A private, token-gated OCI distribution surface for signed release artifacts.

This is deliberately a small **read-only** registry, not a second image builder.
Images are assembled and signed elsewhere; this process only serves content that
an operator has placed in a content-addressed root. It is bound to loopback and
requires a bearer token because a container image is executable content: a
registry that any local process can write is a distribution path for unsigned
code.

Layout under ``--root``::

    blobs/sha256/<64 lowercase hex>          raw blob bytes
    manifests/<name>/<reference>.json        OCI image manifest

``<name>`` is a Docker repository name (lowercase path components). A reference
is either a tag or a ``sha256:`` digest. Paths are parsed, never joined from raw
request text, so ``..`` and absolute names cannot escape the root.

The service is intentionally not wired into the package installer or the
self-improvement loop. A release manifest names the image digest; promotion to a
running container remains an explicit operator action.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import stat
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

DEFAULT_ROOT = Path.home() / ".local" / "state" / "sparknet" / "master-node" / "registry"
DEFAULT_PORT = 5000
NAME_RE = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$")
TAG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
MAX_MANIFEST_BYTES = 4 << 20


class RegistryError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def _require(condition: bool, status: int, code: str, message: str) -> None:
    if not condition:
        raise RegistryError(status, code, message)


def normalize_name(value: str) -> str:
    _require(
        isinstance(value, str) and bool(NAME_RE.fullmatch(value)),
        HTTPStatus.NOT_FOUND,
        "name-invalid",
        "invalid repository name",
    )
    return value


def normalize_reference(value: str) -> str:
    _require(
        isinstance(value, str) and (bool(TAG_RE.fullmatch(value)) or bool(DIGEST_RE.fullmatch(value))),
        HTTPStatus.NOT_FOUND,
        "reference-invalid",
        "invalid manifest reference",
    )
    return value


def normalize_digest(value: str) -> str:
    _require(
        isinstance(value, str) and bool(DIGEST_RE.fullmatch(value)),
        HTTPStatus.NOT_FOUND,
        "digest-invalid",
        "invalid blob digest",
    )
    return value


class Store:
    """Content-addressed manifest and blob lookup with no write path."""

    def __init__(self, root: Path):
        self.root = Path(root).resolve()
        self.blobs = self.root / "blobs" / "sha256"
        self.manifests = self.root / "manifests"

    def manifest(self, name: str, reference: str) -> tuple[bytes, str]:
        name = normalize_name(name)
        reference = normalize_reference(reference)
        path = self.manifests.joinpath(*name.split("/"), f"{reference}.json")
        try:
            data = path.read_bytes()
        except FileNotFoundError as exc:
            raise RegistryError(HTTPStatus.NOT_FOUND, "manifest-unknown", "manifest not found") from exc
        _require(
            len(data) <= MAX_MANIFEST_BYTES,
            HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            "manifest-too-large",
            "manifest is too large",
        )
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        if reference.startswith("sha256:") and reference != digest:
            raise RegistryError(
                HTTPStatus.NOT_FOUND, "manifest-digest-mismatch", "manifest content does not match its digest reference"
            )
        return data, digest

    def blob(self, digest: str) -> bytes:
        digest = normalize_digest(digest)
        path = self.blobs / digest.split(":", 1)[1]
        try:
            data = path.read_bytes()
        except FileNotFoundError as exc:
            raise RegistryError(HTTPStatus.NOT_FOUND, "blob-unknown", "blob not found") from exc
        actual = "sha256:" + hashlib.sha256(data).hexdigest()
        if actual != digest:
            raise RegistryError(
                HTTPStatus.INTERNAL_SERVER_ERROR, "blob-corrupt", "blob content does not match its digest"
            )
        return data

    def tags(self, name: str) -> list[str]:
        name = normalize_name(name)
        directory = self.manifests.joinpath(*name.split("/"))
        if not directory.is_dir():
            raise RegistryError(HTTPStatus.NOT_FOUND, "name-unknown", "repository not found")
        return sorted(
            path.stem
            for path in directory.glob("*.json")
            if TAG_RE.fullmatch(path.stem) or DIGEST_RE.fullmatch(path.stem)
        )

    def catalog(self) -> list[str]:
        if not self.manifests.is_dir():
            return []
        names = []
        for path in self.manifests.rglob("*.json"):
            relative = path.relative_to(self.manifests).with_suffix("")
            candidate = relative.as_posix()
            if NAME_RE.fullmatch(candidate):
                names.append(candidate)
        return sorted(set(names))


def read_token(token_file: Path | None, env: str | None) -> str:
    if env:
        token = env.strip()
    elif token_file:
        _require(
            token_file.is_file(),
            HTTPStatus.INTERNAL_SERVER_ERROR,
            "token-missing",
            f"token file not found: {token_file}",
        )
        mode = stat.S_IMODE(token_file.stat().st_mode)
        _require(
            mode & 0o077 == 0,
            HTTPStatus.INTERNAL_SERVER_ERROR,
            "token-mode",
            "token file must not be group/other readable",
        )
        token = token_file.read_text(encoding="utf-8").strip()
    else:
        token = ""
    _require(
        len(token) >= 16,
        HTTPStatus.INTERNAL_SERVER_ERROR,
        "token-required",
        "a bearer token of at least 16 characters is required",
    )
    return token


class RegistryHTTPServer(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], store: Store, token: str):
        self.store = store
        self.token = token
        super().__init__(address, RegistryHandler)


class RegistryHandler(BaseHTTPRequestHandler):
    server_version = "sparknet-registry/1"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    @property
    def registry(self) -> RegistryHTTPServer:
        return self.server  # type: ignore[return-value]

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"[registry] {self.address_string()} {fmt % args}", file=sys.stderr, flush=True)

    def _authorized(self) -> bool:
        value = self.headers.get("Authorization", "")
        if not value.startswith("Bearer "):
            return False
        supplied = value[len("Bearer ") :].strip()
        return hmac.compare_digest(supplied, self.registry.token)

    def _headers(
        self, status: int, length: int = 0, content_type: str = "application/json", digest: str | None = None
    ) -> None:
        self.send_response(status)
        self.send_header("Docker-Distribution-API-Version", "registry/2.0")
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        if digest:
            self.send_header("Docker-Content-Digest", digest)
        self.end_headers()

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8") + b"\n"
        self._headers(status, len(body))
        self.wfile.write(body)

    def _error(self, error: RegistryError) -> None:
        self._json(error.status, {"errors": [{"code": error.code, "message": error.message}], "status": error.status})

    def _unauthorized(self) -> None:
        self.send_response(HTTPStatus.UNAUTHORIZED)
        self.send_header("Docker-Distribution-API-Version", "registry/2.0")
        self.send_header("Content-Length", "0")
        self.send_header("WWW-Authenticate", 'Bearer realm="sparknet-registry"')
        self.end_headers()

    def _path_parts(self) -> list[str]:
        raw = self.path.split("?", 1)[0]
        _require(raw.startswith("/v2/") or raw == "/v2", HTTPStatus.NOT_FOUND, "not-found", "unknown route")
        parts = [part for part in raw.split("/") if part]
        _require(all(part not in (".", "..") for part in parts), HTTPStatus.NOT_FOUND, "not-found", "invalid path")
        return parts

    def do_HEAD(self) -> None:
        self._dispatch(head=True)

    def do_GET(self) -> None:
        self._dispatch(head=False)

    def _dispatch(self, head: bool) -> None:
        try:
            if not self._authorized():
                self._unauthorized()
                return
            parts = self._path_parts()
            if parts == ["v2"]:
                self._json(HTTPStatus.OK, {"name": "sparknet-registry", "version": "1"})
                return
            if len(parts) == 2 and parts[1] == "_catalog":
                self._json(HTTPStatus.OK, {"repositories": self.registry.store.catalog()})
                return
            if len(parts) >= 4 and parts[0] == "v2" and parts[-2] == "manifests":
                name = "/".join(parts[1:-2])
                data, digest = self.registry.store.manifest(name, parts[-1])
                self._headers(HTTPStatus.OK, len(data), "application/vnd.oci.image.manifest.v1+json", digest)
                if not head:
                    self.wfile.write(data)
                return
            if len(parts) >= 4 and parts[0] == "v2" and parts[-2] == "blobs":
                digest = parts[-1]
                data = self.registry.store.blob(digest)
                self._headers(HTTPStatus.OK, len(data), "application/octet-stream", digest)
                if not head:
                    self.wfile.write(data)
                return
            if len(parts) >= 4 and parts[0] == "v2" and parts[-2:] == ["tags", "list"]:
                name = "/".join(parts[1:-2])
                self._json(HTTPStatus.OK, {"name": name, "tags": self.registry.store.tags(name)})
                return
            raise RegistryError(HTTPStatus.NOT_FOUND, "not-found", "unknown route")
        except RegistryError as exc:
            self._error(exc)
        except (BrokenPipeError, ConnectionResetError):
            return


def serve(store: Store, token: str, bind: str, port: int) -> None:
    server = RegistryHTTPServer((bind, port), store, token)
    print(f"[registry] listening on http://{bind}:{server.server_port} root={store.root}", file=sys.stderr, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Private token-gated OCI registry (read-only).")
    parser.add_argument("--root", type=Path, default=Path(os.environ.get("SPARKNET_REGISTRY_ROOT", DEFAULT_ROOT)))
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--token-file", type=Path, default=None)
    parser.add_argument("--describe", action="store_true")
    args = parser.parse_args(argv)

    if args.describe:
        print(
            json.dumps(
                {
                    "bind": args.bind,
                    "port": args.port,
                    "root": str(args.root),
                    "auth": "bearer token; loopback only",
                    "mode": "read-only OCI distribution",
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    if args.bind not in {"127.0.0.1", "::1", "localhost"}:
        print("[registry] refusing a non-loopback bind; a private registry is not an overlay service", file=sys.stderr)
        return 2
    try:
        token = read_token(args.token_file, os.environ.get("SPARKNET_REGISTRY_TOKEN"))
        store = Store(args.root)
    except (RegistryError, OSError) as exc:
        print(f"[registry] {exc}", file=sys.stderr)
        return 1
    serve(store, token, args.bind, args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
