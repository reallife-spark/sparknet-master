#!/usr/bin/env python3
"""The Master's uplift intake: consented vectors, inventory, traces and KV.

This is the peer -> Master half of the Qdrant/uplift design. It is one
overlay-only listener on 8091 with signed routes:

    POST /api/v1/inventory       small JSON inventory batch
    POST /api/v1/vector-snapshot binary Qdrant snapshot + manifest header
    POST /api/v1/trace-batch     JSON teacher-trace batch
    POST /api/v1/kv-artifact     binary raw-KV artifact + manifest header
    GET  /v1/health              liveness

Authentication is layered, in this order:

1. the source must be a registered, non-revoked peer overlay address;
2. the request must carry a valid Ed25519 signature from that peer's pinned
   node key (``--trusted-key NODE_ID=PATH``);
3. the registry entry must hold the peer-held ``model-uplift`` capability;
4. freshness and a replay nonce are checked.

The service holds no signing key and cannot reach the signer. It stores what a
consented peer sent; it never makes an authority decision, never writes a
registry and never serves the stored data back through 4223.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "shared"))
from sparknet_loader import load_by_path

NODE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

SERVICE_DIR = Path(__file__).resolve().parent
ROLE_ROOT = SERVICE_DIR.parent
FABRIC_ROOT = ROLE_ROOT.parent
DEFAULT_BIND = "10.100.0.1"
DEFAULT_PORT = 8091
DEFAULT_STATE = Path(os.environ.get("SPARKNET_UPLIFT_STATE", "/srv/sparknet/uplift"))
DEFAULT_REGISTRY = ROLE_ROOT / "manifests" / "node-authorizations.json"
MAX_JSON = 8 * 1024 * 1024
MAX_ARTIFACT = 1024 * 1024 * 1024
MAX_STUDENT_ARTIFACT = 4 * 1024 * 1024 * 1024
REPLAY_WINDOW = 300
INVENTORY_NAMESPACE = uuid.UUID("c3a7bb6e-4f6d-5d8e-9b8a-2b4f2f5b9c11")
QDRANT_COLLECTION = "uplift-inventory"


class Refusal(Exception):
    def __init__(self, status: int, reason: str, detail: str = "") -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason
        self.detail = detail


def _load(name: str, path: Path):
    if not path.is_file():
        return None
    return load_by_path(name, path)


def load_authz() -> Any:
    return _load("sparknet_uplift_authz", FABRIC_ROOT / "shared" / "sparknet-authz.py")


def load_http() -> Any:
    return _load("sparknet_uplift_http", FABRIC_ROOT / "shared" / "sparknet-http.py")


def _bare(address: str) -> str:
    return str(address or "").split("/", 1)[0].strip()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso() -> str:
    return _now().isoformat(timespec="seconds").replace("+00:00", "Z")


class Registry:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.entries: list[dict[str, Any]] = []
        self.master_key = None
        self._mtime_ns = 0
        self.reload()

    def refresh(self) -> None:
        try:
            mtime = self.path.stat().st_mtime_ns
        except OSError as exc:
            raise Refusal(503, "registry-unavailable", str(exc)) from exc
        if mtime != self._mtime_ns:
            self.reload()

    def reload(self) -> None:
        data = json.loads(self.path.read_text(encoding="utf-8"))
        entries = data.get("authorizations") if isinstance(data, dict) else None
        if not isinstance(entries, list):
            raise Refusal(503, "registry-invalid", "registry has no authorizations[]")
        self.entries = [entry for entry in entries if isinstance(entry, dict)]
        self._mtime_ns = self.path.stat().st_mtime_ns
        authz = load_authz()
        try:
            self.master_key = authz.public_key_from_b64(str(data.get("master_public_key_b64") or ""))
        except Exception as exc:
            raise Refusal(503, "registry-invalid", f"master key: {exc}") from exc

    def by_source(self, source: str) -> dict[str, Any] | None:
        source = _bare(source)
        for entry in self.entries:
            if _bare(str(entry.get("overlay_ipv4") or "")) == source:
                return entry
        return None

    def by_node_id(self, node_id: str) -> dict[str, Any] | None:
        for entry in self.entries:
            identity = entry.get("identity") if isinstance(entry.get("identity"), dict) else {}
            if str(identity.get("node_id") or "") == node_id:
                return entry
        return None


def _trusted_keys(values: list[str]) -> dict[str, Any]:
    authz = load_authz()
    keys: dict[str, Any] = {}
    for item in values:
        node_id, sep, path = item.partition("=")
        if not sep or not node_id or not path:
            raise SystemExit(f"uplift-intake: expected NODE_ID=PATH, got {item!r}")
        keys[node_id] = authz.load_public_key(Path(path))
    return keys


def _message_sha(method: str, path: str, body_sha: str, timestamp: str, nonce: str, node_id: str) -> bytes:
    return (
        b"sparknet-http/1\n"
        + method.upper().encode()
        + b"\n"
        + path.encode()
        + b"\n"
        + body_sha.encode()
        + b"\n"
        + timestamp.encode()
        + b"\n"
        + nonce.encode()
        + b"\n"
        + node_id.encode()
    )


class Intake:
    def __init__(self, *, state: Path, registry: Registry, keys: dict[str, Any], max_age: int = REPLAY_WINDOW) -> None:
        self.state = Path(state)
        self.registry = registry
        self.keys = dict(keys)
        self.max_age = max_age
        self.authz = load_authz()
        self.http = load_http()
        self.seen_nonces: OrderedDict[str, float] = OrderedDict()
        for sub in ("inventory", "snapshots", "traces", "kv", "manifests"):
            (self.state / sub).mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.state, 0o700)

    def _accept_nonce(self, nonce: str) -> None:
        now = time.time()
        while self.seen_nonces:
            oldest, seen = next(iter(self.seen_nonces.items()))
            if now - seen <= self.max_age:
                break
            self.seen_nonces.pop(oldest, None)
        if nonce in self.seen_nonces:
            raise Refusal(409, "replayed_nonce")
        self.seen_nonces[nonce] = now
        while len(self.seen_nonces) > 10000:
            self.seen_nonces.popitem(last=False)

    def authorize(self, *, source: str, node_id: str, timestamp: str, nonce: str) -> dict[str, Any]:
        if not isinstance(node_id, str) or not NODE_ID_RE.fullmatch(node_id):
            raise Refusal(403, "bad-node-id", "node_id must be a single safe identifier")
        self.registry.refresh()
        entry = self.registry.by_source(source)
        if entry is None:
            raise Refusal(403, "off_overlay", "source is not a registered peer")
        authz = load_authz()
        try:
            accepted = authz.accept_entry(
                entry,
                self.registry.master_key,
                now=_now(),
                required_capability="model-uplift",
            )
        except authz.RegistryEntryError as exc:
            if exc.code in (authz.REASON_REVOKED, authz.REASON_EXPIRED, authz.REASON_NOT_YET_VALID):
                raise Refusal(403, exc.code) from exc
            if exc.code == "capability_missing":
                raise Refusal(403, "capability_missing", "model-uplift is not granted") from exc
            if exc.code == authz.REASON_IDENTITY_MISMATCH:
                raise Refusal(403, "wrong_peer", "registry identity does not match its fingerprint") from exc
            if exc.code == authz.REASON_BAD_SIGNATURE:
                raise Refusal(403, "unsigned-entry", "registry entry signature does not verify") from exc
            raise Refusal(403, "malformed", "registry entry has malformed validity") from exc
        identity = accepted.identity
        if str(identity.get("node_id") or "") != node_id:
            raise Refusal(403, "wrong_peer", "signature key does not match the overlay source")
        key = self.keys.get(node_id)
        if key is None:
            raise Refusal(403, "no-key", "no pinned key for this node")
        try:
            issued = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError as exc:
            raise Refusal(401, "bad-timestamp") from exc
        if issued.tzinfo is None:
            issued = issued.replace(tzinfo=timezone.utc)
        age = (_now() - issued).total_seconds()
        if age < -5 or age > self.max_age:
            raise Refusal(401, "stale", f"request is {age:.0f}s outside the window")
        self._accept_nonce(nonce)
        return entry

    def verify_signature(
        self, *, method: str, path: str, body_sha: str, timestamp: str, node_id: str, nonce: str, signature: str
    ) -> None:
        key = self.keys.get(node_id)
        if key is None:
            raise Refusal(403, "no-key")
        if not self.authz.verify_signature(
            key, signature, _message_sha(method, path, body_sha, timestamp, nonce, node_id)
        ):
            raise Refusal(401, "bad-signature")

    def _write_jsonl(self, path: Path, rows: list[Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with path.open("a", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(path, 0o600)

    def _manifest(self, row: dict[str, Any]) -> None:
        self._write_jsonl(self.state / "manifests" / "uplift.jsonl", [row])

    def _qdrant(self, method: str, path: str, payload: dict[str, Any] | None = None) -> bool:
        """Best-effort mirror; storage on disk is authoritative for the intake."""
        base = (
            os.environ.get("SPARKNET_UPLIFT_QDRANT_URL", "").strip()
            or os.environ.get("SPARKNET_QDRANT_URL", "").strip()
        )
        if not base:
            return False
        key = os.environ.get("SPARKNET_QDRANT_API_KEY", "").strip()
        headers = {"Content-Type": "application/json"}
        if key:
            headers["api-key"] = key
        data = json.dumps(payload, sort_keys=True).encode() if payload is not None else None
        request = urllib.request.Request(base.rstrip("/") + path, data=data, method=method, headers=headers)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(request, timeout=5) as response:
                return 200 <= response.status < 300
        except (urllib.error.URLError, OSError, ValueError):
            return False

    def mirror_inventory(self, rows: list[dict[str, Any]]) -> int:
        self._qdrant("PUT", f"/collections/{QDRANT_COLLECTION}", {"vectors": {"size": 1, "distance": "Cosine"}})
        points = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            node = str(row.get("node_id") or "unknown")
            kind = str(row.get("kind") or "unknown")
            object_id = str(row.get("object_id") or "")
            if not object_id:
                continue
            points.append(
                {
                    "id": str(uuid.uuid5(INVENTORY_NAMESPACE, f"{node}:{kind}:{object_id}")),
                    "vector": [0.0],
                    "payload": row,
                }
            )
        mirrored = 0
        for start in range(0, len(points), 1000):
            if self._qdrant(
                "PUT", f"/collections/{QDRANT_COLLECTION}/points?wait=true", {"points": points[start : start + 1000]}
            ):
                mirrored += len(points[start : start + 1000])
        return mirrored

    def inventory(self, *, node_id: str, body: dict[str, Any], source: str) -> dict[str, Any]:
        rows = body.get("inventory")
        if not isinstance(rows, list) or len(rows) > 20000:
            raise Refusal(400, "malformed", "inventory must be a list of at most 20000 rows")
        self._write_jsonl(self.state / "inventory" / f"{node_id}.jsonl", rows)
        mirrored = self.mirror_inventory(rows)
        self._manifest(
            {
                "kind": "inventory",
                "node_id": node_id,
                "source": _bare(source),
                "rows": len(rows),
                "mirrored": mirrored,
                "received_at": _iso(),
            }
        )
        return {"ok": True, "rows": len(rows), "mirrored": mirrored}

    def trace_batch(self, *, node_id: str, body: dict[str, Any], source: str) -> dict[str, Any]:
        rows = body.get("traces")
        if not isinstance(rows, list) or len(rows) > 2000:
            raise Refusal(400, "malformed", "traces must be a list of at most 2000 rows")
        if not all(isinstance(row, dict) and row.get("consent") is True for row in rows):
            raise Refusal(403, "consent-missing", "every trace row must carry consent=true")
        digest = hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()
        path = self.state / "traces" / node_id / f"{int(time.time() * 1000)}-{digest[:16]}.jsonl"
        self._write_jsonl(path, rows)
        self._manifest(
            {
                "kind": "traces",
                "node_id": node_id,
                "source": _bare(source),
                "rows": len(rows),
                "sha256": digest,
                "received_at": _iso(),
            }
        )
        return {"ok": True, "rows": len(rows), "sha256": digest}

    def artifact(self, *, node_id: str, kind: str, body: bytes, headers: Any, source: str) -> dict[str, Any]:
        digest = hashlib.sha256(body).hexdigest()
        try:
            manifest = json.loads(
                base64.b64decode(headers.get("X-Sparknet-Manifest", ""), validate=True).decode("utf-8")
            )
        except Exception as exc:
            raise Refusal(400, "bad-manifest", str(exc)) from exc
        if not isinstance(manifest, dict) or manifest.get("sha256") != digest:
            raise Refusal(400, "digest-mismatch", "manifest sha256 does not match the body")
        collection = str(manifest.get("collection") or manifest.get("artifact_id") or "artifact")
        safe = "".join(c for c in collection if c.isalnum() or c in "-_")[:80] or "artifact"
        if kind == "snapshot":
            directory = self.state / "snapshots" / node_id / safe
            suffix = ".snapshot"
        elif kind == "student":
            directory = self.state / "student" / node_id
            suffix = ".gguf"
        else:
            directory = self.state / "kv" / node_id
            suffix = ".safetensors.gz" if str(manifest.get("compression", "gzip")) == "gzip" else ".safetensors.zst"
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        target = directory / f"{int(time.time() * 1000)}-{digest[:16]}{suffix}"
        fd, temporary = tempfile.mkstemp(prefix=".uplift-", dir=directory)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(body)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, target)
        finally:
            Path(temporary).unlink(missing_ok=True)
        self._manifest(
            {
                "kind": kind,
                "node_id": node_id,
                "source": _bare(source),
                "path": str(target),
                "sha256": digest,
                "size": len(body),
                "received_at": _iso(),
                **manifest,
            }
        )
        return {"ok": True, "sha256": digest, "path": str(target), "size": len(body)}


def _identity(intake: Intake, request: Any) -> tuple[str, str, str, str]:
    node_id = request.headers.get("X-Sparknet-Node-Id", "")
    timestamp = request.headers.get("X-Sparknet-Timestamp", "")
    signature = request.headers.get("X-Sparknet-Signature", "")
    nonce = request.headers.get("X-Sparknet-Nonce", "")
    if not (node_id and timestamp and signature and nonce):
        raise Refusal(401, "unsigned", "node id, timestamp, nonce and signature are required")
    intake.authorize(source=request.client[0], node_id=node_id, timestamp=timestamp, nonce=nonce)
    return node_id, timestamp, signature, nonce


def _authorize(intake: Intake, request: Any, node_id: str, timestamp: str, signature: str, nonce: str) -> None:
    intake.verify_signature(
        method=request.method,
        path=request.path,
        body_sha=hashlib.sha256(request.body).hexdigest(),
        timestamp=timestamp,
        node_id=node_id,
        nonce=nonce,
        signature=signature,
    )


def _inventory(intake: Intake, request: Any) -> Any:
    node_id, timestamp, signature, nonce = _identity(intake, request)
    _authorize(intake, request, node_id, timestamp, signature, nonce)
    if not isinstance(request.json, dict):
        raise Refusal(400, "malformed", "body is not a JSON object")
    return intake.inventory(node_id=node_id, body=request.json, source=request.client[0])


def _trace_batch(intake: Intake, request: Any) -> Any:
    node_id, timestamp, signature, nonce = _identity(intake, request)
    _authorize(intake, request, node_id, timestamp, signature, nonce)
    if not isinstance(request.json, dict):
        raise Refusal(400, "malformed", "body is not a JSON object")
    return intake.trace_batch(node_id=node_id, body=request.json, source=request.client[0])


def _artifact(intake: Intake, request: Any, kind: str) -> Any:
    node_id, timestamp, signature, nonce = _identity(intake, request)
    _authorize(intake, request, node_id, timestamp, signature, nonce)
    return intake.artifact(
        node_id=node_id, kind=kind, body=request.body, headers=request.headers, source=request.client[0]
    )


def _health(intake: Intake, request: Any = None) -> Any:
    http = load_http()
    return http.Response(200, {"ok": True, "service": "sparknet-uplift", "bind": intake.state.as_posix()})


def build_listener(intake: Intake, *, bind: str, port: int) -> Any:
    http = load_http()

    def refusal(exc: BaseException) -> tuple[int, dict[str, Any]]:
        return (
            getattr(exc, "status", 500),
            {"ok": False, "reason": getattr(exc, "reason", "internal"), "detail": getattr(exc, "detail", "")},
        )

    return http.listen(
        [
            http.Route("/v1/health", lambda request: _health(intake), method="GET", parse_json=False, max_body=0),
            http.Route(
                "/api/v1/inventory", lambda request: _inventory(intake, request), method="POST", max_body=MAX_JSON
            ),
            http.Route(
                "/api/v1/trace-batch", lambda request: _trace_batch(intake, request), method="POST", max_body=MAX_JSON
            ),
            http.Route(
                "/api/v1/vector-snapshot",
                lambda request: _artifact(intake, request, "snapshot"),
                method="POST",
                parse_json=False,
                max_body=MAX_ARTIFACT,
            ),
            http.Route(
                "/api/v1/kv-artifact",
                lambda request: _artifact(intake, request, "kv"),
                method="POST",
                parse_json=False,
                max_body=MAX_ARTIFACT,
            ),
            http.Route(
                "/api/v1/student-artifact",
                lambda request: _artifact(intake, request, "student"),
                method="POST",
                parse_json=False,
                max_body=MAX_STUDENT_ARTIFACT,
            ),
        ],
        name="uplift-intake",
        bind=bind,
        port=port,
        refusal=refusal,
        refusal_errors=(Refusal,),
    )


def serve(intake: Intake, *, bind: str, port: int) -> Any:
    return build_listener(intake, bind=bind, port=port)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sparknet Master uplift intake (8091; no key, no signer)")
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--bind", default=DEFAULT_BIND)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--trusted-key", action="append", default=[], help="NODE_ID=PATH")
    parser.add_argument("--check", action="store_true", help="validate the registry/keyring and exit")
    args = parser.parse_args(argv)
    try:
        registry = Registry(args.registry)
        keys = _trusted_keys(args.trusted_key)
        intake = Intake(state=args.state, registry=registry, keys=keys)
    except (OSError, ValueError, Refusal) as exc:
        print(f"sparknet-uplift-intake: {exc}", file=sys.stderr)
        return 2
    if args.check:
        print(f"uplift-intake: state={intake.state} nodes={len(registry.entries)} keys={len(keys)}")
        return 0
    if not args.serve:
        parser.print_help()
        return 0
    listener = serve(intake, bind=args.bind, port=args.port)
    print(f"uplift-intake: listening on {args.bind}:{args.port}; state={intake.state}", file=sys.stderr)
    try:
        listener.wait()
    except KeyboardInterrupt:
        listener.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
