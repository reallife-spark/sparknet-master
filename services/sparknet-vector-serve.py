#!/usr/bin/env python3
"""The 4223 vector store listener: signed, allow-listed retrieval only.

The index itself is derived state built by ``scripts/sparknet-vector.py``. This
service adds no second chunker, embedder or corpus rule: it loads that script by
path, opens the stamped collection and answers a signed query. Two collections
are served:

- ``sparknet-fabric`` — the existing fabric allow-list;
- ``sparknet-shared`` — markdown payloads an accepted share staged under
  ``01_Inbox/share-*`` (privacy model A: explicit share only).

A query is refused with 503 when qdrant-client is absent, the index is missing, or
the collection stamp does not match. It never returns an empty result set to
hide a broken index. The service holds no key and cannot reach the signer.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import threading
import urllib.parse
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "shared"))
from sparknet_loader import load_by_path

ROLE_ROOT = Path(__file__).resolve().parent.parent
FABRIC_ROOT = ROLE_ROOT.parent
DEFAULT_REGISTRY = ROLE_ROOT / "manifests" / "node-authorizations.json"
DEFAULT_STATE = (
    Path(os.environ.get("XDG_STATE_HOME", "").strip() or Path.home() / ".local" / "state")
    / "sparknet"
    / "master-node"
    / "vector"
)


def _load(name: str, path: Path) -> Any:
    if name in sys.modules:
        return sys.modules[name]
    if not path.is_file():
        raise FileNotFoundError(path)
    return load_by_path(name, path)


def _shared_dir() -> Path:
    explicit = os.environ.get("SPARKNET_SHARED_DIR", "").strip()
    if explicit:
        return Path(explicit)
    for candidate in (ROLE_ROOT / "shared", FABRIC_ROOT / "shared"):
        if (candidate / "sparknet-http.py").is_file():
            return candidate
    return FABRIC_ROOT / "shared"


def _load_http() -> Any:
    return _load("sparknet_http_vector", _shared_dir() / "sparknet-http.py")


def _load_vector() -> Any:
    explicit = os.environ.get("SPARKNET_VECTOR_SCRIPT", "").strip()
    path = Path(explicit) if explicit else FABRIC_ROOT / "scripts" / "sparknet-vector.py"
    return _load("sparknet_vector_service", path)


class VectorError(Exception):
    def __init__(self, status: int, reason: str, detail: str = "") -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason
        self.detail = detail


class VectorStore:
    def __init__(
        self,
        *,
        fabric_vault: Path,
        shared_vault: Path,
        state_root: Path,
        registry_path: Path,
        trusted_keys: dict[str, Any],
        authz: Any,
        vector: Any | None = None,
    ):
        self.fabric_vault = Path(fabric_vault)
        self.shared_vault = Path(shared_vault)
        self.state_root = Path(state_root)
        self.registry_path = Path(registry_path)
        self.trusted_keys = dict(trusted_keys)
        self.authz = authz
        self.vector = vector or _load_vector()

    def _collection(self, name: str):
        if name not in ("fabric", "shared"):
            raise VectorError(400, "unknown-collection", "collection must be fabric or shared")
        vault = self.fabric_vault if name == "fabric" else self.shared_vault
        data = self.state_root / name
        try:
            return self.vector.open_checked(name, vault, data)
        except SystemExit as exc:
            raise VectorError(503, "index-unavailable", "index missing, stale or qdrant-client absent") from exc
        except Exception as exc:
            raise VectorError(503, "index-unavailable", str(exc)) from exc

    def query(self, collection: str, query: str, top_k: int) -> list[dict[str, Any]]:
        if not query.strip() or len(query) > 4096:
            raise VectorError(400, "bad-query", "query must be non-empty and at most 4096 characters")
        if not isinstance(top_k, int) or isinstance(top_k, bool) or not 1 <= top_k <= 20:
            raise VectorError(400, "bad-top-k", "top_k must be an integer from 1 to 20")
        opened = self._collection(collection)
        data = self.state_root / collection
        try:
            candidates = self.vector.query_candidates(collection, data, opened, query, top_k)
        except SystemExit as exc:
            raise VectorError(503, "index-unavailable", "query refused by the index stamp") from exc
        return [
            {
                "id": candidate.get("id"),
                "path": candidate.get("path"),
                "snippet": " ".join(str(candidate.get("document", "")).split())[:300],
                "distance": candidate.get("distance"),
            }
            for candidate in candidates
        ]

    def document(self, collection: str, doc_id: str) -> str:
        opened = self._collection(collection)
        try:
            rows = opened.get([doc_id])
        except Exception as exc:
            raise VectorError(404, "unknown-doc", str(exc)) from exc
        if not rows:
            raise VectorError(404, "unknown-doc", doc_id)
        row = rows[0] if isinstance(rows[0], dict) else {}
        document = row.get("document")
        if not document:
            raise VectorError(404, "unknown-doc", doc_id)
        return str(document)

    def _master_key(self) -> Any:
        registry = self._registry()
        encoded = registry.get("master_public_key_b64")
        if not isinstance(encoded, str) or not encoded:
            raise VectorError(503, "registry-invalid", "registry has no master_public_key_b64")
        return self.authz.public_key_from_b64(encoded)

    def _registry(self) -> dict[str, Any]:
        try:
            document = json.loads(self.registry_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise VectorError(503, "registry-unavailable", str(exc)) from exc
        if not isinstance(document, dict):
            raise VectorError(503, "registry-invalid", "registry is not an object")
        return document

    def authorize(self, node_id: str) -> None:
        registry = self._registry()
        entry = next(
            (
                candidate
                for candidate in registry.get("authorizations") or []
                if isinstance(candidate, dict)
                and str((candidate.get("identity") or {}).get("node_id") or "") == node_id
            ),
            None,
        )
        if entry is None:
            raise VectorError(403, "unauthorized", "caller is not in the registry")
        try:
            decision = self.authz.evaluate(entry.get("identity") or {}, registry, self._master_key())
        except Exception as exc:
            raise VectorError(403, "unauthorized", str(exc)) from exc
        capabilities = list(decision.capabilities) if decision.allowed else []
        if not {"cluster-dispatch", "cluster-serve"} & set(capabilities):
            raise VectorError(403, "no-capability", "caller needs cluster-dispatch or cluster-serve")
        if node_id not in self.trusted_keys:
            raise VectorError(403, "no-key", "caller has no trusted transport key")

    def reindex(self, collection: str) -> None:
        if collection not in ("fabric", "shared"):
            raise VectorError(400, "unknown-collection", "collection must be fabric or shared")
        vault = self.fabric_vault if collection == "fabric" else self.shared_vault
        data = self.state_root / collection
        try:
            self.vector.cmd_index(collection, vault, data)
        except SystemExit as exc:
            raise VectorError(503, "reindex-failed", "index build refused") from exc


def router_for(store: VectorStore):
    def router(method: str, path: str, body: dict[str, Any], identity: dict[str, Any]):
        caller = str(identity.get("verified_key_id") or "")
        if path == "/v1/health":
            try:
                store.authorize(caller)
                store._collection("fabric")
                store._collection("shared")
            except VectorError as exc:
                return exc.status, {"ok": False, "reason": exc.reason, "detail": exc.detail}
            return 200, {"ok": True, "collections": ["fabric", "shared"]}
        if path.startswith("/admin/"):
            try:
                store.authorize(caller)
                store.reindex(str(body.get("collection") or "fabric"))
            except VectorError as exc:
                return exc.status, {"ok": False, "reason": exc.reason, "detail": exc.detail}
            return 200, {"ok": True, "collection": body.get("collection") or "fabric"}
        try:
            store.authorize(caller)
            if method == "POST" and path == "/v1/query":
                hits = store.query(
                    str(body.get("collection") or "fabric"),
                    str(body.get("query") or ""),
                    body.get("top_k", 5),
                )
                return 200, {"ok": True, "hits": hits}
            if method == "GET" and path.startswith("/v1/doc/"):
                doc_id = urllib.parse.unquote(path[len("/v1/doc/") :])
                return 200, {"ok": True, "document": store.document(str(body.get("collection") or "fabric"), doc_id)}
        except VectorError as exc:
            return exc.status, {"ok": False, "reason": exc.reason, "detail": exc.detail}
        return 404, {"ok": False, "reason": "not-found"}

    return router


def _load_keyring(values: list[str], authz: Any) -> dict[str, Any]:
    keyring: dict[str, Any] = {}
    for item in values:
        node_id, separator, path = item.partition("=")
        if not separator or not node_id or not path:
            raise VectorError(400, "bad-key", f"expected NODE_ID=PATH, got {item!r}")
        keyring[node_id] = authz.load_public_key(Path(path))
    if not keyring:
        raise VectorError(500, "no-verifier", "at least one --trusted-key is required")
    return keyring


def _serve(http: Any, router: Any, *, bind: str, port: int, keyring: dict[str, Any]) -> None:
    listener = http.listen(
        [
            http.Route(
                "/",
                lambda request: router(request.method, request.path, request.json or {}, request.identity),
                auth="signed",
                prefix=True,
            )
        ],
        name="vector-serve",
        bind=bind,
        port=port,
        public_keys=keyring,
        loopback_only_routes=("/admin",),
    )
    listener.start()
    stopping = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopping.set())
    signal.signal(signal.SIGINT, lambda *_: stopping.set())
    print(f"sparknet-vector-serve: 4223 on {bind}:{port} (fabric, shared)", flush=True)
    try:
        while not stopping.wait(1.0):
            pass
    finally:
        listener.stop()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="signed 4223 vector store listener")
    parser.add_argument("--fabric-vault", type=Path, default=FABRIC_ROOT)
    parser.add_argument("--shared-vault", type=Path, default=ROLE_ROOT)
    parser.add_argument("--state-root", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4223)
    parser.add_argument("--trusted-key", action="append", default=[], metavar="NODE_ID=PATH")
    args = parser.parse_args(argv)
    try:
        http = _load_http()
        authz = http._load_authz()
        store = VectorStore(
            fabric_vault=args.fabric_vault,
            shared_vault=args.shared_vault,
            state_root=args.state_root,
            registry_path=args.registry,
            trusted_keys=_load_keyring(args.trusted_key, authz),
            authz=authz,
        )
    except (OSError, ValueError, VectorError) as exc:
        print(f"sparknet-vector-serve: {exc}", file=sys.stderr)
        return 2
    _serve(http, router_for(store), bind=args.bind, port=args.port, keyring=store.trusted_keys)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
