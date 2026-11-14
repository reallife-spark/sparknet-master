#!/usr/bin/env python3
"""Master-signed resource directory for model and memory endpoints.

The directory is metadata only. It is signed by the isolated operational signer
through `sign-resource-directory`; it holds no key, vault content or authority.
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "shared"))
from sparknet_loader import load_by_path  # noqa: E402

HTTP = load_by_path("sparknet_resource_directory_http", ROOT / "shared" / "sparknet-http.py")
RESOURCE = load_by_path("sparknet_resource_directory_contract", ROOT / "shared" / "sparknet-resource-directory.py")
DEFAULT_SIGNER = Path.home() / ".local/state/sparknet/master-node/signer/signer.sock"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _signer(request: dict[str, Any], socket_path: Path) -> dict[str, Any]:
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(10)
    connection.connect(str(socket_path))
    connection.sendall((json.dumps(request, sort_keys=True) + "\n").encode())
    buffer = b""
    while not buffer.endswith(b"\n"):
        chunk = connection.recv(65536)
        if not chunk:
            break
        buffer += chunk
    connection.close()
    response = json.loads(buffer.decode())
    if not response.get("ok"):
        raise RuntimeError(str(response.get("error") or "signer refused"))
    return response


def build_directory(
    *, node_id: str, master: bool, nodes: list[dict[str, Any]], ttl_seconds: int = 300
) -> dict[str, Any]:
    now = _now()
    return {
        "directory_id": f"{node_id}-{int(now.timestamp())}",
        "issued_at": now.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "expires_at": (now + timedelta(seconds=ttl_seconds)).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "nodes": nodes,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="serve the Master-signed resource directory")
    parser.add_argument("--node-id", default="sparknet-node-0001")
    parser.add_argument("--bind", default="10.100.0.1")
    parser.add_argument("--port", type=int, default=8089)
    parser.add_argument("--signer-socket", type=Path, default=DEFAULT_SIGNER)
    parser.add_argument("--peer-overlay", default="10.100.0.2")
    parser.add_argument("--ttl", type=int, default=300)
    args = parser.parse_args(argv)
    nodes = [
        {
            "node_id": "sparknet-node-0001",
            "overlay_ipv4": "10.100.0.1",
            "models": {"qwen3-4b": "chat", "qwen3-embedding-0.6b": "embedding"},
            "memory": {"router": "10.100.0.1:4094", "scopes": ["fabric", "admin"]},
            "health": "ok",
        },
        {
            "node_id": "sparknet-node-0002",
            "overlay_ipv4": args.peer_overlay,
            "models": {
                "qwen3-30b": "chat",
                "qwen3-coder-30b-65k": "chat",
                "qwen3-vl-4b-65k": "chat",
                "qwen3-embedding-0.6b": "embedding",
            },
            "memory": {"router": f"{args.peer_overlay}:4094", "scopes": ["fabric", "admin"]},
            "health": "ok",
        },
    ]
    public_key = json.loads((ROOT / "master-node" / "manifests" / "node-authorizations.json").read_text())[
        "master_public_key_b64"
    ]
    cache: dict[str, Any] = {"expires_at": None, "payload": None}

    def payload() -> dict[str, Any]:
        current = cache["payload"]
        if isinstance(current, dict) and cache["expires_at"] is not None and _now() < cache["expires_at"]:
            return current
        unsigned = build_directory(node_id=args.node_id, master=True, nodes=nodes, ttl_seconds=args.ttl)
        root = _signer({"op": "root-id"}, args.signer_socket)
        signed = _signer(
            {"op": "sign-resource-directory", "root_id": root.get("root_id"), "directory": unsigned},
            args.signer_socket,
        )
        document = signed.get("resource_directory")
        if not isinstance(document, dict) or not RESOURCE.verify(
            document, public_key, HTTP._load_authz(ROOT / "shared")
        ):
            raise RuntimeError("resource-directory: signature did not verify")
        result = {"ok": True, "schema": "sparknet-resource-directory/1", "directory": document}
        cache["payload"] = result
        cache["expires_at"] = _now() + timedelta(seconds=args.ttl)
        return result

    listener = HTTP.listen(
        [
            HTTP.Route(
                "/v1/resources", lambda request: (200, payload()), "GET", auth="plain", source="overlay", parse_json=False
            )
        ],
        name="sparknet-resource-directory",
        bind=args.bind,
        port=args.port,
    )
    listener.wait()
    return 0


if __name__ == "__main__":
    main()
