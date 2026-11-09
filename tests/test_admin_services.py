"""4221 file share and 4222 NAT status: read-only by construction."""

from __future__ import annotations

import importlib.util
import json
import socket
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROLE_ROOT = Path(__file__).resolve().parent.parent
SHARED = ROLE_ROOT.parent / "shared"
NOW = datetime(2026, 10, 31, 12, 0, tzinfo=timezone.utc)


def _load(name: str, path: Path):
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def authz():
    return _load("admin_services_authz", SHARED / "sparknet-authz.py")


@pytest.fixture(scope="module")
def files():
    return _load("admin_services_files", ROLE_ROOT / "services" / "sparknet-file-share.py")


@pytest.fixture(scope="module")
def nat():
    return _load("admin_services_nat", ROLE_ROOT / "services" / "sparknet-nat-status.py")


def _registry(tmp_path: Path, authz, capabilities: list[str]) -> Path:
    master = Ed25519PrivateKey.generate()
    identity = {
        "node_id": "peer-1",
        "role": "peer",
        "wireguard_public_key_b64": "a2V5",
        "overlay_ipv4": "10.100.0.2/32",
        "requested_capabilities": capabilities,
    }
    entry = authz.sign_authorization(identity, master, capabilities, ttl_days=3650, now=NOW)
    path = tmp_path / "registry.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "master_public_key_b64": authz.public_key_b64(master.public_key()),
                "authorizations": [entry],
            }
        )
    )
    return path


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def _wire(http, module, router, key):
    port = _free_port()
    server = http.serve(router, bind="127.0.0.1", port=port, public_keys={"peer-1": key.public_key()})
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    thread.start()
    return server, thread, f"http://127.0.0.1:{port}"


def test_file_share_lists_and_fetches_but_never_writes(files, authz, tmp_path: Path):
    http = _load("admin_services_http_file", SHARED / "sparknet-http.py")
    root = tmp_path / "share"
    (root / "sub").mkdir(parents=True)
    (root / "a.txt").write_text("alpha")
    (root / "sub" / "b.md").write_text("beta")
    (tmp_path / "outside.txt").write_text("outside")
    (root / "link").symlink_to(tmp_path / "outside.txt")
    key = Ed25519PrivateKey.generate()
    share = files.FileShare(root, _registry(tmp_path, authz, ["p2p-sync"]), {"peer-1": key.public_key()}, authz)
    server, thread, base = _wire(http, files, files.router_for(share), key)
    try:
        status, body = http.post_json(base, "GET", "/v1/files", {}, key)
        assert status == 200
        assert [item["path"] for item in body["files"]] == ["a.txt", "sub/b.md"]

        status, body = http.post_json(base, "GET", "/v1/file/sub%2Fb.md", {}, key)
        assert status == 200
        assert body["sha256"] and body["content_b64"]

        status, body = http.post_json(base, "GET", "/v1/file/..%2Fetc%2Fpasswd", {}, key)
        assert status == 400 and body["reason"] == "unsafe-path"
        status, body = http.post_json(base, "GET", "/v1/file/link", {}, key)
        assert status == 400 and body["reason"] == "unsafe-path"
        status, _ = http.post_json(base, "POST", "/v1/files", {}, key)
        assert status == 404
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_nat_status_and_dry_run_are_read_only(nat, authz, tmp_path: Path):
    http = _load("admin_services_http_nat", SHARED / "sparknet-http.py")
    key = Ed25519PrivateKey.generate()
    status = nat.NatStatus(_registry(tmp_path, authz, ["admin-supervise"]), {"peer-1": key.public_key()}, authz)
    status._run = lambda command: {"ok": True, "exit": 0, "stdout": " ".join(command), "stderr": ""}
    server, thread, base = _wire(http, nat, nat.router_for(status), key)
    try:
        status_code, body = http.post_json(base, "GET", "/v1/status", {}, key)
        assert status_code == 200 and body["ok"]
        assert set(body["status"]) == set(nat.READ_COMMANDS)
        status_code, body = http.post_json(base, "POST", "/v1/dry-run", {"proposal": {"peer": "peer-1"}}, key)
        assert status_code == 200 and body["dry_run"] and body["changes"] == []
        status_code, _ = http.post_json(base, "POST", "/v1/apply", {}, key)
        assert status_code == 404
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_nat_command_table_contains_no_writer(files, nat):
    source = (ROLE_ROOT / "services" / "sparknet-nat-status.py").read_text()
    assert "shell=True" not in source
    for command in nat.READ_COMMANDS.values():
        assert command[0] in {"wg", "ip", "sysctl", "iptables"}
        assert not any(token in command for token in ("-A", "-I", "-D", "flush", "add", "del", "set", "up", "down"))
    assert "-A" not in source and "-I" not in source and "-D" not in source
    assert "iptables" in source and "nat" in source
    files_source = (ROLE_ROOT / "services" / "sparknet-file-share.py").read_text()
    assert "write_text" not in files_source and "write_bytes" not in files_source
