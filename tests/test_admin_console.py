"""The Master admin console (fabric Step 29 phase 3: the operator's seat).

The console composes an admin-request, has the isolated signer sign it, and posts
it to a peer's `/admin/*` route. These tests prove each link without a real
signer, a real peer or a real WebUI:

* composition projects exactly the shared field set and is canonicalisable by the
  one implementation, so the console cannot invent a request the peer refuses;
* the entity requirements the console checks against equal the peer bridge's,
  asserted against the peer's own source so the two cannot drift;
* the signer protocol round-trips over a real unix socket, and the signature the
  fake signer produces verifies against the shared verifier (same code the real
  signer runs);
* dispatch posts the signed envelope to the right route and hands a peer's 4xx
  answer through verbatim instead of reparsing it;
* the feed merges and de-duplicates across nodes, and KDE push is a no-op when
  there is no KDE Connect to push to.
"""

from __future__ import annotations

import importlib.util
import json
import socket
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROLE_ROOT = Path(__file__).resolve().parent.parent
FABRIC_ROOT = ROLE_ROOT.parent
SHARED_DIR = FABRIC_ROOT / "shared"
NOW = datetime(2026, 10, 7, 12, 0, 0, tzinfo=timezone.utc)


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        pytest.skip(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


authz = _load("sparknet_authz_console_test", SHARED_DIR / "sparknet-authz.py")
console = _load("sparknet-admin-console", ROLE_ROOT / "services" / "sparknet-admin-console.py")


# --- fakes --------------------------------------------------------------------


class FakeSigner:
    """A real unix-socket server that signs with the same authz code the signer uses.

    This is not a mock of the signer's transport only: it derives the canonical
    bytes with ``authz.admin_request_message`` and signs with ``authz.sign_bytes``,
    the exact calls ``Signer._sign_admin_request`` makes. So a request that comes
    back from it verifies against the shared verifier, which is the property the
    console actually depends on.
    """

    def __init__(self, tmp_path: Path, private_key: Ed25519PrivateKey):
        self.private_key = private_key
        self.requests: list[dict[str, Any]] = []
        self.socket_path = tmp_path / "signer.sock"
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(str(self.socket_path))
        self._server.listen(5)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while True:
            try:
                connection, _ = self._server.accept()
            except OSError:
                return
            try:
                self._handle(connection)
            finally:
                connection.close()

    def _handle(self, connection: socket.socket) -> None:
        data = b""
        while not data.endswith(b"\n"):
            chunk = connection.recv(4096)
            if not chunk:
                break
            data += chunk
        request = json.loads(data.decode("utf-8"))
        self.requests.append(request)
        if request["op"] == "root-id":
            response = {"ok": True, "root_id": "root-0001", "node_id": "master-0001"}
        elif request["op"] == "sign-admin-request":
            unsigned = {k: v for k, v in request["request"].items() if k != "signature_b64"}
            message = authz.admin_request_message(unsigned)
            signature = authz.sign_bytes(self.private_key, message)
            response = {"ok": True, "admin_request": {**unsigned, "signature_b64": signature}}
        else:
            response = {"ok": False, "error": f"unknown op {request['op']!r}"}
        connection.sendall(json.dumps(response).encode("utf-8") + b"\n")

    def close(self) -> None:
        self._server.close()


class FakeBridge:
    """A loopback HTTP peer that verifies the Master signature before answering."""

    def __init__(self, public_key, *, status: int = 200, body: dict | None = None):
        self.public_key = public_key
        self.status = status
        self.body = body
        self.calls: list[tuple[str, str, dict]] = []
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def _handler(self):
        bridge = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):  # silence the test output
                return

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length)
                payload = json.loads(raw.decode("utf-8"))
                bridge.calls.append(("POST", self.path, payload))
                signature = payload.get("signature_b64", "")
                assert authz.verify_signature(bridge.public_key, signature, authz.admin_request_message(payload)), (
                    "the peer must only ever receive a validly signed request"
                )
                out = json.dumps(bridge.body if bridge.body is not None else {"ok": True}).encode()
                self.send_response(bridge.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

        return Handler

    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


@pytest.fixture
def master_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def signer(tmp_path: Path, master_key: Ed25519PrivateKey) -> FakeSigner:
    fake = FakeSigner(tmp_path, master_key)
    try:
        yield fake
    finally:
        fake.close()


def _entries(fingerprint: str = "f" * 64, node_id: str = "peer-1", ip: str = "10.100.0.2/32") -> list[dict]:
    return [{"fingerprint": fingerprint, "identity": {"node_id": node_id, "overlay_ipv4": ip}}]


# --- composition --------------------------------------------------------------


def test_compose_projects_the_shared_field_set():
    request = console.compose_request(
        authz,
        action="set_user_role",
        master_node_id="master-0001",
        target_node_id="peer-1",
        target_fingerprint="f" * 64,
        entity={"user_id": "u1", "role": "admin"},
        clock=lambda: NOW,
        request_id="rid-1",
        nonce="nonce-1",
    )
    assert set(request) == set(authz.ADMIN_REQUEST_FIELDS), (
        "the console must project exactly the fields the signer signs"
    )
    assert authz.admin_request_message(request)  # canonicalisable is the contract


def test_compose_refuses_an_unknown_action():
    with pytest.raises(console.ConsoleError, match="unknown action"):
        console.compose_request(
            authz,
            action="root-everything",
            master_node_id="m",
            target_node_id="p",
            target_fingerprint="x",
        )


def test_compose_refuses_a_missing_entity_field():
    with pytest.raises(console.ConsoleError, match="requires role"):
        console.compose_request(
            authz,
            action="set_user_role",
            master_node_id="m",
            target_node_id="p",
            target_fingerprint="x",
            entity={"user_id": "u1"},
        )


def test_entity_requirements_match_the_peer_bridge():
    """The console's per-action entity check must equal the peer's enforcement.

    Two copies of "what does set_user_role need" is exactly how the console would
    start sending requests the peer refuses. Assert against the peer's own source.
    """
    bridge = _load(
        "sparknet_dispatch_bridge_console_test",
        FABRIC_ROOT / "peer-node" / "services" / "sparknet-dispatch-bridge.py",
    )
    assert {action: tuple(fields) for action, fields in bridge.ADMIN_ENTITY_FIELDS.items()} == console.REQUIRED_ENTITY
    assert set(console.REQUIRED_ENTITY) == set(authz.ADMIN_REQUEST_ACTIONS), (
        "a shared action must have a console entity rule, and vice versa"
    )


# --- signer protocol ----------------------------------------------------------


def test_signer_client_round_trips_root_id_and_sign(signer: FakeSigner, master_key: Ed25519PrivateKey):
    client = console.SignerClient(signer.socket_path)
    request = console.compose_request(
        authz,
        action="list_users",
        master_node_id="master-0001",
        target_node_id="peer-1",
        target_fingerprint="f" * 64,
        clock=lambda: NOW,
    )
    signed = client.sign(request)
    assert signed["signature_b64"]
    assert authz.verify_signature(
        master_key.public_key(), signed["signature_b64"], authz.admin_request_message(signed)
    ), "the signature the console obtained must verify against the shared verifier"
    assert [r["op"] for r in signer.requests] == ["root-id", "sign-admin-request"]


def test_signer_client_refuses_a_missing_socket(tmp_path: Path):
    client = console.SignerClient(tmp_path / "nope.sock")
    with pytest.raises(console.ConsoleError, match="does not exist"):
        client.root_id()


# --- dispatch -----------------------------------------------------------------


def test_send_signs_and_dispatches_end_to_end(
    signer: FakeSigner, master_key: Ed25519PrivateKey, monkeypatch: pytest.MonkeyPatch
):
    bridge = FakeBridge(master_key.public_key(), body={"ok": True, "result": {"users": []}})
    try:
        monkeypatch.setattr(console, "bridge_url", lambda ip, port=console.BACKING_PORT: bridge.base())
        con = console.Console(
            master_node_id="master-0001",
            authz=authz,
            client=console.SignerClient(signer.socket_path),
            registry=None,
        )
        con._entries = _entries()
        result = con.send("list_users", spec="peer-1")
        assert result["ok"] is True and result["status"] == 200
        assert bridge.calls and bridge.calls[0][0] == "POST"
        assert bridge.calls[0][1] == "/admin/list_users"
    finally:
        bridge.close()


def test_dispatch_hands_a_webui_refusal_through(master_key: Ed25519PrivateKey):
    refusal = {"ok": False, "reason": "webui-refused", "webui_status": 403}
    target = console.Target(node_id="peer-1", fingerprint="f" * 64, url="http://127.0.0.1:1")
    signed = {"action": "list_users", "signature_b64": "x"}
    with pytest.raises(console.ConsoleError):
        console.dispatch(target, "list_users", signed, timeout=0.5)
    # A reachable peer that refuses is a result, not an error:
    bridge = FakeBridge(master_key.public_key(), status=403, body=refusal)
    try:
        target = console.Target(node_id="peer-1", fingerprint="f" * 64, url=bridge.base())
        signed = {
            "request_id": "r",
            "master_node_id": "m",
            "target_node_id": "peer-1",
            "target_fingerprint": "f" * 64,
            "issued_at": NOW.isoformat(),
            "expires_at": NOW.isoformat(),
            "nonce": "n",
            "action": "list_users",
        }
        signed["signature_b64"] = authz.sign_bytes(master_key, authz.admin_request_message(signed))
        result = console.dispatch(target, "list_users", signed)
        assert result["ok"] is False and result["status"] == 403
        assert result["payload"] == refusal
    finally:
        bridge.close()


# --- target resolution --------------------------------------------------------


def test_resolve_target_builds_the_overlay_url():
    target = console.resolve_target("peer-1", _entries())
    assert target.node_id == "peer-1"
    assert target.url == "http://10.100.0.2:4096", "the /32 must be stripped"


def test_resolve_target_by_fingerprint():
    target = console.resolve_target("f" * 64, _entries())
    assert target.node_id == "peer-1"


def test_resolve_target_takes_a_bare_url_as_given():
    target = console.resolve_target("http://10.100.0.9:4096", [])
    assert target.url == "http://10.100.0.9:4096"
    assert target.node_id is None


def test_resolve_target_refuses_an_unknown_node():
    with pytest.raises(console.ConsoleError, match="no registry entry"):
        console.resolve_target("peer-ghost", _entries())


def test_load_registry_requires_an_authorizations_list(tmp_path: Path):
    path = tmp_path / "reg.json"
    path.write_text(json.dumps({"schema_version": "1.0"}))
    with pytest.raises(console.ConsoleError, match="authorizations"):
        console.load_registry(path)


# --- the feed -----------------------------------------------------------------


def _console_with_send(payloads: dict[str, dict]) -> console.Console:
    con = console.Console(master_node_id="master-0001", authz=authz, registry=None)

    def fake_send(action: str, *, spec: str, entity=None):
        return {"ok": True, "status": 200, "payload": payloads[spec]}

    con.send = fake_send  # type: ignore[method-assign]
    return con


def test_feed_merges_and_dedupes_across_nodes():
    payloads = {
        "peer-1": {
            "node": "peer-1",
            "events": [
                {"event": "auth.login", "ts": "2026-10-07T10:00:00Z", "actor": "ana"},
                {"event": "auth.signup", "ts": "2026-10-07T09:00:00Z", "actor": "bob"},
            ],
        },
        "peer-2": {
            "node": "peer-2",
            "events": [
                {"event": "auth.login", "ts": "2026-10-07T11:00:00Z", "actor": "ana"},
            ],
        },
    }
    events = _console_with_send(payloads).feed(["peer-1", "peer-2"])
    assert [e["ts"] for e in events] == ["2026-10-07T09:00:00Z", "2026-10-07T10:00:00Z", "2026-10-07T11:00:00Z"], (
        "the feed must be time-ordered across nodes"
    )
    assert {e["node"] for e in events} == {"peer-1", "peer-2"}


def test_feed_dedupes_a_repeated_record():
    repeated = {"event": "auth.login", "ts": "2026-10-07T10:00:00Z", "actor": "ana"}
    payloads = {
        "peer-1": {"node": "peer-1", "events": [repeated, dict(repeated)]},
    }
    events = _console_with_send(payloads).feed(["peer-1"])
    assert len(events) == 1, "an append-only spool re-read must not double an event"


# --- KDE push -----------------------------------------------------------------


def test_kde_devices_from_env_parses():
    assert console.kde_devices_from_env({"SPARKNET_KDE_DEVICES": "a, b ,c"}) == ["a", "b", "c"]
    assert console.kde_devices_from_env({}) == []


def test_notify_kde_builds_the_plugin_command():
    ran: list[list[str]] = []

    def run(cmd, **kwargs):
        ran.append(cmd)

        class Result:
            returncode = 0
            stdout = ""

        return Result()

    ok = console.notify_kde("3 admin event(s)", devices=["dev-1"], which=lambda n: "/usr/bin/" + n, run=run)
    assert ok is True
    assert ran == [["kdeconnect-cli", "-d", "dev-1", "--ping-msg", "sparknet: 3 admin event(s)"]]


def test_notify_kde_is_a_noop_without_the_binary():
    assert console.notify_kde("x", which=lambda n: None, run=lambda *a, **k: None) is False


# --- CLI surface --------------------------------------------------------------


def test_cli_dry_run_composes_without_signing(capsys: pytest.CaptureFixture):
    rc = console.main(
        [
            "role",
            "peer-1",
            "u1",
            "admin",
            "--master-node-id",
            "master-0001",
            "--dry-run",
            "--json",
            "--registry",
            "/nonexistent/registry.json",
        ]
    )
    # The registry is only needed to resolve the target, which dry-run still does.
    assert rc == 1
    assert "registry" in capsys.readouterr().err


def test_cli_requires_a_master_node_id(capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("SPARKNET_NODE_ID", raising=False)
    rc = console.main(["users", "peer-1"])
    assert rc == 1
    assert "--master-node-id" in capsys.readouterr().err


def test_main_maps_positional_entity_without_the_target(monkeypatch: pytest.MonkeyPatch):
    """`approve <node> <user_id>` must send the user id, never the node spec.

    The target names the node; it is not an entity field. Sending it as
    `user_id` made the peer refuse every user_id action as an unknown user
    (found live 2026-10-12).
    """
    seen: dict[str, Any] = {}

    def fake_send(self, action, *, spec, entity=None):
        seen.update(action=action, spec=spec, entity=entity)
        return {"ok": True}

    monkeypatch.setattr(console.Console, "send", fake_send)

    rc = console.main(["approve", "peer-1", "u1", "--master-node-id", "m1", "--registry", "reg.json"])
    assert rc == 0
    assert seen == {"action": "approve_user", "spec": "peer-1", "entity": {"user_id": "u1"}}

    rc = console.main(["role", "peer-2", "u9", "admin", "--master-node-id", "m1", "--registry", "reg.json"])
    assert rc == 0
    assert seen == {
        "action": "set_user_role",
        "spec": "peer-2",
        "entity": {"user_id": "u9", "role": "admin"},
    }
