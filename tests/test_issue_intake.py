"""The signed issue route: real socket, real signature, real store.

The route is the peer half's counterpart. These tests prove acceptance, the
capability gate, replay refusal, digest refusal, redaction refusal and the
key/node binding, not just that the source file contains a string.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType

from sparknet_loader import load_by_path

ROLE_ROOT = Path(__file__).resolve().parent.parent
FABRIC_ROOT = ROLE_ROOT.parent
INTAKE_PATH = ROLE_ROOT / "services" / "sparknet-peer-intake.py"
HTTP_PATH = FABRIC_ROOT / "shared" / "sparknet-http.py"
ISSUE_ROUTE = "/api/v1/issues"
PEER_FP = "a" * 64
PEER_NODE = "sparknet-node-0002"


def _load(name: str, path: Path) -> ModuleType:
    return load_by_path(name, path)


intake = _load("sparknet_issue_intake_test", INTAKE_PATH)
authz = intake.authz
http = _load("sparknet_issue_http_test", HTTP_PATH)


def _directory(*, capability: bool = True) -> intake.PeerDirectory:
    now = datetime.now(timezone.utc)
    return intake.PeerDirectory(
        [
            {
                "fingerprint": PEER_FP,
                "overlay_ipv4": "127.0.0.1/32",
                "capabilities": ["issue-report"] if capability else ["telemetry"],
                "revoked": False,
                "issued_at": (now - timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
                "expires_at": (now + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
                "identity": {"node_id": PEER_NODE},
            }
        ]
    )


def _keys(tmp_path: Path) -> tuple[Path, object, object]:
    private_b64, public_b64 = authz.generate_keypair()
    private_path = tmp_path / "node-private.b64"
    public_path = tmp_path / "node-public.b64"
    private_path.write_text(private_b64)
    public_path.write_text(public_b64)
    return private_path, authz.load_private_key(private_path), authz.load_public_key(public_path)


def _payload(**overrides) -> dict:
    values = {
        "issue_id": "fix-console-token",
        "node_id": PEER_NODE,
        "peer_fingerprint": PEER_FP,
        "title": "Console rejects a valid token",
        "body": "The token is valid but the console returns 401.",
        "status": "open",
        "labels": ["needs-triage"],
        "links": [{"kind": "file", "ref": "scripts/sparknet-console.py"}],
        "source": ".",
    }
    values.update(overrides)
    return authz.build_issue_report(**values)


def _server(tmp_path: Path, *, capability: bool = True, key: object | None = None):
    store = intake.IssueStore(tmp_path / "issues.jsonl", state_dir=tmp_path / "state")
    listener = intake.build_listener(
        bind="127.0.0.1",
        port=0,
        directory=_directory(capability=capability),
        spool=tmp_path / "telemetry.jsonl",
        request_dir=tmp_path / "requests",
        issue_keys={PEER_NODE: key} if key is not None else {},
        issue_store=store,
    )
    listener.start()
    return listener, listener, store, f"http://127.0.0.1:{listener.servers[0].server_address[1]}"


def _post(base: str, payload: dict, private: object) -> tuple[int, dict]:
    return http.post_json(base, "POST", ISSUE_ROUTE, payload, private, timeout=5)


def test_a_signed_issue_is_recorded(tmp_path: Path) -> None:
    _, private, public = _keys(tmp_path)
    server, thread, store, base = _server(tmp_path, key=public)
    try:
        status, body = _post(base, _payload(), private)
        assert status == 200, body
        assert body["status"] == "recorded" and body["issue_id"] == "fix-console-token"
        rows = [json.loads(line) for line in (tmp_path / "issues.jsonl").read_text().splitlines() if line.strip()]
        assert len(rows) == 1
        assert rows[0]["node_id"] == PEER_NODE
        assert rows[0]["received_from"] == "127.0.0.1"
        assert rows[0]["source"] == "."
        assert store.listing()[0]["issue_id"] == "fix-console-token"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_capability_missing_is_refused_before_the_body(tmp_path: Path) -> None:
    _, private, public = _keys(tmp_path)
    server, thread, _, base = _server(tmp_path, capability=False, key=public)
    try:
        status, body = _post(base, _payload(), private)
        assert status == 403 and body["error"] == "capability_missing"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_replay_is_refused(tmp_path: Path) -> None:
    _, private, public = _keys(tmp_path)
    server, thread, _, base = _server(tmp_path, key=public)
    try:
        payload = _payload()
        assert _post(base, payload, private)[0] == 200
        status, body = _post(base, payload, private)
        assert status == 409 and body["error"] == "replayed_nonce"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_a_wrong_key_is_refused(tmp_path: Path) -> None:
    _, private, _ = _keys(tmp_path)
    _, _, other_public = _keys(tmp_path)
    server, thread, _, base = _server(tmp_path, key=other_public)
    try:
        status, body = _post(base, _payload(), private)
        assert status == 401 and body["error"] == "bad_signature"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_digest_mismatch_is_refused(tmp_path: Path) -> None:
    _, private, public = _keys(tmp_path)
    server, thread, _, base = _server(tmp_path, key=public)
    try:
        payload = _payload()
        payload["body"] = "changed after the digest"
        status, body = _post(base, payload, private)
        assert status == 400 and body["error"] == "digest_mismatch"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_secret_shaped_body_is_refused(tmp_path: Path) -> None:
    _, private, public = _keys(tmp_path)
    server, thread, _, base = _server(tmp_path, key=public)
    try:
        status, body = _post(base, _payload(body="password=supersecret12345"), private)
        assert status == 400 and body["error"] == "secret_shaped"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_node_id_must_match_the_registry_entry(tmp_path: Path) -> None:
    _, private, public = _keys(tmp_path)
    server, thread, _, base = _server(tmp_path, key=public)
    try:
        status, body = _post(base, _payload(node_id="sparknet-node-9999"), private)
        assert status == 403 and body["error"] == "wrong_peer"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
