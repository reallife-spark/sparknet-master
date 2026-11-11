"""Step 67D: the RFI inbox transport, end to end.

The envelope tests (tests/contracts/test_rfi_answers.py) and the install-rule tests
(tests/test_provenance.py) prove the *rule*; this suite proves the *channel*: an
answer signed on the Master side is pushed over a real socket to the peer's own
guard daemon (loaded by path), installed into ``01_Inbox/``, and recorded as an
``inbox_acceptance`` block. That is the leg ``tracking-schema.json``'s
``phase_boundary`` gates — nothing may claim transport delivery works until a
listener exists and ``ports.json`` says so.

The shape mirrors ``test_registry_dist.py``: a real guard subprocess, a real HTTP
POST, and the peer's own acceptance rule deciding what lands. The refusals are
the point as much as the happy path — a channel that delivers is trivial, one
that delivers *only* what the Master signed for *this* peer is the contract.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sparknet_loader import load_by_path

ROLE_ROOT = Path(__file__).resolve().parent.parent
FABRIC_ROOT = ROLE_ROOT.parent
GUARD = FABRIC_ROOT / "peer-node" / "services" / "sparknet-guard-d.py"
COMPOSER = ROLE_ROOT / "scripts" / "sparknet-rfi-answer.sh"
INTAKE = ROLE_ROOT / "services" / "sparknet-peer-intake.py"
INTAKE_ROUTE = "/api/v1/rfi-request"
RFI_ROUTE = "/api/v1/rfi"
OWNER_ID = "U-10421"


def _load(name: str, path: Path):
    return load_by_path(name, path)


authz = _load("sparknet_authz_rfi", FABRIC_ROOT / "shared" / "sparknet-authz.py")
provenance = _load("sparknet_provenance_rfi", FABRIC_ROOT / "shared" / "sparknet-provenance.py")


# --- fixtures ----------------------------------------------------------------


def _public_b64(key: Ed25519PrivateKey) -> str:
    return base64.b64encode(
        key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).decode()


@pytest.fixture
def master_state(tmp_path: Path) -> tuple[Path, Ed25519PrivateKey]:
    """A throwaway Master state dir with one operational key pair."""
    key = Ed25519PrivateKey.generate()
    state = tmp_path / "master-state"
    keys = state / "keys"
    keys.mkdir(parents=True)
    raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    (keys / "operational.ed25519").write_text(base64.b64encode(raw).decode() + "\n")
    (keys / "operational.ed25519").chmod(0o600)
    (keys / "operational.pub.b64").write_text(_public_b64(key) + "\n")
    return state, key


def _identity(node_id: str = "peer-rfi") -> dict:
    return {
        "node_id": node_id,
        "role": "peer",
        "wireguard_public_key_b64": base64.b64encode(b"\x11" * 32).decode(),
        "overlay_ipv4": "10.100.0.9",
        "requested_capabilities": ["telemetry", "guard-apply"],
    }


def _user_record_template() -> str:
    return (
        "---\n"
        "type: user-record\n"
        "schema: sparknet-user/1\n"
        "status: unfilled\n"
        'owner_id: ""\n'
        'owner_node: ""\n'
        "role: owner\n"
        "immutable: true\n"
        "key:\n"
        "  alg: ed25519\n"
        '  public_key_b64: ""\n'
        '  fingerprint: ""\n'
        '  key_ref: "$SPARKNET_STATE_DIR/keys/user.ed25519"\n'
        '  created: ""\n'
        "---\n\n"
        "# user record\n"
    )


@pytest.fixture
def peer_vault(tmp_path: Path, master_state, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    """A user-init'd peer vault, with nothing installed yet.

    Returns ``(vault, state_dir)``. The state dir holds the user key (from
    ``user_init``) and the node key, because installing an answer appends a
    dual-signed ``inbox_acceptance`` block and both halves must exist.
    """
    _master_state, master_key = master_state
    vault = tmp_path / "peer"
    state = tmp_path / "peer-state"
    (vault / "00_System").mkdir(parents=True)
    (vault / "01_Inbox").mkdir()
    (vault / "blockchain").mkdir()
    (vault / "manifests" / "keys").mkdir(parents=True)
    (vault / "00_System" / "user.md").write_text(_user_record_template())
    (vault / "manifests" / "node-identity.json").write_text(json.dumps(_identity(), indent=2) + "\n")
    (vault / "manifests" / "critical-manifest.json").write_text(json.dumps({"protected_paths": []}, indent=2) + "\n")
    (vault / "manifests" / "security-policies.json").write_text(
        json.dumps({"wireguard": {"master_anchor_ip": "10.100.0.1"}}, indent=2) + "\n"
    )
    (vault / "manifests" / "keys" / "master-ed25519.pub.b64").write_text(_public_b64(master_key) + "\n")
    (vault / "manifests" / "keys" / "master-ed25519.pub.b64").chmod(0o600)

    # user_init writes the user key into SPARKNET_STATE_DIR; point it at the peer's.
    monkeypatch.setenv("SPARKNET_STATE_DIR", str(state))
    provenance.user_init(vault, owner_id=OWNER_ID)
    node_key = state / "keys" / "ed25519-node.key.b64"
    node_key.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    private_b64, _ = authz.generate_keypair()
    node_key.write_text(private_b64 + "\n")
    node_key.chmod(0o600)
    return vault, state


def _fingerprint(vault: Path) -> str:
    return authz.fingerprint(json.loads((vault / "manifests" / "node-identity.json").read_text()))


# --- guard + composer plumbing -----------------------------------------------


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _start_guard(vault: Path, state: Path, port: int, *, extra_env: dict[str, str] | None = None) -> subprocess.Popen:
    """The peer's own guard, not a stub — the code that would run on the node."""
    # A bogus KDE device id keeps the arrival notification hermetic: the guard
    # calls the real notify path, and without this a dev host that happens to have
    # kdeconnect-cli paired would ping a real device on every install test. The
    # spool row is what the test asserts; whether a ping landed is host-dependent.
    env = {
        **os.environ,
        "SPARKNET_STATE_DIR": str(state),
        "SPARKNET_KDE_DEVICES": "sparknet-test-nonexistent",
        **(extra_env or {}),
    }
    process = subprocess.Popen(
        [
            sys.executable,
            str(GUARD),
            "--vault-root",
            str(vault),
            "--listen",
            "127.0.0.1",
            "--port",
            str(port),
            "--bind-any",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    deadline = time.time() + 30
    while time.time() < deadline:
        if process.poll() is not None:
            raise AssertionError(f"the peer guard died: {process.stderr.read() if process.stderr else ''}")
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/v1/status", timeout=1) as response:
                if response.status == 200:
                    return process
        except (urllib.error.URLError, OSError):
            time.sleep(0.1)
    process.terminate()
    raise AssertionError("the peer guard never started listening")


@pytest.fixture
def running_guard(peer_vault):
    vault, state = peer_vault
    port = _free_port()
    process = _start_guard(vault, state, port)
    try:
        yield port
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()


def _post(port: int, artifact: dict, path: str = RFI_ROUTE) -> tuple[int, dict]:
    body = json.dumps(artifact).encode()
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            return error.code, json.loads(raw)
        except json.JSONDecodeError:
            return error.code, {"raw": raw.decode("utf-8", "replace")}


def _start_telemetry_intake(peer_fp: str, spool: Path):
    """The real 8090 telemetry route, loopback-mapped to the destination peer."""
    intake = _load("sparknet_peer_intake_alert", INTAKE)
    directory = intake.PeerDirectory(
        [
            {
                "fingerprint": peer_fp,
                "overlay_ipv4": "127.0.0.1/32",
                "capabilities": ["telemetry"],
                "issued_at": "2020-01-01T00:00:00Z",
                "expires_at": "2099-01-01T00:00:00Z",
            }
        ]
    )
    listener = intake.build_listener(
        bind="127.0.0.1",
        port=0,
        directory=directory,
        spool=spool,
        request_dir=spool.parent / "requests",
    )
    listener.start()
    return listener, listener, f"http://127.0.0.1:{listener.servers[0].server_address[1]}"


def _write_telemetry_registry(vault: Path, master_key: Ed25519PrivateKey, capabilities=("telemetry",)) -> None:
    identity = json.loads((vault / "manifests" / "node-identity.json").read_text())
    entry = authz.sign_authorization(identity, master_key, list(capabilities))
    (vault / "manifests" / "node-authorizations.json").write_text(
        json.dumps({"schema_version": "1.0", "authorizations": [entry]}, indent=2) + "\n"
    )


def _telemetry_rows(spool: Path) -> list[dict]:
    if not spool.exists():
        return []
    return [json.loads(line) for line in spool.read_text().splitlines() if line.strip()]


def _compose(
    master_state: Path,
    url: str,
    peer_fp: str,
    *,
    request_id="RFI-1",
    item_name="answer.md",
    content: bytes | None = b"# the answer\n",
    empty=False,
    answered_at=None,
) -> subprocess.CompletedProcess:
    """Run the Master-side composer against a loopback guard (--offline, --url)."""
    env = {**os.environ, "SPARKNET_STATE_DIR": str(master_state)}
    cmd = [
        str(COMPOSER),
        "--request-id",
        request_id,
        "--peer",
        peer_fp,
        "--item-name",
        item_name,
        "--url",
        url,
        "--offline",
        "--timeout",
        "10",
    ]
    if empty:
        cmd.append("--empty")
    else:
        # Content rides in a file; the composer reads its bytes.
        content_file = Path(os.environ["RFI_CONTENT_FILE"])
        content_file.write_bytes(content or b"")
        cmd += ["--content", str(content_file)]
    if answered_at:
        cmd += ["--answered-at", answered_at]
    return subprocess.run(cmd, capture_output=True, text=True, env=env)


@pytest.fixture
def content_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "answer-content.md"
    monkeypatch.setenv("RFI_CONTENT_FILE", str(path))
    return path


def _start_intake(peer_fp: str, request_dir: Path):
    """The real 8090 peer intake, loopback-mapped to the destination peer."""
    intake = _load("sparknet_peer_intake_rfi", INTAKE)
    directory = intake.PeerDirectory(
        [
            {
                "fingerprint": peer_fp,
                "overlay_ipv4": "127.0.0.1/32",
                "capabilities": [],
                "issued_at": "2020-01-01T00:00:00Z",
                "expires_at": "2099-01-01T00:00:00Z",
            }
        ]
    )
    listener = intake.build_listener(
        bind="127.0.0.1",
        port=0,
        directory=directory,
        spool=request_dir.parent / "telemetry.jsonl",
        request_dir=request_dir,
    )
    listener.start()
    return listener, listener, int(listener.servers[0].server_address[1])


def _compose_from_request(
    master_state: Path,
    artifact: Path,
    url: str,
    *,
    item_name="answer.md",
    content_file: Path,
    sources: str | None = None,
) -> subprocess.CompletedProcess:
    """The 70C path: the request artifact supplies peer, id, question and scope."""
    env = {**os.environ, "SPARKNET_STATE_DIR": str(master_state)}
    cmd = [
        str(COMPOSER),
        "--request",
        str(artifact),
        "--item-name",
        item_name,
        "--url",
        url,
        "--offline",
        "--timeout",
        "10",
        "--content",
        str(content_file),
    ]
    if sources is not None:
        cmd += ["--sources", sources]
    return subprocess.run(cmd, capture_output=True, text=True, env=env)


def _acceptances(vault: Path) -> list[dict]:
    blocks = provenance.load_ledger(vault / "blockchain" / "ledger.json")["blocks"]
    return [b for b in blocks if (b.get("data") or {}).get("event") == "inbox_acceptance"]


# --- the happy path: an answer crosses the wire and lands --------------------


def test_a_composed_answer_lands_in_the_inbox_and_is_recorded(
    master_state, peer_vault, running_guard, content_file
) -> None:
    vault, state = peer_vault
    _mstate, _key = master_state
    peer_fp = _fingerprint(vault)
    url = f"http://127.0.0.1:{running_guard}{RFI_ROUTE}"

    result = _compose(_mstate, url, peer_fp, request_id="RFI-1", item_name="guard.md", content=b"# the answer\n")
    assert result.returncode == 0, result.stdout + result.stderr

    # The item is in the inbox, byte for byte.
    assert (vault / "01_Inbox" / "guard.md").read_bytes() == b"# the answer\n"
    # The install rule recorded the request id, so a re-delivery is a duplicate.
    record = json.loads((vault / "manifests" / "rfi-installation.json").read_text())
    assert record["request_ids"] == ["RFI-1"]
    # And the arrival is attributable: a dual-signed inbox_acceptance block.
    acceptances = _acceptances(vault)
    assert len(acceptances) == 1
    data = acceptances[0]["data"]
    assert data["source"] == "master-node"
    assert data["item"] == "01_Inbox/guard.md"
    assert set(data["signatures"]) == {"user", "node"}
    # The answer verifies under the Master key the peer has pinned.
    assert data["decision"] == "accepted"

    # 67B: the arrival also reaches the human — a durable spool row under the
    # guard's state dir. Whether a KDE ping landed (`notified`) is host-dependent,
    # so only the durable record is asserted here; the ping itself is pinned by
    # tests/test_notify.py with an injected device.
    spool = state / "notifications" / "arrivals.jsonl"
    assert spool.is_file(), "an arrived item must leave a notification, not only a ledger block"
    rows = [json.loads(line) for line in spool.read_text().splitlines() if line.strip()]
    assert len(rows) == 1
    assert rows[0]["event"] == "inbox_arrival"
    assert rows[0]["item"] == "01_Inbox/guard.md"
    assert rows[0]["request_id"] == "RFI-1"
    assert isinstance(rows[0]["notified"], bool)


def test_an_installed_answer_emits_an_overlay_attributed_inbox_alert(
    master_state, peer_vault, content_file, tmp_path: Path
) -> None:
    """70F: the arrival reaches the Master as evidence, while 67B stays local.

    The guard is the real subprocess, the intake is the real 8090 telemetry route,
    and the composer is the real Master-side path — so this is the whole leg, not
    a unit of ``_emit_inbox_alert``. The alert is unsigned and overlay-attributed
    (the intake derives the same fingerprint from 127.0.0.1); it carries the item,
    request id, digest and ledger hash, and no authority.
    """
    vault, state = peer_vault
    mstate, master_key = master_state
    peer_fp = _fingerprint(vault)
    _write_telemetry_registry(vault, master_key)

    telemetry_spool = tmp_path / "telemetry.jsonl"
    server, thread, base = _start_telemetry_intake(peer_fp, telemetry_spool)
    port = _free_port()
    process = _start_guard(
        vault,
        state,
        port,
        extra_env={"SPARKNET_TELEMETRY_ENDPOINT": base + "/api/v1/telemetry"},
    )
    try:
        result = _compose(
            mstate,
            f"http://127.0.0.1:{port}{RFI_ROUTE}",
            peer_fp,
            request_id="RFI-ALERT",
            item_name="alert.md",
            content=b"# alert\n",
        )
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert result.returncode == 0, result.stdout + result.stderr
    rows = _telemetry_rows(telemetry_spool)
    assert [row["kind"] for row in rows] == ["inbox_alert"]
    report = {key: value for key, value in rows[0].items() if key != "source"}
    ok, reason = authz.verify_telemetry_report(report, expected_fingerprint=peer_fp)
    assert ok, reason
    assert rows[0]["source"] == "127.0.0.1"
    assert "signature_b64" not in report
    payload = report["payload"]
    assert payload["item"] == "01_Inbox/alert.md"
    assert payload["source"] == "master-node"
    assert payload["request_id"] == "RFI-ALERT"
    assert payload["content_sha256"]
    assert payload["audit_block"]
    assert "grant" not in json.dumps(payload).lower()

    # 67B is unchanged: the local durable spool still records the arrival.
    arrivals = state / "notifications" / "arrivals.jsonl"
    local = [json.loads(line) for line in arrivals.read_text().splitlines() if line.strip()]
    assert local[0]["item"] == "01_Inbox/alert.md"
    assert local[0]["request_id"] == "RFI-ALERT"


def test_an_ungranted_peer_still_installs_but_sends_no_alert(
    master_state, peer_vault, content_file, tmp_path: Path
) -> None:
    """No telemetry capability means no remote alert; acceptance is unaffected."""
    vault, state = peer_vault
    mstate, _master_key = master_state
    peer_fp = _fingerprint(vault)
    telemetry_spool = tmp_path / "telemetry.jsonl"
    server, thread, base = _start_telemetry_intake(peer_fp, telemetry_spool)
    port = _free_port()
    process = _start_guard(
        vault,
        state,
        port,
        extra_env={"SPARKNET_TELEMETRY_ENDPOINT": base + "/api/v1/telemetry"},
    )
    try:
        result = _compose(
            mstate,
            f"http://127.0.0.1:{port}{RFI_ROUTE}",
            peer_fp,
            request_id="RFI-NO-ALERT",
            item_name="quiet.md",
            content=b"# quiet\n",
        )
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert result.returncode == 0, result.stdout + result.stderr
    assert (vault / "01_Inbox" / "quiet.md").read_bytes() == b"# quiet\n"
    assert not telemetry_spool.exists()
    assert (state / "notifications" / "arrivals.jsonl").is_file()


def test_an_empty_answer_is_a_legitimate_delivery(master_state, peer_vault, running_guard) -> None:
    """'Nothing found' crosses the wire and installs like any other answer."""
    vault, _state = peer_vault
    _mstate, _key = master_state
    url = f"http://127.0.0.1:{running_guard}{RFI_ROUTE}"
    result = _compose(_mstate, url, _fingerprint(vault), request_id="RFI-EMPTY", item_name="empty.md", empty=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert (vault / "01_Inbox" / "empty.md").read_bytes() == b""
    assert json.loads((vault / "manifests" / "rfi-installation.json").read_text())["request_ids"] == ["RFI-EMPTY"]


# --- 70C: a queued request drives the composer --------------------------------


def test_a_queued_request_closes_the_peer_to_peer_loop(
    master_state, peer_vault, running_guard, content_file, tmp_path: Path
) -> None:
    """request -> real 8090 intake -> queue artifact -> composer -> peer inbox."""
    vault, _state = peer_vault
    mstate, _key = master_state
    peer_fp = _fingerprint(vault)
    request_dir = tmp_path / "requests"
    server, thread, port = _start_intake(peer_fp, request_dir)
    try:
        request = authz.build_rfi_request(
            request_id="RFI-E2E",
            peer_fingerprint=peer_fp,
            question="which concepts cover the overlay?",
            scope=["concepts"],
        )
        status, body = _post(port, request, path=INTAKE_ROUTE)
        assert status == 202 and body == {"status": "queued", "request_id": "RFI-E2E"}
        artifacts = list(request_dir.glob("*.json"))
        assert len(artifacts) == 1

        content_file.write_bytes(b"# scoped answer\n")
        result = _compose_from_request(
            mstate,
            artifacts[0],
            f"http://127.0.0.1:{running_guard}{RFI_ROUTE}",
            item_name="scoped.md",
            content_file=content_file,
            sources="concepts",
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert (vault / "01_Inbox" / "scoped.md").read_bytes() == b"# scoped answer\n"
        assert json.loads((vault / "manifests" / "rfi-installation.json").read_text())["request_ids"] == ["RFI-E2E"]
        document = json.loads(result.stdout)
        assert document["request_id"] == "RFI-E2E"
        assert document["peer_fingerprint"] == peer_fp
        assert document["delivery"]["scope"] == ["concepts"]
        assert document["delivery"]["sources"] == ["concepts"]
        assert document["delivery"]["question"] == "which concepts cover the overlay?"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_the_composer_refuses_to_widen_the_request_scope(
    master_state, peer_vault, running_guard, content_file, tmp_path: Path
) -> None:
    vault, _state = peer_vault
    mstate, _key = master_state
    peer_fp = _fingerprint(vault)
    request_dir = tmp_path / "requests"
    server, thread, port = _start_intake(peer_fp, request_dir)
    try:
        request = authz.build_rfi_request(
            request_id="RFI-SCOPE",
            peer_fingerprint=peer_fp,
            question="anything",
            scope=["concepts"],
        )
        assert _post(port, request, path=INTAKE_ROUTE)[0] == 202
        artifact = next(request_dir.glob("*.json"))
        content_file.write_bytes(b"# secret\n")
        url = f"http://127.0.0.1:{running_guard}{RFI_ROUTE}"

        missing = _compose_from_request(mstate, artifact, url, item_name="a.md", content_file=content_file)
        assert missing.returncode != 0 and "must declare --sources" in missing.stderr

        widened = _compose_from_request(
            mstate, artifact, url, item_name="b.md", content_file=content_file, sources="security"
        )
        assert widened.returncode != 0 and "outside the request's scope" in widened.stderr
        assert not (vault / "01_Inbox" / "a.md").exists()
        assert not (vault / "01_Inbox" / "b.md").exists()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_the_composer_refuses_a_stale_request_artifact(
    master_state, peer_vault, running_guard, content_file, tmp_path: Path
) -> None:
    _vault, _state = peer_vault
    mstate, _key = master_state
    peer_fp = _fingerprint(_vault)
    stale = authz.build_rfi_request(
        request_id="RFI-STALE",
        peer_fingerprint=peer_fp,
        question="too late",
        scope=["concepts"],
        ttl_seconds=-1,
    )
    artifact = tmp_path / "stale.json"
    artifact.write_text(json.dumps(stale))
    content_file.write_bytes(b"# nope\n")
    result = _compose_from_request(
        mstate,
        artifact,
        f"http://127.0.0.1:{running_guard}{RFI_ROUTE}",
        item_name="stale.md",
        content_file=content_file,
        sources="concepts",
    )
    assert result.returncode != 0 and "[expired]" in result.stderr
    assert not (tmp_path / "peer" / "01_Inbox" / "stale.md").exists()


# --- refusals over the wire --------------------------------------------------


def test_a_replayed_answer_is_refused_by_the_peer(master_state, peer_vault, running_guard, content_file) -> None:
    vault, _state = peer_vault
    _mstate, _key = master_state
    url = f"http://127.0.0.1:{running_guard}{RFI_ROUTE}"
    peer_fp = _fingerprint(vault)
    assert _compose(_mstate, url, peer_fp, request_id="RFI-1", item_name="guard.md").returncode == 0

    # The same request again: the composer self-checks with an empty install set,
    # so it delivers — and the *peer* refuses it as the duplicate it is.
    replay = _compose(_mstate, url, peer_fp, request_id="RFI-1", item_name="guard.md", content=b"# different\n")
    assert replay.returncode != 0
    assert "duplicate_answer" in replay.stdout + replay.stderr
    # The first answer stands; the replay neither replaced it nor added a record.
    assert (vault / "01_Inbox" / "guard.md").read_bytes() == b"# the answer\n"
    assert json.loads((vault / "manifests" / "rfi-installation.json").read_text())["request_ids"] == ["RFI-1"]
    assert len(_acceptances(vault)) == 1


def test_an_answer_for_another_peer_is_refused(master_state, peer_vault, running_guard) -> None:
    vault, _state = peer_vault
    _mstate, master_key = master_state
    # Signed by the pinned Master, but bound to a different peer's fingerprint:
    # the signature is valid, so this isolates the peer-binding check. An answer
    # minted for one node must not install into another's inbox.
    artifact = authz.sign_rfi_answer(
        content=b"# stolen\n",
        item_name="guard.md",
        peer_fingerprint="b" * 64,
        request_id="RFI-X",
        master_private_key=master_key,
    )
    status, body = _post(running_guard, artifact)
    assert status == 403
    assert body["code"] == authz.REASON_RFI_WRONG_PEER
    assert not (vault / "01_Inbox" / "guard.md").exists()


def test_a_tampered_answer_is_refused_before_it_lands(master_state, peer_vault, running_guard) -> None:
    vault, _state = peer_vault
    _mstate, master_key = master_state
    peer_fp = _fingerprint(vault)
    good = authz.sign_rfi_answer(
        content=b"# benign\n",
        item_name="guard.md",
        peer_fingerprint=peer_fp,
        request_id="RFI-T",
        master_private_key=master_key,
    )
    # Swap the payload under a valid signature: the digest binds it.
    forged = {**good, "content_b64": base64.b64encode(b"# injected\n").decode()}
    status, body = _post(running_guard, forged)
    assert status == 400
    assert body["code"] == authz.REASON_RFI_DIGEST_MISMATCH
    assert not (vault / "01_Inbox" / "guard.md").exists()


def test_an_answer_signed_by_another_master_is_refused(peer_vault, running_guard) -> None:
    vault, _state = peer_vault
    stranger = Ed25519PrivateKey.generate()
    artifact = authz.sign_rfi_answer(
        content=b"# from nobody\n",
        item_name="guard.md",
        peer_fingerprint=_fingerprint(vault),
        request_id="RFI-S",
        master_private_key=stranger,
    )
    status, body = _post(running_guard, artifact)
    assert status == 403
    assert body["code"] == authz.REASON_RFI_BAD_SIGNATURE
    assert not (vault / "01_Inbox" / "guard.md").exists()


def test_an_expired_answer_is_refused(master_state, peer_vault, running_guard, content_file) -> None:
    vault, _state = peer_vault
    _mstate, _key = master_state
    url = f"http://127.0.0.1:{running_guard}{RFI_ROUTE}"
    long_ago = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat().replace("+00:00", "Z")
    # The composer self-checks against the answer's own timestamp, so it delivers;
    # the peer's clock is the one that finds it stale.
    result = _compose(_mstate, url, _fingerprint(vault), request_id="RFI-OLD", item_name="old.md", answered_at=long_ago)
    assert result.returncode != 0
    assert "expired" in result.stdout + result.stderr
    assert not (vault / "01_Inbox" / "old.md").exists()


def test_an_unsafe_item_name_is_refused_and_writes_nothing(master_state, peer_vault, running_guard) -> None:
    vault, _state = peer_vault
    _mstate, _master_key = master_state
    # item_name is inside the signed projection, so rfi_answer_message refuses to
    # even canonicalise a traversing name — the peer reads that as `malformed`
    # before it checks any signature, and nothing is written outside 01_Inbox.
    before = (vault / "00_System" / "user.md").read_bytes()
    artifact = {
        "answered_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "content_b64": base64.b64encode(b"x").decode(),
        "content_sha256": hashlib.sha256(b"x").hexdigest(),
        "item_name": "../00_System/user.md",
        "peer_fingerprint": _fingerprint(vault),
        "request_id": "RFI-TRAVERSAL",
        "signature_b64": base64.b64encode(b"\x00" * 64).decode(),
    }
    status, body = _post(running_guard, artifact)
    assert status == 400
    assert body["code"] == authz.REASON_RFI_MALFORMED
    # The traversal target is untouched, and nothing landed in the inbox.
    assert (vault / "00_System" / "user.md").read_bytes() == before
    assert list((vault / "01_Inbox").iterdir()) == []


# --- route hygiene -----------------------------------------------------------


def test_the_rfi_route_is_not_a_discovery_surface(running_guard) -> None:
    """Push only: GET on the route is a method mismatch, and no sibling path to POST to."""
    with pytest.raises(urllib.error.HTTPError) as raised:
        urllib.request.urlopen(f"http://127.0.0.1:{running_guard}{RFI_ROUTE}", timeout=5)
    assert raised.value.code == 405
    status, _body = _post(running_guard, {"anything": True}, path="/api/v1/elsewhere")
    assert status == 404


def test_a_vault_with_no_user_record_refuses_cleanly_before_writing(master_state, tmp_path: Path) -> None:
    """Installing records a dual-signed acceptance; a vault that cannot record it
    must refuse before the item is written, not leave an item with no trail."""
    _mstate, master_key = master_state
    # A guard vault with an identity and the pinned Master key, but NO user record.
    vault = tmp_path / "bare-peer"
    (vault / "manifests" / "keys").mkdir(parents=True)
    (vault / "01_Inbox").mkdir()
    (vault / "blockchain").mkdir()
    (vault / "manifests" / "node-identity.json").write_text(json.dumps(_identity("bare"), indent=2) + "\n")
    (vault / "manifests" / "critical-manifest.json").write_text(json.dumps({"protected_paths": []}, indent=2) + "\n")
    (vault / "manifests" / "security-policies.json").write_text(
        json.dumps({"wireguard": {"master_anchor_ip": "10.100.0.1"}}, indent=2) + "\n"
    )
    (vault / "manifests" / "keys" / "master-ed25519.pub.b64").write_text(_public_b64(master_key) + "\n")
    (vault / "manifests" / "keys" / "master-ed25519.pub.b64").chmod(0o600)

    state = tmp_path / "bare-state"
    state.mkdir()
    port = _free_port()
    process = _start_guard(vault, state, port)
    try:
        artifact = authz.sign_rfi_answer(
            content=b"# answer\n",
            item_name="guard.md",
            peer_fingerprint=_fingerprint(vault),
            request_id="RFI-NOUSER",
            master_private_key=master_key,
        )
        status, body = _post(port, artifact)
        assert status == 503
        assert body["code"] == "no_user_record"
        assert not (vault / "01_Inbox" / "guard.md").exists()
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
