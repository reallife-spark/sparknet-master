"""Steps 69C + 70B: the Master peer-intake listener on 8090, for real.

This replaces ``test_listener_8090.py``, which Master Step 7 itself flagged as a test
that "passes by reading the source file's text, not by binding a socket or refusing
anything." These bind a real ``ThreadingHTTPServer`` and POST real bodies, so a
refusal the DoD names is a refusal a test can actually provoke.

70B adds the RFI request route: same registry source gate, no capability, verified by
``authz.verify_rfi_request`` and queued as one content-addressed artifact for the
composer. The route is exercised over the same loopback socket as telemetry.

The source gate is registry-driven, so a test maps ``127.0.0.1`` to a registered peer
(the same trick ``test_registry_dist.py`` uses to reach a loopback guard): attribution
is then exercised end to end, and the gate's own branches are unit-tested directly.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType
from urllib import error as urlerror
from urllib import request as urlrequest

import pytest
from sparknet_loader import load_by_path

ROLE_ROOT = Path(__file__).resolve().parent.parent
FABRIC_ROOT = ROLE_ROOT.parent
INTAKE_PATH = ROLE_ROOT / "services" / "sparknet-peer-intake.py"
TELEMETRY_ROUTE = "/api/v1/telemetry"
REQUEST_ROUTE = "/api/v1/rfi-request"
PEER_FP = "a" * 64


def _load(name: str, path: Path) -> ModuleType:
    return load_by_path(name, path)


intake = _load("sparknet_peer_intake", INTAKE_PATH)
authz = intake.authz


def _directory(*, telemetry: bool = True, revoked: bool = False, loopback: bool = True) -> intake.PeerDirectory:
    """A directory whose only peer sits at 127.0.0.1, so a loopback POST attributes."""
    entries = []
    if loopback:
        entries.append(
            {
                "fingerprint": PEER_FP,
                "overlay_ipv4": "127.0.0.1/32",
                "capabilities": ["telemetry", "guard-apply"] if telemetry else ["guard-apply"],
                "revoked": revoked,
                "issued_at": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
                "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
            }
        )
    return intake.PeerDirectory(entries)


def _report(**overrides) -> dict:
    # No fixed `now`: the intake verifies against the real clock, so a report built
    # at a pinned past instant would arrive expired. build_telemetry_report defaults
    # to the current time, which is what a live pusher would stamp.
    params = {"kind": "status", "peer_fingerprint": PEER_FP, "payload": {"alive": True}}
    params.update(overrides)
    return authz.build_telemetry_report(**params)


def _request(**overrides) -> dict:
    params = {
        "request_id": "rfi-1",
        "peer_fingerprint": PEER_FP,
        "question": "which concepts cover the overlay?",
        "scope": ["concepts"],
    }
    params.update(overrides)
    return authz.build_rfi_request(**params)


def _server(directory, spool: Path, request_dir: Path | None = None):
    listener = intake.build_listener(
        bind="127.0.0.1",
        port=0,
        directory=directory,
        spool=spool,
        request_dir=request_dir,
    )
    listener.start()
    return listener, None, f"http://127.0.0.1:{listener.servers[0].server_address[1]}"


def _post(base: str, report: dict, path: str = TELEMETRY_ROUTE) -> tuple[int, dict]:
    req = urlrequest.Request(
        base + path, data=json.dumps(report).encode(), headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urlrequest.urlopen(req, timeout=5) as response:
            return response.status, json.loads(response.read())
    except urlerror.HTTPError as exc:
        return exc.code, json.loads(exc.read())


# --- the source gate, unit-tested --------------------------------------------


def test_the_source_gate_maps_a_registered_telemetry_peer() -> None:
    assert _directory().attribute("127.0.0.1") == (PEER_FP, "")


def test_the_source_gate_refuses_an_ungranted_peer() -> None:
    """Wiring the telemetry capability: a peer without it may not push."""
    assert _directory(telemetry=False).attribute("127.0.0.1") == (None, "capability_missing")


def test_the_source_gate_refuses_a_revoked_peer() -> None:
    assert _directory(revoked=True).attribute("127.0.0.1") == (None, "revoked")


def test_the_source_gate_refuses_an_unknown_source() -> None:
    assert _directory(loopback=False).attribute("127.0.0.1") == (None, "off_overlay")
    # The Master's own address is not a peer entry, so it is not a telemetry source.
    assert _directory().attribute("10.100.0.1") == (None, "off_overlay")


def test_the_address_is_matched_bare_of_its_prefix() -> None:
    now = datetime.now(timezone.utc)
    d = intake.PeerDirectory(
        [
            {
                "fingerprint": PEER_FP,
                "overlay_ipv4": "10.100.0.9/32",
                "capabilities": ["telemetry"],
                "issued_at": (now - timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
                "expires_at": (now + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
            }
        ]
    )
    assert d.attribute("10.100.0.9") == (PEER_FP, "")


def test_the_request_gate_does_not_require_telemetry() -> None:
    """Asking is not reporting: a registered peer without `telemetry` may ask."""
    assert _directory(telemetry=False).attribute("127.0.0.1", capability=None) == (PEER_FP, "")
    # The rest of the gate still applies.
    assert _directory(telemetry=False, revoked=True).attribute("127.0.0.1", capability=None) == (None, "revoked")
    assert _directory(telemetry=False, loopback=False).attribute("127.0.0.1", capability=None) == (None, "off_overlay")


# --- the listener, over a real socket ----------------------------------------


def test_a_valid_report_is_recorded_and_acknowledged(tmp_path: Path) -> None:
    spool = tmp_path / "telemetry" / "reports.jsonl"
    listener, _thread, base = _server(_directory(), spool)
    try:
        report = _report()
        status, body = _post(base, report)
        assert status == 200
        assert body["status"] == "recorded" and body["kind"] == "status" and body["spooled"] is True
        rows = [json.loads(x) for x in spool.read_text().splitlines() if x.strip()]
        assert len(rows) == 1
        assert rows[0]["nonce"] == report["nonce"]
        assert rows[0]["source"] == "127.0.0.1"
        assert oct(spool.stat().st_mode & 0o777) == "0o600"
    finally:
        listener.stop()


def test_a_report_naming_another_peer_is_refused(tmp_path: Path) -> None:
    """Attribution is the overlay: the body's fingerprint must match the source's."""
    listener, _thread, base = _server(_directory(), tmp_path / "s.jsonl")
    try:
        status, body = _post(base, _report(peer_fingerprint="b" * 64))
        assert status == 403 and body["error"] == "wrong_peer"
    finally:
        listener.stop()


def test_an_ungranted_source_is_refused_before_the_body_is_read(tmp_path: Path) -> None:
    listener, _thread, base = _server(_directory(telemetry=False), tmp_path / "s.jsonl")
    try:
        status, body = _post(base, _report())
        assert status == 403 and body["error"] == "capability_missing"
        assert not (tmp_path / "s.jsonl").exists()
    finally:
        listener.stop()


def test_a_replayed_nonce_is_refused(tmp_path: Path) -> None:
    listener, _thread, base = _server(_directory(), tmp_path / "s.jsonl")
    try:
        report = _report()
        assert _post(base, report)[0] == 200
        status, body = _post(base, report)
        assert status == 409 and body["error"] == "replayed_nonce"
    finally:
        listener.stop()


def test_a_malformed_report_is_refused(tmp_path: Path) -> None:
    listener, _thread, base = _server(_directory(), tmp_path / "s.jsonl")
    try:
        status, body = _post(base, {**_report(), "escalate": True})
        assert status == 400 and body["error"] == "malformed"
    finally:
        listener.stop()


# --- the RFI request route, over the same socket ------------------------------


def test_a_request_from_an_ungranted_peer_is_queued(tmp_path: Path) -> None:
    """No `telemetry` capability is needed to ask, and no answer is produced here."""
    request_dir = tmp_path / "requests"
    listener, _thread, base = _server(_directory(telemetry=False), tmp_path / "s.jsonl", request_dir)
    try:
        request = _request()
        status, body = _post(base, request, path=REQUEST_ROUTE)
        assert status == 202
        assert body == {"status": "queued", "request_id": "rfi-1"}
        assert "answer" not in body
        files = list(request_dir.glob("*.json"))
        assert len(files) == 1
        assert json.loads(files[0].read_text()) == request
        assert oct(files[0].stat().st_mode & 0o777) == "0o600"
        assert oct(request_dir.stat().st_mode & 0o777) == "0o700"
    finally:
        listener.stop()


def test_a_request_naming_another_peer_is_refused(tmp_path: Path) -> None:
    listener, _thread, base = _server(_directory(), tmp_path / "s.jsonl", tmp_path / "requests")
    try:
        status, body = _post(base, _request(peer_fingerprint="b" * 64), path=REQUEST_ROUTE)
        assert status == 403 and body["error"] == "wrong_peer"
        assert not (tmp_path / "requests").exists()
    finally:
        listener.stop()


def test_a_request_from_an_unregistered_source_is_refused(tmp_path: Path) -> None:
    listener, _thread, base = _server(_directory(loopback=False), tmp_path / "s.jsonl", tmp_path / "requests")
    try:
        status, body = _post(base, _request(), path=REQUEST_ROUTE)
        assert status == 403 and body["error"] == "off_overlay"
        assert not (tmp_path / "requests").exists()
    finally:
        listener.stop()


def test_a_replayed_request_is_refused(tmp_path: Path) -> None:
    request_dir = tmp_path / "requests"
    listener, _thread, base = _server(_directory(), tmp_path / "s.jsonl", request_dir)
    try:
        request = _request()
        assert _post(base, request, path=REQUEST_ROUTE)[0] == 202
        status, body = _post(base, request, path=REQUEST_ROUTE)
        assert status == 409 and body["error"] == "replayed_nonce"
        assert len(list(request_dir.glob("*.json"))) == 1
    finally:
        listener.stop()


def test_an_expired_request_is_refused(tmp_path: Path) -> None:
    listener, _thread, base = _server(_directory(), tmp_path / "s.jsonl", tmp_path / "requests")
    try:
        status, body = _post(base, _request(ttl_seconds=-1), path=REQUEST_ROUTE)
        assert status == 403 and body["error"] == "expired"
    finally:
        listener.stop()


def test_a_future_request_is_refused(tmp_path: Path) -> None:
    listener, _thread, base = _server(_directory(), tmp_path / "s.jsonl", tmp_path / "requests")
    try:
        ahead = datetime.now(timezone.utc) + timedelta(seconds=900)
        status, body = _post(base, _request(now=ahead), path=REQUEST_ROUTE)
        assert status == 403 and body["error"] == "not_yet_valid"
    finally:
        listener.stop()


def test_the_queue_filename_is_the_digest_not_the_request_id(tmp_path: Path) -> None:
    """A peer-chosen request_id must not be able to choose a path."""
    request_dir = tmp_path / "requests"
    listener, _thread, base = _server(_directory(), tmp_path / "s.jsonl", request_dir)
    try:
        status, _ = _post(base, _request(request_id="../../escape"), path=REQUEST_ROUTE)
        assert status == 202
        files = list(request_dir.glob("*.json"))
        assert len(files) == 1 and files[0].parent == request_dir
        assert len(files[0].stem) == 64 and all(c in "0123456789abcdef" for c in files[0].stem)
        assert not (tmp_path / "escape.json").exists()
    finally:
        listener.stop()


def test_a_malformed_request_is_refused(tmp_path: Path) -> None:
    listener, _thread, base = _server(_directory(), tmp_path / "s.jsonl", tmp_path / "requests")
    try:
        status, body = _post(base, {**_request(), "signature_b64": "forged"}, path=REQUEST_ROUTE)
        assert status == 400 and body["error"] == "malformed"
    finally:
        listener.stop()


def test_healthz_and_unknown_routes(tmp_path: Path) -> None:
    listener, _thread, base = _server(_directory(), tmp_path / "s.jsonl")
    try:
        with urlrequest.urlopen(base + "/healthz", timeout=5) as response:
            assert response.status == 200 and json.loads(response.read())["ok"] is True
        # Push-only: nothing to GET on the intake route, no sibling to POST to.
        with pytest.raises(urlerror.HTTPError) as raised:
            urlrequest.urlopen(base + TELEMETRY_ROUTE, timeout=5)
        assert raised.value.code == 405
        assert _post(base, _report(), path="/api/v1/elsewhere")[0] == 404
    finally:
        listener.stop()


def test_serve_refuses_a_non_overlay_bind(tmp_path: Path) -> None:
    with pytest.raises(intake.IntakeError, match="non-overlay"):
        intake.serve("0.0.0.0", 8090, directory=_directory(), spool=tmp_path / "s.jsonl", request_dir=tmp_path / "req")


# --- contract + posture pins --------------------------------------------------


def test_the_contract_declares_8090_the_peer_intake() -> None:
    ports = json.loads((FABRIC_ROOT / "contracts" / "ports.json").read_text())
    spec = ports["ports"]["8090"]
    assert spec["service"] == "master-peer-intake"
    assert spec["bound_by"] == "master" and spec["overlay_only"] is True
    assert spec["binds_to"] == "10.100.0.1"
    assert spec["implementation_state"] == "implemented"
    assert "/api/v1/telemetry" in spec["note"] and "/api/v1/rfi-request" in spec["note"]


def test_the_intake_carries_no_authority() -> None:
    """The intake observes and queues; it never signs, answers, grants, revokes or approves."""
    source = INTAKE_PATH.read_text()
    for verb in ("sign_bytes", "sign_rfi_answer", "build_rfi_answer", "sign_authorization", "guard_approval_message"):
        assert verb not in source, f"the intake must not reach for a signing primitive ({verb})"
    assert "records evidence" in source or "no authority" in source.lower()


def test_the_unit_binds_the_overlay_only() -> None:
    unit = (ROLE_ROOT / "systemd" / "sparknet-peer-intake.service").read_text()
    assert "10.100.0.1" in unit
    assert "0.0.0.0" not in unit
    assert "sparknet-peer-intake.py" in unit
    assert "--request-dir" in unit


def test_eval_store_is_append_only_and_idempotent_by_report_id(tmp_path: Path) -> None:
    report = {
        "schema": "sparknet-eval-report/1",
        "report_id": "a" * 64,
        "node_id": "peer-1",
        "peer_fingerprint": PEER_FP,
        "records": [{"schema": "sparknet-skill-eval/1"}],
        "records_sha256": "b" * 64,
        "generated_at": "2026-11-12T00:00:00Z",
        "issued_at": "2026-11-12T00:00:00Z",
        "expires_at": "2026-11-12T00:05:00Z",
        "nonce": "c" * 32,
    }
    store = intake.EvalStore(tmp_path / "evals.jsonl")
    assert store.record(report, source="127.0.0.1") == "recorded"
    assert store.record(report, source="127.0.0.1") == "duplicate"
    reloaded = intake.EvalStore(tmp_path / "evals.jsonl")
    assert ("peer-1", "a" * 64) in reloaded.seen
