"""Step 9C/9G: the scheduler is a fail-closed lease state machine and signed dispatcher."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType

import pytest
from sparknet_loader import load_by_path

ROLE_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = ROLE_ROOT.parent
SCHEDULER = ROLE_ROOT / "services" / "sparknet-scheduler.py"
AUTHZ = REPO_ROOT / "shared" / "sparknet-authz.py"


def _load(path: Path, name: str) -> ModuleType:
    return load_by_path(name, path)


scheduler = _load(SCHEDULER, "sparknet_scheduler")
authz = _load(AUTHZ, "sparknet_scheduler_test_authz")


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _key(seed: int) -> str:
    return base64.b64encode(bytes([seed]) * 32).decode("ascii")


def _idle(
    now: datetime,
    *,
    interactive: int = 0,
    ssh: int = 0,
    gpu: float = 0.0,
    errors: list[str] | None = None,
    sampled_at: datetime | None = None,
) -> dict:
    return {
        "schema_version": "sparknet-idle/1",
        "sampled_at": _iso(sampled_at or now),
        "interactive_sessions": interactive,
        "ssh_sessions": ssh,
        "gpu_probe": "tegrastats",
        "gpu_util_pct": gpu,
        "wg_interface": "wg1",
        "wg_rx_bytes": None,
        "wg_tx_bytes": None,
        "wg_peer_count": None,
        "errors": list(errors or []),
    }


def _identity(node_id: str, role: str, overlay: str, seed: int) -> dict:
    return {
        "node_id": node_id,
        "role": role,
        "wireguard_public_key_b64": _key(seed),
        "overlay_ipv4": overlay,
        "requested_capabilities": ["telemetry"],
    }


def _registry(
    tmp_path: Path,
    now: datetime,
    *,
    nodes: list[dict] | None = None,
    revoked: bool = False,
) -> tuple[Path, dict, dict]:
    nodes = nodes or [("agx64", "peer", "10.100.0.2", 1)]
    private_b64, public_b64 = authz.generate_keypair()
    private_key = authz.private_key_from_b64(private_b64)
    entries = []
    identities = {}
    for node_id, role, overlay, seed in nodes:
        identity = _identity(node_id, role, overlay, seed)
        identities[node_id] = identity
        entries.append(
            authz.sign_authorization(
                identity,
                private_key,
                ["telemetry"],
                ttl_days=1,
                now=now,
                revoked=revoked,
            )
        )
    document = {
        "schema_version": "1.0",
        "master_public_key_b64": public_b64,
        "description": "test registry",
        "authorizations": entries,
    }
    path = tmp_path / "registry.json"
    path.write_text(json.dumps(document, sort_keys=True))
    return path, document, identities


def _row(
    identity: dict,
    idle: dict,
    nonce: str,
    *,
    source: str | None = None,
) -> dict:
    moment = scheduler.parse_ts(idle["sampled_at"])
    return {
        "source": source or identity["overlay_ipv4"],
        "kind": "metrics",
        "peer_fingerprint": authz.fingerprint(identity),
        "payload": {"idle": idle},
        "issued_at": _iso(moment),
        "expires_at": _iso(moment + timedelta(minutes=5)),
        "nonce": nonce,
    }


def _write_spool(path: Path, rows: list[dict]) -> None:
    path.write_text("\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n")


def _observer(
    path: Path, now: datetime, key: str, *, boot: str = "boot-1", previous: int = 100, current: int = 100
) -> None:
    history = [
        {
            "sampled_at": _iso(now - timedelta(seconds=60)),
            "interface": "wg1",
            "peers": [{"public_key_b64": key, "rx_bytes": previous, "tx_bytes": 50}],
        },
        {
            "sampled_at": _iso(now),
            "interface": "wg1",
            "peers": [{"public_key_b64": key, "rx_bytes": current, "tx_bytes": 50}],
        },
    ]
    path.write_text(
        json.dumps(
            {
                "schema_version": "sparknet-wg-observer/1",
                "boot_id": boot,
                "sampled_at": _iso(now),
                "interface": "wg1",
                "peers": history[-1]["peers"],
                "history": history,
                "errors": [],
            },
            sort_keys=True,
        )
    )


def _arm_args(tmp_path: Path, now: datetime, plan_id: str, *, confirm: str | None = None) -> list[str]:
    return [
        "--registry",
        str(tmp_path / "registry.json"),
        "--telemetry",
        str(tmp_path / "telemetry.jsonl"),
        "--snapshot",
        str(tmp_path / "wg.json"),
        "--state-dir",
        str(tmp_path / "state"),
        "--now",
        _iso(now),
        "arm",
        "--plan-id",
        plan_id,
        "--confirm",
        confirm or plan_id,
        "--operator",
        "alice",
        "--reason",
        "test window",
    ]


def _global_args(tmp_path: Path, now: datetime, command: str) -> list[str]:
    return [
        "--registry",
        str(tmp_path / "registry.json"),
        "--telemetry",
        str(tmp_path / "telemetry.jsonl"),
        "--snapshot",
        str(tmp_path / "wg.json"),
        "--state-dir",
        str(tmp_path / "state"),
        "--now",
        _iso(now),
        command,
    ]


class _FakeIdle:
    def __init__(self, sample: dict) -> None:
        self.sample = sample

    def collect_idle_evidence(self, *, now=None, interface=None) -> dict:
        return self.sample


def _prepare_ready(tmp_path: Path, now: datetime, *, nodes: list[dict] | None = None) -> dict:
    registry_path, _, identities = _registry(tmp_path, now, nodes=nodes)
    assert registry_path.exists()
    identity = identities["agx64"]
    samples = [_idle(now - timedelta(minutes=10)), _idle(now - timedelta(minutes=5))]
    rows = [
        _row(identity, _idle(now - timedelta(minutes=10)), "n1"),
        _row(identity, _idle(now - timedelta(minutes=5)), "n2"),
    ]
    _write_spool(tmp_path / "telemetry.jsonl", rows)
    _observer(tmp_path / "wg.json", now, identity["wireguard_public_key_b64"])
    state = scheduler.default_state()
    state["local_history"] = samples
    scheduler.save_state(tmp_path / "state", state, now)
    return identity


def test_plan_requires_three_consecutive_samples(tmp_path, monkeypatch, capsys):
    now = datetime.now().astimezone().replace(hour=2, minute=15, second=0, microsecond=0)
    identity = _prepare_ready(tmp_path, now)
    state = scheduler.load_state(tmp_path / "state")
    state["local_history"] = state["local_history"][-1:]
    scheduler.save_state(tmp_path / "state", state, now)
    monkeypatch.setattr(scheduler, "_idle", lambda: _FakeIdle(_idle(now)))
    monkeypatch.setattr(scheduler, "_current_boot_id", lambda: "boot-1")
    rows = scheduler.read_telemetry(tmp_path / "telemetry.jsonl")
    rows.append(_row(identity, _idle(now), "n3"))
    _write_spool(tmp_path / "telemetry.jsonl", rows)

    code = scheduler.main(_global_args(tmp_path, now, "plan"))
    output = json.loads(capsys.readouterr().out)
    assert code == 2
    assert output["ready"] is False
    assert "insufficient_samples" in output["reasons"]
    state = scheduler.load_state(tmp_path / "state")
    assert state["state"] == "PROBING"
    assert len(state["local_history"]) == 2


def test_plan_is_dry_run_and_arm_records_the_confirmed_lease(tmp_path, monkeypatch, capsys):
    now = datetime.now().astimezone().replace(hour=2, minute=15, second=0, microsecond=0)
    identity = _prepare_ready(tmp_path, now)
    monkeypatch.setattr(scheduler, "_idle", lambda: _FakeIdle(_idle(now)))
    monkeypatch.setattr(scheduler, "_current_boot_id", lambda: "boot-1")
    rows = json.loads("[" + ",".join((tmp_path / "telemetry.jsonl").read_text().splitlines()) + "]")
    rows.append(_row(identity, _idle(now), "n3"))
    _write_spool(tmp_path / "telemetry.jsonl", rows)

    assert scheduler.main(_global_args(tmp_path, now, "plan")) == 0
    planned = json.loads(capsys.readouterr().out)
    assert planned["ready"] is True
    assert planned["plan"]["assignments"] == []
    assert planned["plan"]["roster_digest"]
    assert planned["plan"]["evidence"]["ready"] is True
    plan_id = planned["plan"]["plan_id"]

    assert scheduler.main(_arm_args(tmp_path, now, plan_id)) == 0
    armed = json.loads(capsys.readouterr().out)
    assert armed["state"] == "ARMED"
    assert armed["lease"]["operator"] == "alice"
    assert armed["lease"]["reason"] == "test window"
    assert armed["lease"]["plan_id"] == plan_id
    assert armed["lease"]["assignments"] == []

    assert scheduler.main(_global_args(tmp_path, now, "status")) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["state"] == "ARMED"
    assert status["ready"] is True

    assert scheduler.main(_global_args(tmp_path, now, "abort")) == 0
    aborted = json.loads(capsys.readouterr().out)
    assert aborted["state"] == "CLOSED"
    assert scheduler.load_state(tmp_path / "state")["state"] == "CLOSED"


def test_arm_requires_the_exact_plan_id_and_confirmation(tmp_path, monkeypatch, capsys):
    now = datetime.now().astimezone().replace(hour=2, minute=15, second=0, microsecond=0)
    identity = _prepare_ready(tmp_path, now)
    monkeypatch.setattr(scheduler, "_idle", lambda: _FakeIdle(_idle(now)))
    monkeypatch.setattr(scheduler, "_current_boot_id", lambda: "boot-1")
    rows = json.loads("[" + ",".join((tmp_path / "telemetry.jsonl").read_text().splitlines()) + "]")
    rows.append(_row(identity, _idle(now), "n3"))
    _write_spool(tmp_path / "telemetry.jsonl", rows)
    assert scheduler.main(_global_args(tmp_path, now, "plan")) == 0
    plan_id = json.loads(capsys.readouterr().out)["plan"]["plan_id"]

    code = scheduler.main(_arm_args(tmp_path, now, plan_id, confirm="wrong"))
    assert code == 2
    assert json.loads(capsys.readouterr().out)["error"] == "confirmation_mismatch"
    code = scheduler.main(
        [
            *_global_args(tmp_path, now, "arm"),
            "--plan-id",
            "wrong",
            "--confirm",
            "wrong",
            "--operator",
            "alice",
            "--reason",
            "test",
        ]
    )
    assert code == 2
    assert json.loads(capsys.readouterr().out)["error"] == "plan_id_mismatch"


def test_an_expired_plan_cannot_be_armed(tmp_path, monkeypatch, capsys):
    now = datetime.now().astimezone().replace(hour=2, minute=15, second=0, microsecond=0)
    identity = _prepare_ready(tmp_path, now)
    monkeypatch.setattr(scheduler, "_idle", lambda: _FakeIdle(_idle(now)))
    monkeypatch.setattr(scheduler, "_current_boot_id", lambda: "boot-1")
    rows = json.loads("[" + ",".join((tmp_path / "telemetry.jsonl").read_text().splitlines()) + "]")
    rows.append(_row(identity, _idle(now), "n3"))
    _write_spool(tmp_path / "telemetry.jsonl", rows)
    assert scheduler.main(_global_args(tmp_path, now, "plan")) == 0
    plan_id = json.loads(capsys.readouterr().out)["plan"]["plan_id"]

    assert scheduler.main(_arm_args(tmp_path, now + timedelta(seconds=601), plan_id)) == 2
    assert json.loads(capsys.readouterr().out)["error"] == "plan_expired"


def test_a_busy_signal_drains_an_armed_window(tmp_path, monkeypatch, capsys):
    now = datetime.now().astimezone().replace(hour=2, minute=15, second=0, microsecond=0)
    identity = _prepare_ready(tmp_path, now)
    monkeypatch.setattr(scheduler, "_idle", lambda: _FakeIdle(_idle(now)))
    monkeypatch.setattr(scheduler, "_current_boot_id", lambda: "boot-1")
    rows = json.loads("[" + ",".join((tmp_path / "telemetry.jsonl").read_text().splitlines()) + "]")
    rows.append(_row(identity, _idle(now), "n3"))
    _write_spool(tmp_path / "telemetry.jsonl", rows)
    assert scheduler.main(_global_args(tmp_path, now, "plan")) == 0
    plan_id = json.loads(capsys.readouterr().out)["plan"]["plan_id"]
    assert scheduler.main(_arm_args(tmp_path, now, plan_id)) == 0
    capsys.readouterr()

    later = now + timedelta(minutes=1)
    monkeypatch.setattr(scheduler, "_idle", lambda: _FakeIdle(_idle(later)))
    rows.append(_row(identity, _idle(later, interactive=1), "n4"))
    _write_spool(tmp_path / "telemetry.jsonl", rows)
    _observer(tmp_path / "wg.json", later, identity["wireguard_public_key_b64"])

    assert scheduler.main(_global_args(tmp_path, later, "plan")) == 2
    drained = json.loads(capsys.readouterr().out)
    assert drained["state"] == "CLOSED"
    assert "interactive_sessions_busy" in drained["reasons"]
    assert scheduler.load_state(tmp_path / "state")["state"] == "CLOSED"


def test_arm_refuses_busy_evidence(tmp_path, monkeypatch, capsys):
    now = datetime.now().astimezone().replace(hour=2, minute=15, second=0, microsecond=0)
    identity = _prepare_ready(tmp_path, now)
    monkeypatch.setattr(scheduler, "_idle", lambda: _FakeIdle(_idle(now)))
    monkeypatch.setattr(scheduler, "_current_boot_id", lambda: "boot-1")
    rows = json.loads("[" + ",".join((tmp_path / "telemetry.jsonl").read_text().splitlines()) + "]")
    rows.append(_row(identity, _idle(now), "n3"))
    _write_spool(tmp_path / "telemetry.jsonl", rows)
    assert scheduler.main(_global_args(tmp_path, now, "plan")) == 0
    plan_id = json.loads(capsys.readouterr().out)["plan"]["plan_id"]

    rows.append(_row(identity, _idle(now, gpu=90.0), "n4"))
    _write_spool(tmp_path / "telemetry.jsonl", rows)
    assert scheduler.main(_arm_args(tmp_path, now, plan_id)) == 2
    assert "gpu_busy" in json.loads(capsys.readouterr().out)["error"]


def test_the_lease_window_is_capped_at_120_minutes_and_0500(tmp_path):
    local = datetime.now().astimezone()
    early = local.replace(hour=1, minute=0, second=0, microsecond=0)
    start, end = scheduler.lease_window(early)
    assert start.hour == 2 and end.hour == 4

    late = local.replace(hour=4, minute=30, second=0, microsecond=0)
    start, end = scheduler.lease_window(late)
    assert start.hour == 4 and end.hour == 5 and end.minute == 0

    with pytest.raises(scheduler.SchedulerError, match="outside_window"):
        scheduler.lease_window(local.replace(hour=5, minute=0, second=0, microsecond=0))


def test_plan_outside_the_window_is_refused(tmp_path, monkeypatch, capsys):
    now = datetime.now().astimezone().replace(hour=6, minute=0, second=0, microsecond=0)
    identity = _prepare_ready(tmp_path, now)
    monkeypatch.setattr(scheduler, "_idle", lambda: _FakeIdle(_idle(now)))
    monkeypatch.setattr(scheduler, "_current_boot_id", lambda: "boot-1")
    rows = json.loads("[" + ",".join((tmp_path / "telemetry.jsonl").read_text().splitlines()) + "]")
    rows.append(_row(identity, _idle(now), "n3"))
    _write_spool(tmp_path / "telemetry.jsonl", rows)

    assert scheduler.main(_global_args(tmp_path, now, "plan")) == 2
    output = json.loads(capsys.readouterr().out)
    assert output["reasons"] == ["outside_window"]
    assert scheduler.load_state(tmp_path / "state")["state"] == "DISARMED"


def test_a_modified_registry_is_refused(tmp_path):
    now = datetime.now(timezone.utc)
    path, document, _ = _registry(tmp_path, now)
    document["authorizations"][0]["signature_b64"] = "A" * 88
    path.write_text(json.dumps(document))
    with pytest.raises(scheduler.SchedulerError, match="registry_bad_signature"):
        scheduler.load_registry(path, now=now)


def test_observer_is_fail_closed(tmp_path):
    now = datetime.now(timezone.utc)
    key = _key(1)
    nodes = [
        {
            "fingerprint": "f" * 64,
            "node_id": "agx64",
            "role": "peer",
            "wireguard_public_key_b64": key,
            "overlay_ipv4": "10.100.0.2",
        }
    ]
    path = tmp_path / "wg.json"
    assert scheduler.observer_evidence(path, nodes, now, current_boot_id="boot-1")["reasons"] == ["observer_missing"]

    _observer(path, now, key, previous=0, current=2 * 1024 * 1024)
    assert "wireguard_busy" in scheduler.observer_evidence(path, nodes, now, current_boot_id="boot-1")["reasons"]

    _observer(path, now, key, previous=100, current=50)
    assert (
        "observer_counter_reset" in scheduler.observer_evidence(path, nodes, now, current_boot_id="boot-1")["reasons"]
    )

    _observer(path, now, key)
    assert (
        "observer_boot_changed"
        in scheduler.observer_evidence(path, nodes, now, current_boot_id="other-boot")["reasons"]
    )

    _observer(path, now - timedelta(minutes=5), key)
    assert "observer_stale" in scheduler.observer_evidence(path, nodes, now, current_boot_id="boot-1")["reasons"]

    _observer(path, now, _key(2))
    assert "observer_peer_missing" in scheduler.observer_evidence(path, nodes, now, current_boot_id="boot-1")["reasons"]

    _observer(path, now + timedelta(minutes=10), key)
    assert "observer_from_future" in scheduler.observer_evidence(path, nodes, now, current_boot_id="boot-1")["reasons"]


def test_nonconsecutive_or_busy_samples_reset_the_gate():
    now = datetime.now(timezone.utc)
    idle = _idle(now)
    samples = [
        _idle(now - timedelta(minutes=12)),
        _idle(now - timedelta(minutes=5)),
        idle,
    ]
    evidence, reasons = scheduler._samples_reasons(samples, now=now, ignore_wireguard_errors=True)
    assert evidence and "sample_gap_too_long" in reasons

    samples = [_idle(now - timedelta(minutes=10)), _idle(now - timedelta(minutes=5)), _idle(now, gpu=6.0)]
    evidence, reasons = scheduler._samples_reasons(samples, now=now, ignore_wireguard_errors=True)
    assert any("gpu_busy" in reason for reason in reasons)


def test_arm_takes_a_fresh_master_sample(tmp_path, monkeypatch, capsys):
    now = datetime.now().astimezone().replace(hour=2, minute=15, second=0, microsecond=0)
    identity = _prepare_ready(tmp_path, now)
    monkeypatch.setattr(scheduler, "_current_boot_id", lambda: "boot-1")
    rows = json.loads("[" + ",".join((tmp_path / "telemetry.jsonl").read_text().splitlines()) + "]")
    rows.append(_row(identity, _idle(now), "n3"))
    _write_spool(tmp_path / "telemetry.jsonl", rows)
    monkeypatch.setattr(scheduler, "_idle", lambda: _FakeIdle(_idle(now)))
    assert scheduler.main(_global_args(tmp_path, now, "plan")) == 0
    plan_id = json.loads(capsys.readouterr().out)["plan"]["plan_id"]

    later = now + timedelta(seconds=90)
    monkeypatch.setattr(scheduler, "_idle", lambda: _FakeIdle(_idle(later, interactive=1)))
    assert scheduler.main(_arm_args(tmp_path, later, plan_id)) == 2
    assert "interactive_sessions_busy" in json.loads(capsys.readouterr().out)["error"]
    assert scheduler.load_state(tmp_path / "state")["state"] == "PROBING"


def test_malformed_peer_payload_breaks_the_gate(tmp_path):
    now = datetime.now(timezone.utc)
    _, _, identities = _registry(tmp_path, now)
    identity = identities["agx64"]
    rows = [
        _row(identity, _idle(now - timedelta(minutes=10)), "m1"),
        _row(identity, _idle(now - timedelta(minutes=5)), "m2"),
        _row(identity, _idle(now), "m3"),
    ]
    rows[1]["payload"] = {"idle": "not-an-object"}
    node = {
        "fingerprint": authz.fingerprint(identity),
        "node_id": "agx64",
        "role": "peer",
        "wireguard_public_key_b64": identity["wireguard_public_key_b64"],
        "overlay_ipv4": identity["overlay_ipv4"],
    }
    evidence = scheduler.peer_evidence(node, rows, now)
    assert evidence["idle"] is False
    assert "idle_missing" in evidence["reasons"]


def test_missing_telemetry_source_is_busy(tmp_path):
    now = datetime.now(timezone.utc)
    _, _, identities = _registry(tmp_path, now)
    identity = identities["agx64"]
    rows = [
        _row(identity, _idle(now - timedelta(minutes=10)), "s1"),
        _row(identity, _idle(now - timedelta(minutes=5)), "s2"),
        _row(identity, _idle(now), "s3"),
    ]
    rows[1]["source"] = ""
    node = {
        "fingerprint": authz.fingerprint(identity),
        "node_id": "agx64",
        "role": "peer",
        "wireguard_public_key_b64": identity["wireguard_public_key_b64"],
        "overlay_ipv4": identity["overlay_ipv4"],
    }
    evidence = scheduler.peer_evidence(node, rows, now)
    assert evidence["idle"] is False
    assert "telemetry_source_mismatch" in evidence["reasons"]


def test_duplicate_telemetry_nonce_is_busy(tmp_path):
    now = datetime.now(timezone.utc)
    _, _, identities = _registry(tmp_path, now)
    identity = identities["agx64"]
    rows = [
        _row(identity, _idle(now - timedelta(minutes=10)), "same"),
        _row(identity, _idle(now - timedelta(minutes=5)), "same"),
        _row(identity, _idle(now), "same"),
    ]
    nodes = [
        {
            "fingerprint": authz.fingerprint(identity),
            "node_id": "agx64",
            "role": "peer",
            "wireguard_public_key_b64": identity["wireguard_public_key_b64"],
            "overlay_ipv4": identity["overlay_ipv4"],
        }
    ]
    registry = {"document": {}, "nodes": nodes}
    _observer(tmp_path / "wg.json", now, identity["wireguard_public_key_b64"])
    evidence = scheduler.build_evidence(
        registry,
        rows,
        tmp_path / "wg.json",
        [_idle(now - timedelta(minutes=10)), _idle(now - timedelta(minutes=5)), _idle(now)],
        now,
        current_boot_id="boot-1",
    )
    assert "telemetry_replayed_nonce" in evidence["reasons"]


def test_the_scheduler_has_no_listener_surface_and_dispatch_is_gated():
    text = SCHEDULER.read_text()
    # Dispatch is allowed in 9G, but the scheduler still must not listen or
    # become a remote shell. The signer socket is the only socket operation.
    assert "HTTPServer" not in text
    assert "socket.bind" not in text
    assert ".listen(" not in text
    assert "os.system" not in text
    assert "no_active_lease" in text
    assert "sign-cluster-job" in text


def test_the_probe_timer_can_notify_but_never_arms() -> None:
    service = (ROLE_ROOT / "systemd" / "sparknet-nocturnal-probe.service").read_text()
    timer = (ROLE_ROOT / "systemd" / "sparknet-nocturnal-probe.timer").read_text()
    makefile = (ROLE_ROOT / "Makefile").read_text()
    exec_lines = "\n".join(line for line in service.splitlines() if line.startswith("ExecStart="))
    assert exec_lines and "arm" not in exec_lines.lower()
    assert " plan" not in exec_lines.lower()
    assert "Unit=sparknet-nocturnal-probe.service" in timer
    assert "status --notify" in makefile


def test_dispatch_refuses_without_an_armed_lease(tmp_path: Path) -> None:
    args = type(
        "Args",
        (),
        {
            "state_dir": str(tmp_path),
            "registry": str(tmp_path / "registry.json"),
            "job": str(tmp_path / "job.json"),
            "lease_id": None,
            "signer_socket": None,
            "timeout": 1,
        },
    )()
    with pytest.raises(scheduler.SchedulerError, match="no_active_lease"):
        scheduler._dispatch(args, datetime(2026, 11, 4, 2, 30, tzinfo=timezone.utc))


def test_dispatch_verifies_results_and_writes_the_aggregate(tmp_path: Path, monkeypatch) -> None:
    import hashlib
    import json

    now = datetime(2026, 11, 4, 2, 30, tzinfo=timezone.utc)
    master_id = "master-test"
    peer_id = "peer-test"
    master_root = tmp_path / "master"
    (master_root / "manifests").mkdir(parents=True)
    (master_root / "manifests" / "master-identity.json").write_text(json.dumps({"node_id": master_id}))
    monkeypatch.setattr(scheduler, "ROLE_ROOT", master_root)
    monkeypatch.setenv("SPARKNET_NODE_ID", master_id)

    master_private_b64, _master_public_b64 = authz.generate_keypair()
    peer_private_b64, peer_public_b64 = authz.generate_keypair()
    master_key = authz.private_key_from_b64(master_private_b64)
    peer_identity = {
        "node_id": peer_id,
        "role": "peer",
        "wireguard_public_key_b64": "cGVlci13aXJlZ3VhcmQta2V5",
        "overlay_ipv4": "10.77.0.22/32",
        "requested_capabilities": ["cluster-serve"],
    }
    entry = authz.sign_authorization(
        peer_identity,
        master_key,
        ["cluster-serve"],
        now=now,
        node_pubkey_b64=peer_public_b64,
    )
    registry = {
        "schema_version": "1.0",
        "master_public_key_b64": authz.public_key_b64(master_key.public_key()),
        "authorizations": [entry],
    }
    registry_path = tmp_path / "registry.json"
    registry_path.write_text(json.dumps(registry, indent=2))

    job = {
        "job_id": "job-dispatch-1",
        "conversation_id": "conv-1",
        "initiator_node_id": master_id,
        "created_at": "2026-11-04T02:00:00Z",
        "expires_at": "2026-11-04T03:00:00Z",
        "mode": "decompose",
        "prompt": "say hello",
        "subtasks": [{"node_id": peer_id, "subtask_id": "s1", "instruction": "say hello", "context_refs": []}],
    }
    job_path = tmp_path / "job.json"
    job_path.write_text(json.dumps(job))

    output = "hello"
    result = {
        "schema_version": "sparknet-nocturnal-result/1",
        "lease_id": "lease-1",
        "job_id": job["job_id"],
        "subtask_id": "s1",
        "participant_node_id": peer_id,
        "instruction_sha256": hashlib.sha256(b"say hello").hexdigest(),
        "output_sha256": hashlib.sha256(output.encode()).hexdigest(),
        "model": "test-model",
        "started_at": "2026-11-04T02:30:00Z",
        "ended_at": "2026-11-04T02:30:01Z",
        "coverage": {"answered": ["s1"], "missing": []},
        "output": output,
    }
    nocturnal = scheduler._nocturnal()
    signed_result = nocturnal.sign_result(result, peer_private_b64)
    result_sha = hashlib.sha256((json.dumps(signed_result, sort_keys=True, indent=2) + "\n").encode()).hexdigest()
    manifest = {
        "schema_version": nocturnal.MANIFEST_SCHEMA,
        "lease_id": "lease-1",
        "job_id": job["job_id"],
        "participant_node_id": peer_id,
        "subtasks": [{"subtask_id": "s1", "result_sha256": result_sha, "answered": True}],
        "model": "test-model",
        "corpus_digest": None,
        "started_at": result["started_at"],
        "ended_at": result["ended_at"],
        "coverage": result["coverage"],
        "created_at": "2026-11-04T02:30:02Z",
    }
    signed_manifest = nocturnal.sign_manifest(manifest, peer_private_b64)

    class FakeSigner:
        def __init__(self, *_args, **_kwargs):
            pass

        def sign_job(self, payload):
            return {**payload, "signature_b64": "fake"}

    def fake_http(url, payload=None, *, timeout=30.0):
        if url.endswith("/v1/cluster/submit"):
            return 200, {"ok": True, "job_id": job["job_id"], "status": "accepted"}
        if "/status/" in url:
            return 200, {"ok": True, "status": "completed"}
        if "/result/" in url:
            return 200, {"ok": True, "result": {"results": [signed_result], "manifest": signed_manifest}}
        raise AssertionError(url)

    monkeypatch.setattr(scheduler, "SchedulerSigner", FakeSigner)
    monkeypatch.setattr(scheduler, "_http_json", fake_http)
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    state = scheduler.default_state()
    state["state"] = "ARMED"
    loaded = scheduler.load_registry(registry_path, now=now)
    state["lease"] = {
        "lease_id": "lease-1",
        "expires_at": "2026-11-04T03:00:00Z",
        "roster_digest": scheduler.roster_digest(loaded["nodes"]),
    }
    scheduler.save_state(state_dir, state, now)
    args = type(
        "Args",
        (),
        {
            "state_dir": str(state_dir),
            "registry": str(registry_path),
            "job": str(job_path),
            "lease_id": "lease-1",
            "signer_socket": None,
            "timeout": 5,
        },
    )()
    assert scheduler._dispatch(args, now) == 0
    aggregate = master_root / "01_Inbox" / "nocturnal" / "lease-1" / job["job_id"] / "aggregate.json"
    assert aggregate.is_file()
    assert json.loads(aggregate.read_text())["coverage"]["missing"] == []
