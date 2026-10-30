"""Step 9C: the scheduler is a fail-closed lease state machine, never a dispatcher."""

from __future__ import annotations

import base64
import importlib.util
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType

import pytest

ROLE_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = ROLE_ROOT.parent
SCHEDULER = ROLE_ROOT / "services" / "sparknet-scheduler.py"
AUTHZ = REPO_ROOT / "shared" / "sparknet-authz.py"


def _load(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


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


def test_the_scheduler_has_no_dispatch_or_listener_surface():
    text = SCHEDULER.read_text()
    assert "import socket" not in text
    assert "subprocess" not in text
    assert "sign_" not in text
    assert "os.system" not in text
