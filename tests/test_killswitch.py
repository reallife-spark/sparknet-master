from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest
from sparknet_loader import load_by_path

ROLE_ROOT = Path(__file__).resolve().parent.parent
SERVICES = ROLE_ROOT / "services"
SCRIPT = SERVICES / "sparknet-killswitch.py"
PEER_ROOT = ROLE_ROOT.parent / "peer-node"


def _module():
    return load_by_path("sparknet_killswitch", SCRIPT)


@pytest.fixture()
def killswitch():
    return _module()


def test_killswitch_is_root_gated(killswitch, monkeypatch, capsys):
    monkeypatch.setattr(killswitch.os, "geteuid", lambda: 1000)
    monkeypatch.setenv("SPARKNET_WG_INTERFACE", "wg0")

    assert killswitch.main(["--force"]) == 1
    assert "root required" in capsys.readouterr().err


def test_killswitch_refuses_to_guess_the_overlay(killswitch, monkeypatch, capsys):
    monkeypatch.setattr(killswitch.os, "geteuid", lambda: 0)
    monkeypatch.delenv("SPARKNET_WG_INTERFACE", raising=False)

    assert killswitch.main(["--force"]) == 1
    assert "SPARKNET_WG_INTERFACE is not set" in capsys.readouterr().err


def test_dry_run_is_the_default_and_changes_nothing(killswitch, monkeypatch, capsys):
    monkeypatch.setattr(killswitch.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SPARKNET_WG_INTERFACE", "wg0")
    called = []
    monkeypatch.setattr(killswitch, "execute", lambda actions: called.append(actions))

    assert killswitch.main([]) == 0
    out = capsys.readouterr().out
    assert "DRY-RUN" in out
    assert "systemctl disable --now sparknet-master-signer.service" not in out
    assert "stop and disable sparknet-master-signer.service" in out
    assert called == []


def test_force_executes_the_containment_sequence(killswitch, monkeypatch, capsys):
    monkeypatch.setattr(killswitch.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SPARKNET_WG_INTERFACE", "wg0")
    seen = []

    def fake_execute(actions):
        seen.extend(actions)
        return killswitch.Report(performed=[action.summary for action in actions])

    monkeypatch.setattr(killswitch, "execute", fake_execute)

    assert killswitch.main(["--force"]) == 0
    summaries = [action.summary for action in seen]
    assert summaries[0] == "stop and disable sparknet-master-signer.service"
    assert any("sparknet-master-wireguard-anchor.service" in line for line in summaries)
    assert any("sparknet-admin-webui" in line for line in summaries)
    assert any(action.argv == ("ip", "link", "del", "wg0") for action in seen)
    assert summaries[-1] == "insert the SPARKNET_EMERG_FWD jump"
    assert "ENGAGING cluster containment" in capsys.readouterr().out


def test_every_control_plane_is_stopped_before_the_overlay(killswitch):
    actions = killswitch.build_actions("wg0")
    summaries = [action.summary for action in actions]
    overlay = next(index for index, action in enumerate(actions) if action.argv == ("ip", "link", "del", "wg0"))
    for unit in killswitch.CONTROL_UNITS:
        assert any(unit in line for line in summaries[:overlay])
    assert "sparknet-master-wireguard-anchor.service" in " ".join(summaries[:overlay])


def test_admin_container_does_not_restart_after_a_daemon_restart(killswitch):
    actions = killswitch.build_actions("wg0")
    update = next(action for action in actions if action.argv[:2] == ("docker", "update"))
    assert update.argv == ("docker", "update", "--restart=no", killswitch.ADMIN_CONTAINER)
    assert ("docker", "stop", killswitch.ADMIN_CONTAINER) in [action.argv for action in actions]


def test_firewall_policy_drops_the_cluster_without_flushing_the_host(killswitch):
    actions = killswitch.build_actions("wg0")
    argvs = [action.argv for action in actions]

    assert ("iptables", "-A", killswitch.CHAIN_IN, "-i", "wg0", "-j", "DROP") in argvs
    assert (
        "iptables",
        "-A",
        killswitch.CHAIN_IN,
        "!",
        "-i",
        "lo",
        "-p",
        "tcp",
        "-m",
        "multiport",
        "--dports",
        killswitch.control_port_set(),
        "-j",
        "DROP",
    ) in argvs
    assert (
        "iptables",
        "-A",
        killswitch.CHAIN_IN,
        "!",
        "-i",
        "lo",
        "-p",
        "udp",
        "--dport",
        str(killswitch.WIREGUARD_UDP_PORT),
        "-j",
        "DROP",
    ) in argvs
    assert ("iptables", "-A", killswitch.CHAIN_OUT, "-o", "wg0", "-j", "DROP") in argvs
    assert ("iptables", "-A", killswitch.CHAIN_FWD, "-j", "DROP") in argvs
    assert ("iptables", "-I", "INPUT", "1", "-j", killswitch.CHAIN_IN) in argvs
    assert ("iptables", "-I", "OUTPUT", "1", "-j", killswitch.CHAIN_OUT) in argvs
    assert ("iptables", "-I", "FORWARD", "1", "-j", killswitch.CHAIN_FWD) in argvs
    assert not any("-P" in argv for argv in argvs), "built-in policies must not change"
    assert ("iptables", "-F") not in argvs, "never flush the whole host ruleset"
    for port in killswitch.CONTROL_TCP_PORTS:
        assert str(port) in killswitch.control_port_set()


def test_an_absent_iptables_chain_is_not_a_failure(killswitch):
    def runner(action):
        return subprocess.CompletedProcess(action.argv, 1, "", "iptables: No chain/target/match by that name.")

    report = killswitch.execute(
        [killswitch.Action("delete the chain", ("iptables", "-X", "OLD"))],
        runner=runner,
        out=lambda _line: None,
    )
    assert not report.ok, "a mandatory rule failure is still real"
    report = killswitch.execute(
        [killswitch.Action("delete the chain", ("iptables", "-X", "OLD"), optional=True)],
        runner=runner,
        out=lambda _line: None,
    )
    assert report.ok and report.absent == ["delete the chain"]


def test_a_performed_action_is_recorded_once(killswitch):
    def runner(action):
        return subprocess.CompletedProcess(action.argv, 0, "", "")

    report = killswitch.execute(
        [killswitch.Action("stop the signer", ("systemctl", "stop", "signer"))],
        runner=runner,
        out=lambda _line: None,
    )
    assert report.ok
    assert report.performed == ["stop the signer"]


def test_a_missing_optional_service_does_not_stop_containment(killswitch):
    calls = []

    def runner(action):
        calls.append(action.summary)
        return subprocess.CompletedProcess(action.argv, 0, "", "")

    actions = [
        killswitch.Action("stop a missing unit", ("systemctl", "stop", "missing"), optional=True),
        killswitch.Action("remove the overlay", ("ip", "link", "del", "wg0")),
    ]
    report = killswitch.execute(actions, runner=runner, out=lambda _line: None)
    assert report.ok
    assert calls == ["stop a missing unit", "remove the overlay"]


def test_an_absent_optional_target_is_not_a_failure(killswitch):
    def runner(action):
        return subprocess.CompletedProcess(action.argv, 5, "", "Unit missing.service not found.")

    report = killswitch.execute(
        [killswitch.Action("stop a missing unit", ("systemctl", "stop", "missing.service"), optional=True)],
        runner=runner,
        out=lambda _line: None,
    )
    assert report.ok
    assert report.absent == ["stop a missing unit"]


def test_a_real_optional_failure_is_not_excused(killswitch):
    def runner(action):
        return subprocess.CompletedProcess(action.argv, 1, "", "Access denied")

    report = killswitch.execute(
        [killswitch.Action("stop the signer", ("systemctl", "stop", "signer"), optional=True)],
        runner=runner,
        out=lambda _line: None,
    )
    assert not report.ok
    assert "stop the signer" in report.failures[0]


def test_a_failed_mandatory_action_is_reported(killswitch):
    def runner(action):
        return subprocess.CompletedProcess(action.argv, 2, "", "nft: permission denied")

    report = killswitch.execute(
        [killswitch.Action("install nft", ("nft", "-f", "-"))],
        runner=runner,
        out=lambda _line: None,
    )
    assert not report.ok
    assert "install nft" in report.failures[0]
    assert "permission denied" in report.failures[0]


def test_the_peer_has_no_killswitch_to_invoke():
    assert not (PEER_ROOT / "services" / "sparknet-killswitch.py").exists()
    peer_makefile = (PEER_ROOT / "Makefile").read_text()
    assert not re.search(r"^killswitch:", peer_makefile, re.MULTILINE)
