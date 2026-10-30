"""Step 9C: the root observer reads counters, fails closed and keeps a bounded history."""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType

import pytest

ROLE_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROLE_ROOT / "services" / "sparknet-wg-observer.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("sparknet_wg_observer", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


observer = _load()


def _key(seed: int) -> str:
    return base64.b64encode(bytes([seed]) * 32).decode("ascii")


def _done(stdout: str = "", returncode: int = 0) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(["wg"], returncode, stdout=stdout, stderr="")


def _boot(tmp_path: Path) -> Path:
    path = tmp_path / "boot_id"
    path.write_text("boot-1\n")
    return path


def _runner(stdout: str = "", returncode: int = 0, interface: str = "wg1"):
    def run(argv, timeout=0):
        assert tuple(argv) == ("wg", "show", interface, "transfer")
        return _done(stdout, returncode)

    return run


def test_parse_transfer_keeps_one_row_per_peer_and_ignores_noise():
    rows = observer.parse_wg_transfer(f"{_key(1)}\t100\t50\n\n{_key(2)}\t0\t10\n")
    assert rows == [
        {"public_key_b64": _key(1), "rx_bytes": 100, "tx_bytes": 50},
        {"public_key_b64": _key(2), "rx_bytes": 0, "tx_bytes": 10},
    ]


@pytest.mark.parametrize(
    "text",
    [
        "not-a-key 1 2\n",
        f"{_key(1)} not-a-counter 2\n",
        f"{_key(1)} 1\n",
        f"{_key(1)} -1 2\n",
        f"{_key(1)} 1 2\n{_key(1)} 3 4\n",
    ],
)
def test_a_malformed_transfer_row_is_an_error_not_zero(text):
    with pytest.raises(observer.ObserverError):
        observer.parse_wg_transfer(text)


def test_one_sample_has_boot_time_interface_and_peers(tmp_path):
    now = datetime(2026, 10, 26, 2, 15, tzinfo=timezone.utc)
    snapshot = observer.observe(
        snapshot_path=tmp_path / "wg-observer.json",
        interface="wg1",
        run=_runner(f"{_key(1)}\t100\t50\n"),
        now=now,
        boot_id_path=_boot(tmp_path),
    )
    assert snapshot["boot_id"] == "boot-1"
    assert snapshot["sampled_at"] == "2026-10-26T02:15:00Z"
    assert snapshot["interface"] == "wg1"
    assert snapshot["peers"][0]["rx_bytes"] == 100
    assert snapshot["errors"] == []


def test_history_is_bounded_and_resets_on_interface_or_boot_change(tmp_path):
    path = tmp_path / "wg.json"
    now = datetime(2026, 10, 26, 2, 15, tzinfo=timezone.utc)
    for index in range(35):
        observer.observe(
            snapshot_path=path,
            interface="wg1",
            run=_runner(f"{_key(1)}\t{index}\t{index}\n"),
            now=now.replace(second=index % 60),
            boot_id_path=_boot(tmp_path),
            history_limit=30,
        )
    data = json.loads(path.read_text())
    assert len(data["history"]) == 30
    assert data["history"][-1]["peers"][0]["rx_bytes"] == 34

    observer.observe(
        snapshot_path=path,
        interface="wg0",
        run=_runner(f"{_key(1)}\t1\t1\n", interface="wg0"),
        now=now,
        boot_id_path=_boot(tmp_path),
    )
    changed = json.loads(path.read_text())
    assert changed["interface"] == "wg0"
    assert len(changed["history"]) == 1


def test_a_failed_read_is_written_as_an_error_snapshot(tmp_path):
    path = tmp_path / "wg.json"

    def broken(argv, timeout=0):
        return _done("not a key", returncode=0)

    with pytest.raises(observer.ObserverError):
        observer.observe(
            snapshot_path=path,
            interface="wg1",
            run=broken,
            now=datetime(2026, 10, 26, 2, 15, tzinfo=timezone.utc),
            boot_id_path=_boot(tmp_path),
        )
    data = json.loads(path.read_text())
    assert data["errors"] == ["wireguard_malformed"]
    assert data["peers"] == []


def test_snapshot_is_public_but_not_wildly_writable(tmp_path):
    path = tmp_path / "wg.json"
    observer.observe(
        snapshot_path=path,
        interface="wg1",
        run=_runner(f"{_key(1)}\t100\t50\n"),
        now=datetime(2026, 10, 26, 2, 15, tzinfo=timezone.utc),
        boot_id_path=_boot(tmp_path),
    )
    assert path.stat().st_mode & 0o777 == 0o644
    assert not (tmp_path / ".wg.json.tmp").exists()


def test_check_mode_does_not_write(tmp_path, capsys, monkeypatch):
    path = tmp_path / "wg.json"
    monkeypatch.setattr(observer, "resolve_interface", lambda: "wg1")
    monkeypatch.setattr(
        observer,
        "sample",
        lambda interface, now=None: (_ for _ in ()).throw(observer.ObserverError("wireguard_unreadable")),
    )
    assert (
        observer.main(
            [
                "--check",
                "--interface",
                "wg1",
                "--snapshot",
                str(path),
                "--now",
                "2026-10-26T02:15:00Z",
            ]
        )
        == 1
    )
    assert "wireguard" in capsys.readouterr().err
    assert not path.exists()


def test_no_interface_is_an_error(monkeypatch, tmp_path):
    monkeypatch.delenv("SPARKNET_WG_INTERFACE", raising=False)
    monkeypatch.setattr(observer, "DEFAULT_INTERFACES", ())
    with pytest.raises(observer.ObserverError, match="wireguard_interface_unset"):
        observer.observe(
            snapshot_path=tmp_path / "wg.json",
            interface=None,
            run=_runner(""),
            now=datetime(2026, 10, 26, 2, 15, tzinfo=timezone.utc),
            boot_id_path=_boot(tmp_path),
        )


def test_snapshot_file_contains_no_private_material(tmp_path):
    path = tmp_path / "wg.json"
    observer.observe(
        snapshot_path=path,
        interface="wg1",
        run=_runner(f"{_key(1)}\t100\t50\n"),
        now=datetime(2026, 10, 26, 2, 15, tzinfo=timezone.utc),
        boot_id_path=_boot(tmp_path),
    )
    text = path.read_text()
    assert "private" not in text.lower()
    assert oct(os.stat(path).st_mode & 0o777) == "0o644"
