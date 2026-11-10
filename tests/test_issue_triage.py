"""The Master-local triage CLI writes append-only history and a derived view."""

from __future__ import annotations

import json
from pathlib import Path
from types import ModuleType

import pytest
from sparknet_loader import load_by_path

ROLE_ROOT = Path(__file__).resolve().parent.parent
TRIAGE_PATH = ROLE_ROOT / "scripts" / "sparknet-issue-triage.py"
NODE = "sparknet-node-0002"


def _load(name: str, path: Path) -> ModuleType:
    return load_by_path(name, path)


triage = _load("sparknet_issue_triage_test", TRIAGE_PATH)


def test_transition_writes_ledger_and_view(tmp_path: Path) -> None:
    row = triage.transition(
        state_dir=tmp_path / "state",
        node_id=NODE,
        issue_id="fix-token",
        status="triaged",
        labels=["ready-for-agent"],
        actor="operator",
        note="reproduced",
    )
    assert row["status"] == "triaged"
    ledger = tmp_path / "state" / "issues" / "triage.jsonl"
    view = tmp_path / "state" / "issues" / "triage.json"
    assert ledger.is_file() and view.is_file()
    assert json.loads(ledger.read_text().splitlines()[0])["labels"] == ["ready-for-agent"]
    assert json.loads(view.read_text())[f"{NODE}:fix-token"]["note"] == "reproduced"


def test_cli_reports_json_and_refuses_empty_transition(tmp_path: Path, capsys) -> None:
    assert (
        triage.main(
            [
                "--state-dir",
                str(tmp_path / "state"),
                "--node-id",
                NODE,
                "--issue-id",
                "fix-token",
                "--status",
                "in-progress",
                "--json",
            ]
        )
        == 0
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "in-progress"
    with pytest.raises(SystemExit) as exc:
        triage.main(
            [
                "--state-dir",
                str(tmp_path / "state"),
                "--node-id",
                NODE,
                "--issue-id",
                "fix-token",
            ]
        )
    assert exc.value.code == 2
