"""Evidence capture and review-agent operator paths (Steps 11-12).

Capture is tested end to end against a temporary evidence git repository and a
fake signer: the event file, its digest in the ledger receipt, and the git commit
must agree. The review tests pin findings and reversible trust records, which do
not write the registry or alter evidence.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

SERVICES = Path(__file__).resolve().parent.parent / "services"
EVENT = {
    "event_type": "share-access",
    "who": "peer-a",
    "what": "read page",
    "when": "2026-10-29T00:00:00Z",
    "grant_id": "g1",
    "node_pair": "a-b",
    "share_type": "knowledge",
}


def _load(name: str, filename: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, SERVICES / filename)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    return module


@pytest.fixture(scope="module")
def capture() -> ModuleType:
    return _load("test_evidence_capture", "sparknet-evidence-capture.py")


@pytest.fixture(scope="module")
def review() -> ModuleType:
    return _load("test_review_agents", "sparknet-review-agents.py")


def _git_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "evidence-repo"
    repo.mkdir()
    (repo / "RETENTION.md").write_text("retain\n", encoding="utf-8")
    for command in (
        ["git", "-C", str(repo), "init"],
        ["git", "-C", str(repo), "config", "user.email", "evidence@example.invalid"],
        ["git", "-C", str(repo), "config", "user.name", "evidence-test"],
        ["git", "-C", str(repo), "add", "."],
        ["git", "-C", str(repo), "commit", "-m", "init"],
    ):
        subprocess.run(command, check=True, capture_output=True, text=True)
    return repo


def _fake_signer(calls: list[dict]):
    def sign(evidence: dict) -> dict:
        calls.append(evidence)
        return {"ok": True, "ledger_block": "a" * 64, "content_sha256": evidence["content_sha256"]}

    return sign


def test_capture_writes_the_event_and_commits_it_after_the_ledger(capture: ModuleType, tmp_path: Path) -> None:
    repo = _git_repo(tmp_path)
    calls: list[dict] = []
    service = capture.EvidenceCapture(repo, signer=_fake_signer(calls), git_commit=True)
    receipt = service.capture_event(EVENT)

    event_file = Path(receipt["path"])
    assert event_file.is_file()
    stored = json.loads(event_file.read_text())
    assert stored["event_type"] == EVENT["event_type"]
    assert stored["what"] == EVENT["what"]
    assert "captured_at" in stored
    assert calls and calls[0]["content_sha256"] == receipt["content_sha256"]
    assert receipt["committed"] is True

    tracked = subprocess.run(
        ["git", "-C", str(repo), "ls-files", "--error-unmatch", str(event_file.relative_to(repo))],
        check=True,
        capture_output=True,
        text=True,
    )
    assert tracked.stdout.strip() == str(event_file.relative_to(repo))


def test_capture_refuses_an_incomplete_event(capture: ModuleType, tmp_path: Path) -> None:
    repo = _git_repo(tmp_path)
    calls: list[dict] = []
    service = capture.EvidenceCapture(repo, signer=_fake_signer(calls), git_commit=False)
    with pytest.raises(capture.EvidenceError, match="missing"):
        service.capture_event({"event_type": "share-access"})
    assert calls == []
    assert not list((repo / "events").glob("*.json"))


def test_capture_without_a_signer_removes_the_file(capture: ModuleType, tmp_path: Path) -> None:
    repo = _git_repo(tmp_path)
    service = capture.EvidenceCapture(repo, signer=None, git_commit=False)
    with pytest.raises(capture.EvidenceError, match="no-signer"):
        service.capture_event(EVENT)
    assert not list((repo / "events").glob("*.json"))


def test_a_captured_event_cannot_choose_its_filename(capture: ModuleType, tmp_path: Path) -> None:
    repo = _git_repo(tmp_path)
    receipt = capture.EvidenceCapture(repo, signer=_fake_signer([]), git_commit=False).capture_event(
        {**EVENT, "event_type": "../../escape"}
    )
    event_file = Path(receipt["path"])
    assert event_file.parent == repo / "events"
    assert "escape" in event_file.name
    assert ".." not in event_file.name


def test_a_dry_run_writes_nothing(capture: ModuleType, tmp_path: Path, capsys) -> None:
    repo = _git_repo(tmp_path)
    event_file = tmp_path / "event.json"
    event_file.write_text(json.dumps(EVENT))
    assert capture.main(["--event", str(event_file), "--evidence-repo", str(repo), "--dry-run"]) == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["dry_run"] is True
    assert not list((repo / "events").glob("*.json"))


def test_review_produces_a_finding_without_touching_the_event(review: ModuleType, tmp_path: Path) -> None:
    agent = review.ReviewAgent(evidence_repo=tmp_path, registry_path=tmp_path / "registry.json")
    original = dict(EVENT)
    finding = agent.produce_finding(EVENT)
    assert finding["event_type"] == EVENT["event_type"]
    assert finding["evidence_preserved"] is True
    assert original == EVENT


def test_review_trust_transition_is_reversible_and_preserves_the_flag(review: ModuleType, tmp_path: Path) -> None:
    agent = review.ReviewAgent(evidence_repo=tmp_path, registry_path=tmp_path / "registry.json")
    transition = agent.transition_trust("node-a", "flagged", "review-needed")
    assert transition["node_id"] == "node-a"
    assert transition["level"] == "flagged"
    assert transition["previous_level"] == "flagged"
    assert transition["reversible"] is True
    assert transition["flag_preserved"] is True
    with pytest.raises(ValueError, match="invalid trust level"):
        agent.transition_trust("node-a", "trusted", "typo")


def test_review_repo_produces_one_finding_per_event_without_writing(review: ModuleType, tmp_path: Path) -> None:
    events = tmp_path / "events"
    events.mkdir()
    first = events / "one.json"
    second = events / "two.json"
    first.write_text(json.dumps(EVENT))
    second.write_text(json.dumps({**EVENT, "event_type": "share-close"}))
    before = {path.name: path.read_bytes() for path in events.glob("*.json")}

    findings = review.ReviewAgent(evidence_repo=tmp_path, registry_path=tmp_path / "registry.json").review_repo()

    assert len(findings) == 2
    assert {finding["event_type"] for finding in findings} == {"share-access", "share-close"}
    assert all(finding["evidence_preserved"] for finding in findings)
    assert {path.name: path.read_bytes() for path in events.glob("*.json")} == before


def test_verify_repo_matches_files_to_the_signed_ledger(capture: ModuleType, tmp_path: Path) -> None:
    repo = _git_repo(tmp_path)
    receipt = capture.EvidenceCapture(repo, signer=_fake_signer([]), git_commit=False).capture_event(EVENT)
    ledger = tmp_path / "ledger.json"
    ledger.write_text(
        json.dumps(
            {
                "blocks": [
                    {
                        "data": {
                            "event": "share_evidence",
                            "content_sha256": receipt["content_sha256"],
                        }
                    }
                ]
            }
        )
    )
    service = capture.EvidenceCapture(repo, signer=None, git_commit=False)
    assert service.verify_repo(ledger)["ok"] is True

    Path(receipt["path"]).write_text("{}\n")
    report = service.verify_repo(ledger)
    assert report["ok"] is False
    assert report["missing"] == [receipt["content_sha256"]]
