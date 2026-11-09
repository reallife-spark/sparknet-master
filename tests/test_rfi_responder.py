"""The Master responder answers only from the allow-listed fabric corpus."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SERVICE = REPO_ROOT / "master-node" / "services" / "sparknet-rfi-responder.py"


def _load() -> object:
    spec = importlib.util.spec_from_file_location("sparknet_rfi_responder_test", SERVICE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_a_contract_question_returns_only_contract_sources() -> None:
    module = _load()
    answer, sources = module.search(REPO_ROOT, "authority capability registry", ["contracts"])
    assert "contracts/" in answer
    assert sources == ["contracts"]


def test_a_scope_with_no_fabric_category_returns_an_empty_answer() -> None:
    module = _load()
    answer, sources = module.search(REPO_ROOT, "anything", ["05_Knowledge"])
    assert answer == ""
    assert sources == []


def test_the_corpus_never_contains_personal_pages() -> None:
    module = _load()
    policy = module.corpus_policy()
    entries = policy.corpus_entries(REPO_ROOT, policy.FABRIC_ROOTS)
    for rel in entries:
        parts = rel.parts
        assert not any(
            part in {"00_System", "02_Daily", "03_Sources", "sessions", "_raw", "_staging"} for part in parts
        )
        assert rel.name not in {"user.md", "MEMORY.md", "secrets-index.json"}


def test_dry_run_processes_a_verified_request_without_signing(tmp_path: Path) -> None:
    module = _load()
    authz = module.authz()
    request = authz.build_rfi_request(
        request_id="RFI-TEST-1",
        peer_fingerprint="a" * 64,
        question="How does authority work in the registry?",
        scope=["contracts"],
    )
    request_dir = tmp_path / "requests"
    processed = tmp_path / "processed"
    request_dir.mkdir(parents=True, exist_ok=True)
    (request_dir / "request.json").write_text(json.dumps(request))
    results = module.process_once(
        request_dir=request_dir,
        processed_dir=processed,
        root=REPO_ROOT,
        offline=False,
        socket_path=None,
        url=None,
        registry=None,
        dry_run=True,
        limit=5,
    )
    assert results and results[0]["dry_run"] is True
    assert "contracts/" in results[0]["answer"]
    assert results[0]["sources"] == ["contracts"]


def test_item_names_are_single_safe_components() -> None:
    module = _load()
    assert "/" not in module.safe_item_name("../../RFI 1")
    assert module.safe_item_name("../../RFI 1").endswith(".md")


def test_a_verified_request_is_moved_after_a_successful_compose(tmp_path: Path, monkeypatch) -> None:
    module = _load()
    authz = module.authz()
    request = authz.build_rfi_request(
        request_id="RFI-TEST-2",
        peer_fingerprint="b" * 64,
        question="What is the registry?",
        scope=["contracts"],
    )
    request_dir = tmp_path / "requests"
    processed = tmp_path / "processed"
    request_dir.mkdir()
    (request_dir / "request.json").write_text(json.dumps(request))
    fake = tmp_path / "composer.sh"
    fake.write_text("#!/bin/sh\nexit 0\n")
    fake.chmod(0o755)
    monkeypatch.setattr(module, "COMPOSER", fake)
    results = module.process_once(
        request_dir=request_dir,
        processed_dir=processed,
        root=REPO_ROOT,
        offline=True,
        socket_path=None,
        url=None,
        registry=None,
        dry_run=False,
        limit=5,
    )
    assert results and results[0]["returncode"] == 0
    assert not (request_dir / "request.json").exists()
    assert (processed / "request.json").is_file()
