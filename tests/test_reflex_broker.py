"""The Master reflex broker: overlay-only, local, fail-open, no authority.

These tests pin the things that would turn a sensor into a liability: it refuses
a non-overlay bind, refuses a peer source in Phase 1, refuses a moving model tag,
and abstains on timeout, backend error or budget exhaustion. The audit line must
carry hashes, never state.

They also pin an absence. The broker once held a cloud credential and an egress
path behind a flag that defaulted to off; a flag can be turned on, so the cloud
leg was removed rather than disabled. `test_the_broker_has_no_egress_surface`
asserts the removal structurally, so restoring it is a deliberate act that fails
a test rather than a configuration change nobody reviews.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import ModuleType
from urllib import error as urlerror
from urllib import request as urlrequest

import pytest
from sparknet_loader import load_by_path

ROLE_ROOT = Path(__file__).resolve().parent.parent
BROKER_PATH = ROLE_ROOT / "services" / "sparknet-reflex-broker.py"
UNIT_PATH = ROLE_ROOT / "systemd" / "sparknet-reflex-broker.service"
PORTS = ROLE_ROOT.parent / "contracts" / "ports.json"

PINNED_MODEL = "qwen2.5-3b-32k"


@pytest.fixture(scope="module")
def broker() -> ModuleType:
    return load_by_path("sparknet_reflex_broker", BROKER_PATH)


def _request(broker: ModuleType, model: str = "local", node_id: str = "master") -> dict:
    return broker.reflex.make_request(
        "rag.relevance",
        "alpha",
        {"q": {"type": "noul", "instructions": "relevant?"}},
        model,
        "policy-1",
        node_id,
        "req-1",
    )


def _decide(broker: ModuleType, request: dict, tmp_path: Path, **kwargs) -> dict:
    common = {
        "timeout_s": 1.0,
        "budget": broker.BudgetLedger(),
        "audit_path": tmp_path / "a.jsonl",
    }
    common.update(kwargs)
    return broker.decide(request, **common)


def test_the_contract_declares_4224_overlay_only() -> None:
    ports = json.loads(PORTS.read_text())
    spec = ports["ports"]["4224"]
    assert spec["service"] == "reflex-broker"
    assert spec["bound_by"] == "master"
    assert spec["overlay_only"] is True
    assert spec["binds_to"] == "10.100.0.1"
    assert spec["implementation_state"] == "implemented"


def test_the_unit_binds_the_overlay_and_carries_no_credential() -> None:
    unit = UNIT_PATH.read_text()
    assert "10.100.0.1" in unit
    assert "4224" in unit
    assert "0.0.0.0" not in unit
    assert "--key-file" not in unit, "the cloud leg is gone, so the unit must not pass a credential"
    assert "ALLOW_EGRESS" not in unit
    assert "typesafe" not in unit.lower()


def test_the_broker_has_no_egress_surface(broker: ModuleType) -> None:
    """Nothing in this process can open a socket toward the internet.

    Asserted structurally: an HTTP client that is absent cannot be enabled by an
    environment variable, which is the property a defaulted-off flag never had.
    """
    source = BROKER_PATH.read_text()
    assert "urllib" not in source, "the broker must not carry an HTTP client"
    assert "api.typesafe.ai" not in source
    for name in ("read_key", "vendor_payload", "_vendor_backend", "DEFAULT_ENDPOINT", "validate_local_model"):
        assert not hasattr(broker, name), f"{name} survived the cloud-leg removal"
    assert "jev" not in broker.reflex.BACKENDS
    assert "broker" in broker.reflex.BACKENDS


def test_model_must_be_an_exact_tag(broker: ModuleType) -> None:
    assert broker.validate_model("local") == "local"
    assert broker.validate_model(PINNED_MODEL) == PINNED_MODEL
    assert broker.validate_model("bge-reranker-v2-m3") == "bge-reranker-v2-m3"
    for bad in ("", "   ", "latest", "jev-latest", "some-model:latest"):
        with pytest.raises(broker.BrokerError):
            broker.validate_model(bad)


def test_only_loopback_and_the_master_overlay_are_accepted(broker: ModuleType) -> None:
    assert broker.source_allowed("127.0.0.1") is True
    assert broker.source_allowed("10.100.0.1") is True
    assert broker.source_allowed("10.100.0.2") is False
    assert broker.source_allowed("0.0.0.0") is False


def test_decide_returns_a_decision_and_audits_hashes_only(broker: ModuleType, tmp_path: Path) -> None:
    req = _request(broker)
    req["state"] = "api_key=supersecret"
    audit = tmp_path / "reflex.jsonl"
    decision = broker.decide(
        req,
        call=lambda _r: {"type": "noul", "noul": 0.9},
        timeout_s=1.0,
        budget=broker.BudgetLedger(per_node_per_day=10, global_per_day=10),
        audit_path=audit,
        model_pin="local",
    )
    assert decision["verdict"] == "accept"
    line = audit.read_text()
    assert "supersecret" not in line
    assert "relevant?" not in line
    assert json.loads(line)["verdict"] == "accept"


def test_a_model_that_does_not_match_the_pin_is_refused(broker: ModuleType, tmp_path: Path) -> None:
    req = _request(broker, model="mistral-7b")
    with pytest.raises(broker.BrokerError, match="does not match"):
        _decide(broker, req, tmp_path, call=lambda _r: {"type": "noul", "noul": 0.9}, model_pin=PINNED_MODEL)


def test_the_local_sentinel_always_matches_the_pin(broker: ModuleType, tmp_path: Path) -> None:
    """`local` means "whatever this node runs", so it cannot mismatch a pin.

    The bridge sends the sentinel by default; refusing it would make the ordinary
    request shape unanswerable and the pin a denial-of-service on its own fabric.
    """
    decision = _decide(
        broker,
        _request(broker, model="local"),
        tmp_path,
        call=lambda _r: {"type": "noul", "noul": 0.9},
        model_pin=PINNED_MODEL,
    )
    assert decision["verdict"] == "accept"


def test_offline_abstains_without_calling_the_backend(broker: ModuleType, tmp_path: Path) -> None:
    called = []

    def call(_r):
        called.append(1)
        return {"type": "noul", "noul": 0.9}

    decision = _decide(broker, _request(broker), tmp_path, call=call, offline=True)
    assert decision["verdict"] == "abstain"
    assert decision["_reason"] == "offline"
    assert called == []


def test_budget_exhaustion_abstains(broker: ModuleType, tmp_path: Path) -> None:
    budget = broker.BudgetLedger(per_node_per_day=1, global_per_day=10)
    budget.charge("n1")
    decision = _decide(
        broker,
        _request(broker, node_id="n1"),
        tmp_path,
        call=lambda _r: {"type": "noul", "noul": 0.9},
        budget=budget,
    )
    assert decision["_reason"] == "budget-exhausted"


def test_timeout_and_backend_error_abstain(broker: ModuleType, tmp_path: Path) -> None:
    def slow(_r):
        import time as _t

        _t.sleep(0.5)
        return {"type": "noul", "noul": 0.9}

    def boom(_r):
        raise RuntimeError("backend down")

    common = {"timeout_s": 0.05, "budget": broker.BudgetLedger(), "audit_path": tmp_path / "a.jsonl"}
    assert broker.decide(_request(broker), call=slow, **common)["_reason"] == "timeout"
    assert broker.decide(_request(broker), call=boom, **common)["_reason"] == "backend-error"


def test_check_posture_reports_no_credential_surface(broker: ModuleType, capsys) -> None:
    assert broker.main(["--check", "--bind", "127.0.0.1"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["service"] == "reflex-broker"
    assert "credential" not in payload
    assert "endpoint" not in payload
    assert "allow_egress" not in payload


def test_the_credential_flag_is_gone(broker: ModuleType) -> None:
    """`--key-file` is not accepted, so an old unit fails loudly instead of silently."""
    with pytest.raises(SystemExit):
        broker.main(["--check", "--key-file", "/nonexistent/key"])


def test_healthz_says_nothing_and_decide_serves(broker: ModuleType, tmp_path: Path) -> None:
    listener = broker.serve(
        "127.0.0.1",
        0,
        timeout_s=1.0,
        budget=broker.BudgetLedger(),
        audit_path=tmp_path / "a.jsonl",
        model_pin="local",
        offline=True,
        call=None,
    )
    listener.start()
    base = f"http://127.0.0.1:{listener.servers[0].server_address[1]}"
    try:
        with urlrequest.urlopen(base + "/healthz", timeout=2) as response:
            assert response.status == 200
            assert json.loads(response.read())["ok"] is True

        body = json.dumps(_request(broker)).encode()
        req = urlrequest.Request(
            base + "/v1/reflex/decide",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlrequest.urlopen(req, timeout=2) as response:
            decision = json.loads(response.read())
        assert decision["verdict"] == "abstain"
        assert decision["_reason"] == "offline"

        with pytest.raises(urlerror.HTTPError) as exc:
            urlrequest.urlopen(base + "/nope", timeout=2)
        assert exc.value.code == 404
    finally:
        listener.stop()


def test_the_default_backend_is_local(broker: ModuleType, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SPARKNET_REFLEX_BACKEND", "local")
    decision = _decide(broker, _request(broker, model="local"), tmp_path, call=lambda _r: {"type": "noul", "noul": 0.9})
    assert decision["verdict"] == "accept"
    assert decision["backend"] == "local-rerank"


def _relevance(broker: ModuleType, state: object, model: str = "local") -> dict:
    return broker.reflex.make_request(
        "rag.relevance",
        state,
        {"relevant": {"type": "noul", "instructions": "relevant?"}},
        model,
        "policy-1",
        "master",
        "req-1",
    )


def test_local_rerank_accepts_coverage_and_abstains_on_silence(broker: ModuleType, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SPARKNET_REFLEX_BACKEND", "local")

    covering = _decide(
        broker, _relevance(broker, {"query": "guard nonce", "chunk": "the guard envelope nonce expired"}), tmp_path
    )
    assert covering["verdict"] == "accept"
    assert covering["backend"] == "local-rerank"

    silent = _decide(broker, _relevance(broker, {"query": "guard nonce", "chunk": "a recipe for soup"}), tmp_path)
    assert silent["verdict"] == "abstain"
    assert silent["_reason"] == "low-signal", "no coverage is no signal, never a confident reject"

    malformed = _decide(broker, _relevance(broker, "alpha"), tmp_path)
    assert malformed["verdict"] == "abstain"
    assert malformed["_reason"] == "low-signal"


def test_a_local_backend_failure_abstains_and_never_rejects(broker: ModuleType, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SPARKNET_REFLEX_BACKEND", "local-llm")
    monkeypatch.delenv("SPARKNET_REFLEX_LOCAL_MODEL", raising=False)
    monkeypatch.delenv("SPARKNET_LOCAL_MODEL", raising=False)

    decision = _decide(broker, _request(broker, model="local"), tmp_path)
    assert decision["verdict"] == "abstain"
    assert decision["_reason"] == "backend-error"


def test_an_off_backend_abstains_without_calling_anything(broker: ModuleType, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SPARKNET_REFLEX_BACKEND", "off")
    monkeypatch.setattr(broker, "_local_backend", lambda _r: pytest.fail("an off backend must not be consulted"))
    decision = _decide(broker, _relevance(broker, {"query": "guard", "chunk": "guard"}), tmp_path)
    assert decision["verdict"] == "abstain"
    assert decision["_reason"] == "offline"


def test_a_broker_selector_is_local_too(broker: ModuleType, tmp_path: Path, monkeypatch) -> None:
    """`broker` names this process's own kind: local, not a route off the fabric."""
    monkeypatch.setenv("SPARKNET_REFLEX_BACKEND", "broker")
    assert broker.backend_posture() == "broker"
    assert broker.reflex.backend_from_env("rag.relevance") == "broker"


def test_main_accepts_a_local_model(broker: ModuleType, monkeypatch, capsys) -> None:
    monkeypatch.setenv("SPARKNET_REFLEX_BACKEND", "local")
    monkeypatch.setenv("SPARKNET_REFLEX_MODEL", "local")
    assert broker.main(["--check"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["backend"] == "local"
    assert payload["model"] == "local"


def test_main_refuses_a_moving_model_tag(broker: ModuleType, monkeypatch, capsys) -> None:
    monkeypatch.setenv("SPARKNET_REFLEX_MODEL", "some-model:latest")
    assert broker.main(["--check"]) == 2
    assert "latest" in capsys.readouterr().err
