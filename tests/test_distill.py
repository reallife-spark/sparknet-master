"""The distillation scaffold: dataset selection, redaction and refusal."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROLE_ROOT = Path(__file__).resolve().parent.parent


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


distill = _load("sparknet_distill", ROLE_ROOT / "services" / "sparknet-distill.py")


def _trace(
    root: Path, *, model: str = "teacher", family: str = "qwen", prompt: str = "hello", response: str = "world"
) -> None:
    path = root / "traces" / "peer-1"
    path.mkdir(parents=True)
    (path / "one.jsonl").write_text(
        json.dumps(
            {
                "trace_id": "t-1",
                "model_id": model,
                "family": family,
                "prompt": prompt,
                "response": response,
                "created_at": "2026-11-01T00:00:00Z",
                "consent": True,
            }
        )
        + "\n"
    )


def test_dataset_selects_by_family_and_redacts_secrets(tmp_path: Path):
    _trace(tmp_path / "uplift", prompt="api_key=sk-secret", response="ok")
    config = {"teacher_model_id": "teacher", "family": "qwen", "data_window_days": 3650}
    manifest = distill.build_dataset(config, uplift=tmp_path / "uplift", state=tmp_path / "state")
    assert manifest["trace_count"] == 1
    assert manifest["redaction_report"]["redacted_rows"] >= 1
    train = (tmp_path / "state" / "datasets" / manifest["dataset_id"] / "train.jsonl").read_text()
    assert "sk-secret" not in train
    assert "[REDACTED]" in train


def test_dataset_excludes_a_different_family(tmp_path: Path):
    _trace(tmp_path / "uplift", family="llama")
    config = {"teacher_model_id": "teacher", "family": "qwen", "data_window_days": 3650}
    manifest = distill.build_dataset(config, uplift=tmp_path / "uplift", state=tmp_path / "state")
    assert manifest["trace_count"] == 0


def test_eval_rejects_below_threshold(tmp_path: Path):
    run = tmp_path / "state" / "runs" / "r1"
    run.mkdir(parents=True)
    metrics = tmp_path / "metrics.json"
    metrics.write_text(json.dumps({"held_out_teacher_agreement": 0.1}))
    result = distill.evaluate(
        "r1", metrics, state=tmp_path / "state", config={"thresholds": {"held_out_teacher_agreement": 0.5}}
    )
    assert result["approved"] is False
    assert result["failures"]


def test_redaction_masks_the_value_not_only_the_keyword(tmp_path: Path):
    _trace(
        tmp_path / "uplift",
        prompt="password: hunter2",
        response="-----BEGIN " + "PRIVATE KEY-----\nsecret\n-----END " + "PRIVATE KEY-----",
    )
    config = {"teacher_model_id": "teacher", "family": "qwen", "data_window_days": 3650}
    manifest = distill.build_dataset(config, uplift=tmp_path / "uplift", state=tmp_path / "state")
    train = (tmp_path / "state" / "datasets" / manifest["dataset_id"] / "train.jsonl").read_text()
    assert "hunter2" not in train
    assert "secret" not in train
    assert "[REDACTED PRIVATE KEY]" in train or "[REDACTED]" in train
