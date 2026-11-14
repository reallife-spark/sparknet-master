#!/usr/bin/env python3
"""The Master's same-family distillation scaffold (operator-triggered).

This is deliberately a scaffold, not an autonomous trainer. It owns the dataset
manifest, the hardware/engine doctor, the run record and the model card; the
training command itself is an operator-supplied executable
(``SPARKNET_DISTILL_TRAINER``). That keeps the runtime allow-list free of
PyTorch, keeps the signer out of the trainer, and makes "no training ran" an
explicit state rather than a missing log line.

Commands::

    sparknet-distill.py dataset --config configs/distill.json
    sparknet-distill.py doctor  --config configs/distill.json
    sparknet-distill.py run     --config configs/distill.json [--execute]
    sparknet-distill.py eval    --run RUN_ID --metrics metrics.json
    sparknet-distill.py publish --run RUN_ID
    sparknet-distill.py status

A run is never started by data volume. It requires the operator's ``--execute``
and, for a signed record, the isolated signer socket.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shlex
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "shared"))
from sparknet_loader import load_by_path

SERVICE_DIR = Path(__file__).resolve().parent
ROLE_ROOT = SERVICE_DIR.parent
FABRIC_ROOT = ROLE_ROOT.parent
DEFAULT_CONFIG = ROLE_ROOT / "configs" / "distill.json"
DEFAULT_STATE = Path(os.environ.get("SPARKNET_DISTILL_STATE", "/srv/sparknet/distill"))
DEFAULT_UPLIFT = Path(os.environ.get("SPARKNET_UPLIFT_STATE", "/srv/sparknet/uplift"))
SECRET_ASSIGNMENT = re.compile(
    r"(?i)((?:api[_-]?key|secret|token|password|passwd|private[_-]?key)\s*[:=]\s*)([^\s,;]+)"
)
PRIVATE_KEY_BLOCK = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)
SECRET_PATTERNS = re.compile(r"(?i)(api[_-]?key|secret|token|password|passwd|private[_-]?key|BEGIN [A-Z ]*PRIVATE KEY)")


def _load(name: str, path: Path) -> Any:
    if not path.is_file():
        return None
    return load_by_path(name, path)


def authz() -> Any:
    return _load("sparknet_distill_authz", FABRIC_ROOT / "shared" / "sparknet-authz.py")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def load_config(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SystemExit(f"distill: {path} is not a JSON object")
    return data


def _trace_rows(uplift: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    root = uplift / "traces"
    if not root.is_dir():
        return rows
    for path in sorted(root.glob("*/*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if isinstance(row, dict):
                rows.append(row)
    return rows


def _redact(text: str) -> tuple[str, bool]:
    redacted = PRIVATE_KEY_BLOCK.sub("[REDACTED PRIVATE KEY]", text)
    redacted = SECRET_ASSIGNMENT.sub(r"\1[REDACTED]", redacted)
    changed = redacted != text or bool(SECRET_PATTERNS.search(redacted))
    return redacted, changed


def build_dataset(config: dict[str, Any], *, uplift: Path, state: Path) -> dict[str, Any]:
    teacher = str(config.get("teacher_model_id") or "")
    family = str(config.get("family") or "")
    window = int(config.get("data_window_days") or 30)
    cutoff = time.time() - window * 86400
    selected: list[dict[str, Any]] = []
    redactions = 0
    for row in _trace_rows(uplift):
        if row.get("consent") is not True:
            continue
        if teacher and row.get("model_id") != teacher:
            continue
        if family and row.get("family") != family:
            continue
        created = str(row.get("created_at") or "")
        if created:
            try:
                stamp = datetime.fromisoformat(created.replace("Z", "+00:00")).timestamp()
                if stamp < cutoff:
                    continue
            except ValueError:
                pass
        prompt = str(row.get("prompt") or "")
        response = str(row.get("response") or "")
        if not prompt or not response:
            continue
        prompt, p_redacted = _redact(prompt)
        response, r_redacted = _redact(response)
        redactions += int(p_redacted) + int(r_redacted)
        selected.append(
            {
                "messages": [
                    {"role": "user", "content": prompt},
                    {"role": "assistant", "content": response},
                ],
                "model": row.get("model_id"),
                "source_trace": row.get("trace_id"),
                "created_at": created,
            }
        )
    dataset_id = digest(selected)[:16]
    root = state / "datasets" / dataset_id
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if len(selected) == 1:
        train, val, test = selected, [], []
    elif len(selected) == 2:
        train, val, test = selected[:1], selected[1:], []
    else:
        split = max(1, len(selected) // 10)
        if 2 * split >= len(selected):
            split = 1
        train, val, test = selected[2 * split :], selected[split : 2 * split], selected[:split]
    for name, rows in (("train", train), ("val", val), ("test", test)):
        path = root / f"{name}.jsonl"
        path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")
        os.chmod(path, 0o600)
    manifest = {
        "schema": "sparknet-distill-dataset/1",
        "dataset_id": dataset_id,
        "teacher_model_id": teacher,
        "family": family,
        "created_at": now_iso(),
        "trace_count": len(selected),
        "split_sizes": {"train": len(train), "val": len(val), "test": len(test)},
        "split_digests": {name: digest(rows) for name, rows in (("train", train), ("val", val), ("test", test))},
        "redaction_report": {"redacted_rows": redactions},
    }
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(root / "manifest.json", 0o600)
    return manifest


def doctor(config: dict[str, Any]) -> dict[str, Any]:
    checks: dict[str, Any] = {}
    trainer = os.environ.get("SPARKNET_DISTILL_TRAINER", "").strip()
    if trainer:
        # The live Master runs the trainer in the dedicated image: check the
        # container's imports and CUDA, not the host interpreter's.
        try:
            result = subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--gpus",
                    "all",
                    "--entrypoint",
                    "/usr/bin/python3",
                    "sparknet-distill:dev",
                    "-c",
                    "import torch, transformers, peft; print(torch.cuda.is_available())",
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )
            checks["container"] = result.returncode == 0 and "True" in result.stdout
            checks["container_error"] = (result.stderr or "").strip()[-500:] if result.returncode else ""
        except (OSError, subprocess.SubprocessError) as exc:
            checks["container"] = False
            checks["container_error"] = str(exc)
        checks["gpu"] = "container"
    else:
        for module in ("torch", "transformers", "peft", "trl"):
            checks[module] = bool(importlib.util.find_spec(module))
        try:
            result = subprocess.run(
                ["nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            checks["gpu"] = result.stdout.strip() if result.returncode == 0 else None
        except (OSError, subprocess.SubprocessError):
            checks["gpu"] = None
        checks["container"] = all(checks[m] for m in ("torch", "transformers", "peft", "trl"))
    checks["trainer"] = trainer
    checks["teacher"] = config.get("teacher_model_id", "")
    checks["student"] = config.get("student_base_model", "")
    checks["ok"] = bool(checks.get("container")) and bool(trainer)
    return checks


def _signer_call(payload: dict[str, Any], *, socket_path: Path) -> dict[str, Any]:
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(30)
    try:
        connection.connect(str(socket_path))
        connection.sendall(json.dumps(payload).encode() + b"\n")
        data = b""
        while b"\n" not in data:
            chunk = connection.recv(4096)
            if not chunk:
                break
            data += chunk
    finally:
        connection.close()
    return json.loads(data.split(b"\n", 1)[0].decode())


def _signer_socket() -> Path:
    env = os.environ.get("SPARKNET_STATE_DIR")
    base = Path(env) if env else Path.home() / ".local" / "state" / "sparknet" / "master-node"
    return base / "signer" / "signer.sock"


def run(config: dict[str, Any], *, uplift: Path, state: Path, execute: bool, sign: bool) -> dict[str, Any]:
    manifest = build_dataset(config, uplift=uplift, state=state)
    if not manifest["trace_count"]:
        raise SystemExit("distill: dataset is empty; refusing a run with no consented traces")
    checks = doctor(config)
    run_id = f"run-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{manifest['dataset_id']}"
    root = state / "runs" / run_id
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    plan = {
        "schema": "sparknet-distill-run/1",
        "run_id": run_id,
        "dataset_id": manifest["dataset_id"],
        "teacher_model_id": config.get("teacher_model_id"),
        "student_base_model": config.get("student_base_model"),
        "family": config.get("family"),
        "hyperparameters": {key: config.get(key) for key in ("sequence_length", "method", "epochs", "learning_rate")},
        "doctor": checks,
        "created_at": now_iso(),
    }
    (root / "plan.json").write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if not checks["ok"]:
        plan["refused"] = "doctor did not pass"
        (root / "plan.json").write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return plan
    if not execute:
        plan["state"] = "planned; rerun with --execute"
        (root / "plan.json").write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return plan
    trainer = os.environ.get("SPARKNET_DISTILL_TRAINER", "")
    if not trainer:
        raise SystemExit("distill: SPARKNET_DISTILL_TRAINER is not set")
    env = os.environ.copy()
    env["SPARKNET_DISTILL_RUN"] = run_id
    env["SPARKNET_DISTILL_DATASET"] = str(state / "datasets" / manifest["dataset_id"])
    env["SPARKNET_DISTILL_CONFIG"] = json.dumps(config, sort_keys=True)
    student = str(config.get("student_base_model") or "").strip()
    if not student:
        raise SystemExit("distill: student_base_model is required to bind the trainer to the signed run")
    env["SPARKNET_DISTILL_STUDENT"] = student
    env["SPARKNET_DISTILL_STATE"] = str(state)
    env["SPARKNET_DISTILL_MAX_LEN"] = str(config.get("sequence_length") or 16384)
    result = subprocess.run(shlex.split(trainer), env=env, cwd=str(root))
    artifact = root / "artifact"
    artifact_sha = ""
    if result.returncode == 0 and artifact.is_file():
        artifact_sha = hashlib.sha256(artifact.read_bytes()).hexdigest()
    eval_metrics: dict[str, Any] = {}
    metrics_path = root / "metrics.json"
    if metrics_path.is_file():
        try:
            loaded = json.loads(metrics_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                eval_metrics = loaded
        except ValueError:
            eval_metrics = {}
    approved = result.returncode == 0 and float(eval_metrics.get("held_out_teacher_agreement", 0.0)) > 0.0
    record = {
        "run_id": run_id,
        "dataset_id": manifest["dataset_id"],
        "family": str(config.get("family") or ""),
        "teacher_model_id": str(config.get("teacher_model_id") or ""),
        "teacher_sha256": str(config.get("teacher_sha256") or ""),
        "student_base_model": str(config.get("student_base_model") or ""),
        "student_base_sha256": str(config.get("student_base_sha256") or ""),
        "hyperparameters": plan["hyperparameters"],
        "eval_metrics": eval_metrics,
        "artifact_sha256": artifact_sha,
        "decided_by": os.environ.get("SPARKNET_OPERATOR", "operator"),
        "decided_at": now_iso(),
        "approved": approved,
    }
    if sign and approved:
        root_response = _signer_call({"op": "root-id"}, socket_path=_signer_socket())
        if not root_response.get("ok"):
            raise SystemExit(f"distill: signer refused root-id: {root_response.get('error')}")
        response = _signer_call(
            {"op": "sign-distillation-run", "root_id": root_response["root_id"], "run": record},
            socket_path=_signer_socket(),
        )
        if not response.get("ok"):
            raise SystemExit(f"distill: signer refused: {response.get('error')}")
        record = response["run"]
    (root / "run.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return record


def evaluate(run_id: str, metrics_path: Path, *, state: Path, config: dict[str, Any]) -> dict[str, Any]:
    root = state / "runs" / run_id
    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    thresholds = config.get("thresholds") if isinstance(config.get("thresholds"), dict) else {}
    failures = []
    for key, minimum in thresholds.items():
        if key.endswith("_max"):
            name = key[:-4]
            if float(metrics.get(name, 1.0)) > float(minimum):
                failures.append(f"{name}={metrics.get(name)} > {minimum}")
        elif float(metrics.get(key, 0.0)) < float(minimum):
            failures.append(f"{key}={metrics.get(key)} < {minimum}")
    try:
        run_record = json.loads((root / "run.json").read_text(encoding="utf-8"))
    except OSError:
        run_record = {}
    result = {
        "schema": "sparknet-distill-eval/1",
        "run_id": run_id,
        "metrics": metrics,
        "artifact_sha256": run_record.get("artifact_sha256"),
        "failures": failures,
        "approved": not failures,
        "evaluated_at": now_iso(),
    }
    (root / "eval.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def publish(run_id: str, *, state: Path) -> dict[str, Any]:
    root = state / "runs" / run_id
    run_record = json.loads((root / "run.json").read_text(encoding="utf-8"))
    evaluation = json.loads((root / "eval.json").read_text(encoding="utf-8"))
    if not run_record.get("signature_b64"):
        raise SystemExit("distill: run record is unsigned; refusing to publish")
    if run_record.get("approved") is not True:
        raise SystemExit("distill: run is not approved; refusing to publish")
    if not evaluation.get("approved"):
        raise SystemExit("distill: evaluation is not approved; refusing to publish")
    if evaluation.get("metrics") != run_record.get("eval_metrics"):
        raise SystemExit("distill: evaluation metrics do not match the signed run record")
    if evaluation.get("artifact_sha256") != run_record.get("artifact_sha256"):
        raise SystemExit("distill: evaluation is not bound to the run artifact")
    model_id = f"distilled-{run_id}"
    card = {
        "schema": "sparknet-model-card/1",
        "model_id": model_id,
        "family": run_record.get("family"),
        "base_model": run_record.get("student_base_model"),
        "teacher_model": run_record.get("teacher_model_id"),
        "run_id": run_id,
        "artifact_sha256": run_record.get("artifact_sha256"),
        "eval_metrics": evaluation.get("metrics"),
        "published_at": now_iso(),
    }
    (root / "model-card.json").write_text(json.dumps(card, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return card


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Master same-family distillation scaffold")
    parser.add_argument("command", choices=("dataset", "doctor", "run", "eval", "publish", "status"))
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--uplift", type=Path, default=DEFAULT_UPLIFT)
    parser.add_argument("--run", default="")
    parser.add_argument("--metrics", type=Path)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--sign", action="store_true")
    args = parser.parse_args(argv)
    config = load_config(args.config)
    if args.command == "dataset":
        print(json.dumps(build_dataset(config, uplift=args.uplift, state=args.state), indent=2, sort_keys=True))
        return 0
    if args.command == "doctor":
        checks = doctor(config)
        print(json.dumps(checks, indent=2, sort_keys=True))
        return 0 if checks["ok"] else 3
    if args.command == "run":
        record = run(config, uplift=args.uplift, state=args.state, execute=args.execute, sign=args.sign)
        print(json.dumps(record, indent=2, sort_keys=True))
        return 0 if record.get("approved", True) else 2
    if args.command == "eval":
        if not args.run or not args.metrics:
            raise SystemExit("eval needs --run and --metrics")
        result = evaluate(args.run, args.metrics, state=args.state, config=config)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["approved"] else 2
    if args.command == "publish":
        if not args.run:
            raise SystemExit("publish needs --run")
        print(json.dumps(publish(args.run, state=args.state), indent=2, sort_keys=True))
        return 0
    runs = sorted((args.state / "runs").glob("*")) if (args.state / "runs").is_dir() else []
    print(json.dumps({"runs": [path.name for path in runs]}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
