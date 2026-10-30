#!/usr/bin/env python3
"""The Master's reflex broker — a local sensor the fabric can consult.

Why a broker at all
~~~~~~~~~~~~~~~~~~~
The reflex layer is local-first: a node can answer `rag.relevance` with a local
reranker and never call the network. This broker is the one place a *sibling*
can ask for that judgement over the overlay instead of running its own, so the
fabric has a single sensor to budget, audit and pin. It never leaves the fabric:
every backend in the contract's vocabulary is local, and there is no egress path
here to configure, enable or leak a credential through.

What this process is not
~~~~~~~~~~~~~~~~~~~~~~~~
It is not an authority. It validates the contract, redacts the state it sends,
pins the exact model tag, honours a hard timeout and a daily budget, and returns
a decision. Timeout, backend error, budget exhaustion or malformed backend
output all return `abstain`; the caller falls back to deterministic behavior.
Nothing here signs, grants, revokes or approves.

Phase 1 source policy
~~~~~~~~~~~~~~~~~~~~~
The broker binds the Master's overlay address only. Loopback and the Master's
own overlay address are accepted; every other overlay source is refused with
`403 off_overlay` before the request body is read. Peers get access only when
the `reflex-consult` capability lands, which is a separate cross-role commit.

Usage::

    sparknet-reflex-broker.py --serve --bind 10.100.0.1 --port 4224
    sparknet-reflex-broker.py --check
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

ROLE_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = ROLE_ROOT.parent
REFLEX_PATH = REPO_ROOT / "shared" / "sparknet-reflex.py"

DEFAULT_BIND = "10.100.0.1"
DEFAULT_PORT = 4224
DEFAULT_MODEL = os.environ.get("SPARKNET_REFLEX_MODEL", "local")
DEFAULT_AUDIT = Path("/mnt/log/sparknet-reflex.jsonl")
MAX_BODY = 256 * 1024
# A local LLM answer must land inside the caller's own timeout, so it is the
# smaller of the two by construction; overridable for a slow cold model load.
DEFAULT_LOCAL_LLM_TIMEOUT_S = 5.0

ALLOWED_SOURCES = {"127.0.0.1", "::1", DEFAULT_BIND}


def _load_reflex() -> Any:
    if "sparknet_reflex" in sys.modules:
        return sys.modules["sparknet_reflex"]
    spec = importlib.util.spec_from_file_location("sparknet_reflex", REFLEX_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load the reflex contract from {REFLEX_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["sparknet_reflex"] = module
    spec.loader.exec_module(module)
    return module


reflex = _load_reflex()


class BrokerError(Exception):
    """A refusal the broker can report without echoing request content."""


def validate_model(model: str) -> str:
    """An exact tag for whatever this node runs; only moving aliases are refused.

    There is one validator because there is one kind of backend. The previous
    pair existed to enforce a vendor namespace on the cloud leg and nothing on
    the local one; with the cloud leg gone, a single rule covers every model the
    broker can be pointed at, and `SPARKNET_REFLEX_MODEL=local` still starts.
    """
    model = (model or "").strip()
    if not model:
        raise BrokerError("model must be non-empty")
    if "latest" in model.lower():
        raise BrokerError("model must be an exact tag, not a moving 'latest' alias")
    return model


def source_allowed(address: str) -> bool:
    return address in ALLOWED_SOURCES


@dataclass
class BudgetLedger:
    per_node_per_day: int = 0
    global_per_day: int = 0
    _node_used: dict[str, int] = field(default_factory=dict)
    _global_used: int = 0

    def check(self, node_id: str) -> None:
        if self.per_node_per_day and self._node_used.get(node_id, 0) >= self.per_node_per_day:
            raise reflex.ReflexBudgetExhausted("per-node budget exhausted")
        if self.global_per_day and self._global_used >= self.global_per_day:
            raise reflex.ReflexBudgetExhausted("global budget exhausted")

    def charge(self, node_id: str) -> None:
        self._node_used[node_id] = self._node_used.get(node_id, 0) + 1
        self._global_used += 1


def audit(path: Path, decision: dict[str, Any], request: dict[str, Any], latency_ms: float) -> None:
    """Append hashes only. An unwritable log is reported, never fatal."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(reflex.audit_line(decision, request, request["question_class"], latency_ms) + "\n")
    except OSError as exc:
        print(f"reflex-broker: audit write failed: {exc}", file=sys.stderr)


def backend_posture() -> str:
    """The configured backend.

    One reader for both `decide` and `main`, so the startup check and the
    per-request check can never disagree about which mode the broker is in. It
    returns a name and not a posture pair: there is no egress flag left to read,
    because every backend in the vocabulary is local.
    """
    return os.environ.get("SPARKNET_REFLEX_BACKEND", "local").strip().lower()


def _local_llm_timeout() -> float:
    """Read the local-LLM timeout at call time; a bad value falls back safely."""
    try:
        value = float(os.environ.get("SPARKNET_REFLEX_LOCAL_TIMEOUT", str(DEFAULT_LOCAL_LLM_TIMEOUT_S)))
    except ValueError:
        return DEFAULT_LOCAL_LLM_TIMEOUT_S
    return value if value > 0 else DEFAULT_LOCAL_LLM_TIMEOUT_S


def _local_backend(request: dict[str, Any]) -> dict[str, Any]:
    """Answer from the node itself. Raises on any failure.

    Every failure path here must propagate: ``consult`` turns a raise into an
    abstain, while a synthesised ``noul=0.0`` would be read as a *confident
    reject* — the one outcome the fail-open contract forbids.
    """
    backend_name = reflex.backend_from_env(request.get("question_class", "rag.relevance"))
    if backend_name == "null":
        raise reflex.ReflexPolicyError("local backend is off")
    if backend_name in ("local-rerank", "rules"):
        return reflex.local_relevance_answer(request)
    call = reflex.local_llm_backend(request.get("model"), timeout_s=_local_llm_timeout())
    return call(request)


def decide(
    request: dict[str, Any],
    *,
    call: Any | None = None,
    timeout_s: float,
    budget: BudgetLedger,
    audit_path: Path,
    model_pin: str | None = None,
    offline: bool = False,
) -> dict[str, Any]:
    """Validate, budget, consult and audit one request. Always returns a decision."""
    reflex.validate_request(request)
    backend_env = backend_posture()
    model = validate_model(request.get("model") or reflex.LOCAL_MODEL_SENTINEL)

    # The pin is enforced against a *named* model. A request carrying the local
    # sentinel is asking for whatever this node runs, which is the pin, so it
    # cannot mismatch it — and refusing it would make the default request shape
    # the bridge sends unanswerable.
    if model_pin and model != model_pin and model != reflex.LOCAL_MODEL_SENTINEL:
        raise BrokerError(f"request model {model!r} does not match the pinned {model_pin!r}")
    node_id = request["node_id"]

    if offline or backend_env == "off":
        decision = reflex.abstain_decision(model, "null", "", request, reason="offline")
        audit(audit_path, decision, request, 0.0)
        return decision

    try:
        budget.check(node_id)
    except reflex.ReflexBudgetExhausted:
        decision = reflex.abstain_decision(model, "null", "", request, reason="budget-exhausted")
        audit(audit_path, decision, request, 0.0)
        return decision

    started = time.monotonic()
    backend_name = reflex.backend_from_env(request.get("question_class", "rag.relevance"))
    decision = reflex.consult(
        call or _local_backend,
        request,
        timeout_s=timeout_s,
        backend=backend_name,
        model=model,
    )
    if decision["verdict"] != "abstain":
        budget.charge(node_id)
    latency_ms = (time.monotonic() - started) * 1000.0
    audit(audit_path, decision, request, latency_ms)
    return decision


def _json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":")).encode("utf-8")


class _Handler(BaseHTTPRequestHandler):
    server_version = "sparknet-reflex-broker"
    sys_version = ""

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"reflex-broker: {self.address_string()} {fmt % args}", file=sys.stderr)

    def _send(self, status: int, body: dict[str, Any]) -> None:
        data = _json_bytes(body)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._send(200, {"ok": True})
            return
        self._send(404, {"error": "not_found"})

    def do_POST(self) -> None:
        if self.path != "/v1/reflex/decide":
            self._send(404, {"error": "not_found"})
            return
        if not source_allowed(self.client_address[0]):
            self._send(403, {"error": "off_overlay"})
            return

        length = int(self.headers.get("Content-Length", "0") or 0)
        if length <= 0 or length > MAX_BODY:
            self._send(413 if length > MAX_BODY else 400, {"error": "bad_length"})
            return

        try:
            request = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send(400, {"error": "bad_json"})
            return

        try:
            decision = decide(
                request,
                call=self.server.call,  # type: ignore[attr-defined]
                timeout_s=self.server.timeout_s,  # type: ignore[attr-defined]
                budget=self.server.budget,  # type: ignore[attr-defined]
                audit_path=self.server.audit_path,  # type: ignore[attr-defined]
                model_pin=self.server.model_pin,  # type: ignore[attr-defined]
                offline=self.server.offline,  # type: ignore[attr-defined]
            )
        except reflex.ReflexPolicyError as exc:
            self._send(400, {"error": "contract", "detail": str(exc)})
            return
        except BrokerError as exc:
            self._send(503, {"error": "unavailable", "detail": str(exc)})
            return
        self._send(200, decision)


def serve(
    bind: str,
    port: int,
    *,
    timeout_s: float,
    budget: BudgetLedger,
    audit_path: Path,
    model_pin: str | None,
    offline: bool,
    call: Any | None = None,
) -> None:
    if bind != DEFAULT_BIND and bind not in {"127.0.0.1", "::1"}:
        raise BrokerError("refuse to bind a non-overlay address (Phase 1 is overlay-only)")
    server = ThreadingHTTPServer((bind, port), _Handler)
    server.timeout_s = timeout_s  # type: ignore[attr-defined]
    server.budget = budget  # type: ignore[attr-defined]
    server.audit_path = audit_path  # type: ignore[attr-defined]
    server.model_pin = model_pin  # type: ignore[attr-defined]
    server.offline = offline  # type: ignore[attr-defined]
    server.call = call  # type: ignore[attr-defined]
    print(f"reflex-broker: listening on {bind}:{port} (offline={offline})", file=sys.stderr)
    server.serve_forever()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sparknet Master reflex broker (local-first sensor)")
    parser.add_argument("--serve", action="store_true", help="run the HTTP listener")
    parser.add_argument("--check", action="store_true", help="print posture and exit")
    parser.add_argument("--bind", default=os.environ.get("SPARKNET_REFLEX_BIND", DEFAULT_BIND))
    parser.add_argument("--port", type=int, default=int(os.environ.get("SPARKNET_REFLEX_PORT", DEFAULT_PORT)))
    parser.add_argument("--model", default=os.environ.get("SPARKNET_REFLEX_MODEL", DEFAULT_MODEL))
    parser.add_argument("--timeout", type=float, default=float(os.environ.get("SPARKNET_REFLEX_TIMEOUT", "2.0")))
    parser.add_argument("--audit", default=os.environ.get("SPARKNET_REFLEX_AUDIT", str(DEFAULT_AUDIT)))
    parser.add_argument("--node-budget", type=int, default=int(os.environ.get("SPARKNET_REFLEX_NODE_BUDGET", "0")))
    parser.add_argument("--global-budget", type=int, default=int(os.environ.get("SPARKNET_REFLEX_GLOBAL_BUDGET", "0")))
    parser.add_argument("--offline", action="store_true", help="never consult a backend; every decision abstains")
    args = parser.parse_args(argv)

    backend_env = backend_posture()
    try:
        model = validate_model(args.model)
    except BrokerError as exc:
        print(f"reflex-broker: {exc}", file=sys.stderr)
        return 2

    if args.check:
        print(
            json.dumps(
                {
                    "service": "reflex-broker",
                    "bind": args.bind,
                    "port": args.port,
                    "model": model,
                    "offline": args.offline,
                    "backend": backend_env,
                    "audit": args.audit,
                },
                indent=2,
            )
        )
        return 0

    if not args.serve:
        parser.error("choose --serve or --check")

    budget = BudgetLedger(per_node_per_day=args.node_budget, global_per_day=args.global_budget)
    try:
        serve(
            args.bind,
            args.port,
            timeout_s=args.timeout,
            budget=budget,
            audit_path=Path(args.audit),
            model_pin=model,
            offline=args.offline,
        )
    except (BrokerError, OSError) as exc:
        print(f"reflex-broker: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
