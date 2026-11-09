#!/usr/bin/env python3
"""Master orchestrator: route one validated task event to a peer agent role."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "shared"))
from sparknet_loader import load_shared  # noqa: E402 - shared/ is added by path above

EVENT = load_shared("sparknet-event.py", "sparknet_orchestrator_event")
BUS = load_shared("sparknet-event-bus.py", "sparknet_orchestrator_bus")
ROLES = ("engineering", "cyber")
ORCHESTRATE_TOPIC = "sparknet.task.orchestrate"
AUTHORITY_KEYS = frozenset({"grant", "grants", "grant_id", "capability", "capabilities", "authority", "signature_b64"})


class OrchestratorError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def route(event):
    try:
        normalised = EVENT.validate_event(event)
    except EVENT.EventError as exc:
        raise OrchestratorError(exc.code, exc.message) from exc
    if normalised["topic"] != ORCHESTRATE_TOPIC:
        raise OrchestratorError("bad-topic", f"orchestrator only consumes {ORCHESTRATE_TOPIC}")
    payload = normalised["payload"]
    for key in payload:
        if str(key) in AUTHORITY_KEYS:
            raise OrchestratorError("authority-field", f"payload.{key} carries an authority field")
    role = str(payload.get("role") or "").strip()
    if role not in ROLES:
        raise OrchestratorError("unknown-role", f"role must be one of {', '.join(ROLES)}")
    task_payload = dict(payload)
    task_payload["role"] = role
    task_payload["orchestrator_event_id"] = normalised["event_id"]
    return EVENT.make_event(
        event_type="task.enqueued",
        topic=f"sparknet.task.{role}",
        sender_node_id=normalised["sender_node_id"],
        payload=task_payload,
        classification=normalised["classification"],
        department=normalised.get("department"),
        vault_id=normalised.get("vault_id", ""),
        scope=normalised.get("scope") or [],
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="sparknet-orchestrator")
    parser.add_argument("--nats-url", default=os.environ.get("SPARKNET_NATS_URL", "nats://127.0.0.1:4222"))
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--serve", action="store_true")
    args = parser.parse_args(argv)
    address = BUS.BusAddress.parse(args.nats_url)
    client = BUS.NatsClient(address.host, address.port)
    try:
        client.connect()
        if args.once or not args.serve:
            routed = route(client.subscribe_once(ORCHESTRATE_TOPIC, timeout=5.0))
            client.publish(routed["topic"], routed)
            print(json.dumps({"ok": True, "topic": routed["topic"], "event_id": routed["event_id"]}, sort_keys=True))
            return 0
        for event in client.subscribe(ORCHESTRATE_TOPIC):
            try:
                routed = route(event)
                client.publish(routed["topic"], routed)
                print(
                    json.dumps({"ok": True, "topic": routed["topic"], "event_id": routed["event_id"]}, sort_keys=True),
                    flush=True,
                )
            except OrchestratorError as exc:
                print(f"orchestrator: {exc.code}: {exc}", file=sys.stderr, flush=True)
    except (OrchestratorError, BUS.NatsError, EVENT.EventError) as exc:
        print(f"orchestrator: {exc}", file=sys.stderr)
        return 2
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
