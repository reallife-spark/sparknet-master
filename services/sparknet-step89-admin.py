#!/usr/bin/env python3
"""Signed Master-side Step 89 writes: lake, collab, distill schedule, packages.

Every action is composed as a canonical envelope, signed with the Master node
key, verified before it is applied, and recorded under the Master state dir. The
envelope is provenance, not authority: it cannot grant, revoke or widen a
capability, and the package index it publishes still requires an explicit peer
install.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROLE_ROOT = Path(__file__).resolve().parent.parent
FABRIC_ROOT = ROLE_ROOT.parent
sys.path.insert(0, str(FABRIC_ROOT / "shared"))
from sparknet_loader import load_shared  # noqa: E402 - shared/ is added by path above

AUTHZ = load_shared("sparknet-authz.py", "sparknet_step89_admin_authz")
PACKAGE = load_shared("sparknet-package.py", "sparknet_step89_admin_package")
COLLAB = load_shared("sparknet-collab.py", "sparknet_step89_admin_collab")
ABAC = load_shared("sparknet-abac.py", "sparknet_step89_admin_abac")

SCHEMA = "sparknet-step89-action/1"
ACTIONS = ("lake-intake", "collab-room", "distill-schedule", "package-index")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class AdminError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _node_id(role_root: Path) -> str:
    path = role_root / "manifests" / "master-identity.json"
    if path.is_file():
        return str(json.loads(path.read_text()).get("node_id") or "sparknet-node-0001")
    return "sparknet-node-0001"


def _key(key_file: Path):
    try:
        return AUTHZ.load_private_key(key_file)
    except (OSError, AUTHZ.AuthzError) as exc:
        raise AdminError("key-unavailable", str(exc)) from exc


def _message(envelope: dict[str, Any]) -> bytes:
    return json.dumps(
        {key: value for key, value in envelope.items() if key != "signature_b64"},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _envelope(action: str, payload: dict[str, Any], role_root: Path, key: Any) -> dict[str, Any]:
    if action not in ACTIONS:
        raise AdminError("unknown-action", f"action must be one of {', '.join(ACTIONS)}")
    if not isinstance(payload, dict):
        raise AdminError("bad-payload", "payload must be an object")
    envelope = {
        "schema_version": SCHEMA,
        "request_id": "act_" + uuid.uuid4().hex,
        "action": action,
        "node_id": _node_id(role_root),
        "created_at": _now(),
        "payload": payload,
        "signature_b64": "",
    }
    envelope["signature_b64"] = AUTHZ.sign_bytes(key, _message(envelope))
    return envelope


def verify(envelope: dict[str, Any], key: Any) -> dict[str, Any]:
    if not isinstance(envelope, dict) or envelope.get("schema_version") != SCHEMA:
        raise AdminError("malformed-action", "unknown action schema")
    signature = envelope.get("signature_b64")
    if not isinstance(signature, str) or not signature:
        raise AdminError("unsigned-action", "action has no signature")
    if not AUTHZ.verify_signature(key.public_key(), signature, _message(envelope)):
        raise AdminError("bad-signature", "action signature does not verify")
    if envelope.get("action") not in ACTIONS:
        raise AdminError("unknown-action", "action is not in the closed vocabulary")
    return envelope


def _record(state_root: Path, envelope: dict[str, Any]) -> Path:
    path = state_root / "step89" / "actions" / f"{envelope['request_id']}.json"
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(json.dumps(envelope, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(temp, 0o600)
    os.replace(temp, path)
    return path


def _apply_lake(state_root: Path, payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("consent") is not True:
        raise AdminError("consent-missing", "lake intake requires consent=true")
    classification = payload.get("classification")
    if classification not in ABAC.CLASSIFICATIONS:
        raise AdminError("unknown-classification", "lake record classification is unknown")
    digest = payload.get("digest")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise AdminError("bad-digest", "lake record digest must be 64 lowercase hex")
    size = payload.get("size")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise AdminError("bad-size", "lake record size must be a non-negative integer")
    retention = payload.get("retention_days")
    if not isinstance(retention, int) or isinstance(retention, bool) or not 1 <= retention <= 3650:
        raise AdminError("retention-too-long", "retention_days must be 1..3650")
    root = state_root / "uplift" / "lake"
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    target = root / "records.jsonl"
    with target.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True) + "\n")
    os.chmod(target, 0o600)
    return {"records": str(target), "kind": payload.get("kind")}


COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _apply_collab(role_root: Path, payload: dict[str, Any]) -> dict[str, Any]:
    owner = str(payload.get("owner_node_id") or "").strip()
    if not owner:
        raise AdminError("malformed-room", "owner_node_id is required")
    if not COMPONENT_RE.fullmatch(owner):
        raise AdminError("malformed-room", "owner_node_id is not a safe identifier")
    requested_room = str(payload.get("room_id") or uuid.uuid4().hex)
    if not COMPONENT_RE.fullmatch(requested_room):
        raise AdminError("malformed-room", "room_id must be a single safe path component")
    room = COLLAB.make_room(
        owner_node_id=owner,
        participants=payload.get("participants") or [],
        classification=str(payload.get("classification") or "internal"),
        department=payload.get("department"),
        room_id=requested_room,
        verified=True,
    )
    collab_root = (role_root / "01_Inbox" / "collab").resolve()
    target = collab_root / room["room_id"] / "room.json"
    try:
        target.resolve().relative_to(collab_root)
    except ValueError as exc:
        raise AdminError("malformed-room", "room path escapes the collaboration root") from exc
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    target.write_text(json.dumps(room, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(target, 0o600)
    return {"room_id": room["room_id"], "path": str(target.relative_to(role_root))}


def _apply_distill(state_root: Path, payload: dict[str, Any]) -> dict[str, Any]:
    run_at = payload.get("run_at")
    if not isinstance(run_at, str) or not run_at:
        raise AdminError("malformed-schedule", "run_at is required")
    try:
        moment = datetime.fromisoformat(run_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AdminError("malformed-schedule", "run_at is not ISO-8601") from exc
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    if moment <= datetime.now(timezone.utc):
        raise AdminError("malformed-schedule", "run_at must be in the future")
    root = state_root / "distill" / "schedule"
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    schedule_id = str(payload.get("schedule_id") or "schedule-" + uuid.uuid4().hex)
    if not COMPONENT_RE.fullmatch(schedule_id):
        raise AdminError("malformed-schedule", "schedule_id must be a single safe path component")
    target = root / (schedule_id + ".json")
    try:
        target.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise AdminError("malformed-schedule", "schedule path escapes the schedule root") from exc
    record = {"schema": "sparknet-distill-schedule/1", "status": "scheduled", **payload}
    target.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(target, 0o600)
    return {"schedule_id": target.stem, "path": str(target)}


def _apply_package(state_root: Path, payload: dict[str, Any], key: Any) -> dict[str, Any]:
    files = payload.get("packages")
    if not isinstance(files, list) or not files:
        raise AdminError("malformed-package", "packages must be a non-empty list of files")
    manifests = []
    for item in files:
        try:
            manifests.append(json.loads(Path(str(item)).read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError) as exc:
            raise AdminError("malformed-package", f"{item}: {exc}") from exc
    index = PACKAGE.make_index(manifests)
    signed = PACKAGE.sign_index(index, key)
    target = state_root / "share" / "packages" / "index.json"
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    target.write_text(json.dumps(signed, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(target, 0o600)
    return {"packages": len(signed["packages"]), "path": str(target)}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sparknet-step89-admin", description="signed Master Step 89 writes")
    parser.add_argument("--role-root", type=Path, default=ROLE_ROOT)
    parser.add_argument("--state-root", type=Path, default=Path(os.environ.get("SPARKNET_STATE_ROOT", "/srv/sparknet")))
    parser.add_argument("--key-file", type=Path, default=None)
    sub = parser.add_subparsers(dest="command", required=True)

    lake = sub.add_parser("lake-intake", help="record one consented lake artifact")
    lake.add_argument("--payload", required=True, help="JSON file or - for stdin")
    lake.add_argument("--confirm", action="store_true", help="required to write")

    collab = sub.add_parser("collab-room", help="create one collaboration room")
    collab.add_argument("--payload", required=True, help="JSON file or - for stdin")
    collab.add_argument("--confirm", action="store_true", help="required to write")

    distill = sub.add_parser("distill-schedule", help="schedule one operator-triggered distillation")
    distill.add_argument("--payload", required=True, help="JSON file or - for stdin")
    distill.add_argument("--confirm", action="store_true", help="required to write")

    package = sub.add_parser("package-index", help="sign and publish a package index")
    package.add_argument("--payload", required=True, help="JSON file or - for stdin")
    package.add_argument("--confirm", action="store_true", help="required to write")

    verify_parser = sub.add_parser("verify", help="verify one signed action record")
    verify_parser.add_argument("--file", required=True)
    return parser


def _payload(value: str) -> dict[str, Any]:
    raw = sys.stdin.read() if value == "-" else Path(value).read_text(encoding="utf-8")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise AdminError("bad-payload", "payload must be a JSON object")
    return data


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    role_root = args.role_root.resolve()
    state_root = args.state_root.resolve()
    key_file = args.key_file or (role_root / ".state" / "keys" / "ed25519-node.key.b64")
    try:
        key = _key(key_file)
        if args.command == "verify":
            envelope = verify(json.loads(Path(args.file).read_text(encoding="utf-8")), key)
            print(json.dumps({"ok": True, "action": envelope["action"], "request_id": envelope["request_id"]}))
            return 0
        if not args.confirm:
            raise AdminError("confirmation-required", "signed writes require --confirm")
        payload = _payload(args.payload)
        action = args.command
        if action == "lake-intake":
            result = _apply_lake(state_root, payload)
        elif action == "collab-room":
            result = _apply_collab(role_root, payload)
        elif action == "distill-schedule":
            result = _apply_distill(state_root, payload)
        else:
            result = _apply_package(state_root, payload, key)
        envelope = _envelope(action, payload, role_root, key)
        verify(envelope, key)
        record = _record(state_root, envelope)
        print(
            json.dumps(
                {
                    "ok": True,
                    "action": action,
                    "request_id": envelope["request_id"],
                    "record": str(record),
                    "result": result,
                },
                sort_keys=True,
            )
        )
        return 0
    except (AdminError, OSError, ValueError, json.JSONDecodeError, PACKAGE.PackageError, COLLAB.CollabError) as exc:
        print(f"sparknet-step89-admin: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
