"""Master Step 89 writes are signed, confirmed and provenance-only."""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "master-node" / "services" / "sparknet-step89-admin.py"
SHARED = ROOT / "shared"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


admin = _load("step89_admin_test", SCRIPT)
authz = _load("step89_admin_authz_test", SHARED / "sparknet-authz.py")
package = _load("step89_admin_package_test", SHARED / "sparknet-package.py")


def _setup(tmp_path):
    role = tmp_path / "master"
    state = tmp_path / "state"
    (role / "manifests").mkdir(parents=True)
    (role / "manifests" / "master-identity.json").write_text(json.dumps({"node_id": "sparknet-node-0001"}))
    (state / "keys").mkdir(parents=True)
    private_b64, public_b64 = authz.generate_keypair()
    key = state / "keys" / "ed25519-node.key.b64"
    key.write_text(private_b64 + "\n")
    key.chmod(0o600)
    return role, state, key, public_b64


def _run(role, state, key, *args):
    return admin.main(
        [
            "--role-root",
            str(role),
            "--state-root",
            str(state),
            "--key-file",
            str(key),
            *args,
        ]
    )


def _payload(tmp_path, value):
    path = tmp_path / "payload.json"
    path.write_text(json.dumps(value))
    return str(path)


def test_lake_intake_is_signed_and_recorded(tmp_path, capsys):
    role, state, key, public = _setup(tmp_path)
    payload = _payload(
        tmp_path,
        {
            "consent": True,
            "kind": "teacher-trace",
            "classification": "confidential",
            "digest": "a" * 64,
            "size": 10,
            "retention_days": 30,
        },
    )
    assert _run(role, state, key, "lake-intake", "--payload", payload, "--confirm") == 0
    record = next((state / "step89" / "actions").glob("*.json"))
    envelope = json.loads(record.read_text())
    assert authz.verify_signature(
        authz.public_key_from_b64(public),
        envelope["signature_b64"],
        admin._message(envelope),
    )
    assert (state / "uplift" / "lake" / "records.jsonl").read_text().count("\n") == 1
    assert _run(role, state, key, "verify", "--file", str(record)) == 0


def test_lake_intake_requires_consent_and_confirmation(tmp_path):
    role, state, key, _ = _setup(tmp_path)
    payload = _payload(
        tmp_path,
        {
            "consent": False,
            "kind": "teacher-trace",
            "classification": "internal",
            "digest": "a" * 64,
            "size": 1,
            "retention_days": 30,
        },
    )
    assert _run(role, state, key, "lake-intake", "--payload", payload) == 2
    assert _run(role, state, key, "lake-intake", "--payload", payload, "--confirm") == 2


def test_collab_room_and_distill_schedule(tmp_path):
    role, state, key, _ = _setup(tmp_path)
    room = _payload(
        tmp_path,
        {
            "owner_node_id": "node-1",
            "classification": "internal",
            "participants": [{"node_id": "node-1", "user_id": "user-1", "role": "owner"}],
        },
    )
    assert _run(role, state, key, "collab-room", "--payload", room, "--confirm") == 0
    assert (role / "01_Inbox" / "collab").glob("*/room.json")
    when = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    schedule = _payload(tmp_path, {"run_at": when, "config": "configs/distill.json"})
    assert _run(role, state, key, "distill-schedule", "--payload", schedule, "--confirm") == 0
    assert list((state / "distill" / "schedule").glob("*.json"))


def test_package_index_is_signed_and_verifiable(tmp_path):
    role, state, key, public = _setup(tmp_path)
    manifest = {
        "schema_version": "sparknet-package/1",
        "package_id": "tool",
        "version": "1.0.0",
        "description": "test",
        "artifacts": [{"path": "bin/tool", "sha256": "a" * 64, "size": 1}],
        "dependencies": [],
        "signer_node_id": "master",
        "created_at": "2099-01-01T00:00:00Z",
    }
    package_file = tmp_path / "tool.json"
    package_file.write_text(json.dumps(manifest))
    payload = _payload(tmp_path, {"packages": [str(package_file)]})
    assert _run(role, state, key, "package-index", "--payload", payload, "--confirm") == 0
    index = json.loads((state / "share" / "packages" / "index.json").read_text())
    assert package.verify_index_signature(index, authz.public_key_from_b64(public)) is True


def test_collab_and_schedule_ids_cannot_escape_their_roots(tmp_path):
    role, state, key, _ = _setup(tmp_path)
    room = _payload(tmp_path, {"owner_node_id": "owner-1", "room_id": "../../escape", "classification": "internal"})
    assert _run(role, state, key, "collab-room", "--payload", room, "--confirm") != 0
    assert not (role.parent / "escape").exists()
    when = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    schedule = _payload(tmp_path, {"run_at": when, "schedule_id": "../../escape", "config": "configs/distill.json"})
    assert _run(role, state, key, "distill-schedule", "--payload", schedule, "--confirm") != 0
    assert not (state.parent / "escape.json").exists()
