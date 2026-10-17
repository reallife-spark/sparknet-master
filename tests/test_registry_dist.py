"""Step 6: registry distribution."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

ROLE_ROOT = Path(__file__).resolve().parent.parent

STATE = None


def state_dir() -> Path:
    global STATE
    if STATE is not None:
        return STATE
    probe = subprocess.run(
        [
            "bash",
            "-c",
            f'. "{ROLE_ROOT}/scripts/sparknet-master-env.sh" >/dev/null && printf "%s" "$SPARKNET_STATE_DIR"',
        ],
        capture_output=True,
        text=True,
        check=True,
        env={**os.environ, "HOME": os.environ.get("HOME", "/nonexistent")},
    )
    STATE = Path(probe.stdout.strip())
    return STATE


needs_keys = pytest.mark.skipif(
    not all((state_dir() / "keys" / f"{n}.ed25519").is_file() for n in ("cluster", "operational", "identity")),
    reason="keys missing",
)


@needs_keys
def test_registry_publish_and_peer_verification(tmp_path):
    # sign one entry
    ident = tmp_path / "id.json"
    ident.write_text(
        json.dumps(
            {
                "node_id": "p",
                "role": "peer",
                "wireguard_public_key_b64": "E" * 44,
                "overlay_ipv4": "10.100.0.13/32",
                "requested_capabilities": ["telemetry"],
            }
        )
    )
    ent = tmp_path / "e.json"
    subprocess.run(
        ["make", "-C", str(ROLE_ROOT), "authz-sign", f"IDENTITY={ident}", "CAPS=telemetry", f"OUT={ent}"], check=True
    )
    reg = tmp_path / "r.json"
    reg.write_text(
        json.dumps({"role": "registry", "schema_version": "1.0.0", "authorizations": [json.loads(ent.read_text())]})
    )
    # tamper test via peer guard? just verify make registry-verify and publish
    subprocess.run(["make", "-C", str(ROLE_ROOT), "registry-verify", f"REGISTRY={reg}"], check=True)
    pub = tmp_path / "pub.reg"
    subprocess.run(["make", "-C", str(ROLE_ROOT), "registry-publish", f"REGISTRY={reg}", f"OUT={pub}"], check=True)
    assert pub.is_file()
    # tamper: change content and verify should fail
    tampered = json.loads(pub.read_text())
    tampered["authorizations"][0]["capabilities"] = ["other"]
    tampered_path = tmp_path / "tampered.json"
    tampered_path.write_text(json.dumps(tampered))
    res = subprocess.run(
        ["make", "-C", str(ROLE_ROOT), "registry-verify", f"REGISTRY={tampered_path}"], capture_output=True
    )
    assert res.returncode != 0
