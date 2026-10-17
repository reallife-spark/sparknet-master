"""Step 3 CLI surface tests (post-S3)."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

ROLE_ROOT = Path(__file__).resolve().parent.parent

_STATE = None


def state_dir() -> Path:
    global _STATE
    if _STATE is not None:
        return _STATE
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
    _STATE = Path(probe.stdout.strip())
    return _STATE


def has_keys() -> bool:
    sd = state_dir() / "keys"
    return all((sd / f"{n}.ed25519").is_file() for n in ("cluster", "operational", "identity"))


needs_keys = pytest.mark.skipif(not has_keys(), reason="need keys")


@needs_keys
def test_make_targets_exist_and_run(tmp_path):
    # authz-sign
    ident = tmp_path / "id.json"
    ident.write_text(
        json.dumps(
            {
                "node_id": "n",
                "role": "peer",
                "wireguard_public_key_b64": "D" * 44,
                "overlay_ipv4": "10.100.0.12/32",
                "requested_capabilities": ["telemetry"],
            }
        )
    )
    ent = tmp_path / "e.json"
    subprocess.run(
        ["make", "-C", str(ROLE_ROOT), "authz-sign", f"IDENTITY={ident}", "CAPS=telemetry", f"OUT={ent}"], check=True
    )
    assert ent.is_file()
    # registry verify
    reg = tmp_path / "r.json"
    reg.write_text(
        json.dumps({"role": "registry", "schema_version": "1.0.0", "authorizations": [json.loads(ent.read_text())]})
    )
    subprocess.run(["make", "-C", str(ROLE_ROOT), "registry-verify", f"REGISTRY={reg}"], check=True)
    # wg render
    wg = tmp_path / "wg0.conf"
    subprocess.run(["make", "-C", str(ROLE_ROOT), "wg-render-master", f"REGISTRY={reg}", f"OUT={wg}"], check=True)
    assert wg.is_file()
