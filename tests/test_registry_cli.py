"""Step 3 CLI sanity tests.

These are lightweight because Step 3's DoD asks for the surface to exist and
function; the heavy enforcement is already in the schema and in authz itself.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

ROLE_ROOT = Path(__file__).resolve().parent.parent
FABRIC_ROOT = ROLE_ROOT.parent
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


def _op_pub() -> str:
    return (state_dir() / "keys" / "operational.pub.b64").read_text().strip()


@needs_keys
def test_authz_sign_produces_valid_entry(tmp_path):
    ident = tmp_path / "id.json"
    ident.write_text(
        json.dumps(
            {
                "node_id": "t",
                "role": "peer",
                "wireguard_public_key_b64": "A" * 44,
                "overlay_ipv4": "10.100.0.9/32",
                "requested_capabilities": ["telemetry"],
            }
        )
    )
    out = tmp_path / "e.json"
    subprocess.run(
        ["make", "-C", str(ROLE_ROOT), "authz-sign", f"IDENTITY={ident}", "CAPS=telemetry", f"OUT={out}"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert out.is_file()
    e = json.loads(out.read_text())
    assert "signature_b64" in e and "fingerprint" in e


@needs_keys
def test_registry_verify_ok(tmp_path):
    ident = tmp_path / "id.json"
    ident.write_text(
        json.dumps(
            {
                "node_id": "t2",
                "role": "peer",
                "wireguard_public_key_b64": "B" * 44,
                "overlay_ipv4": "10.100.0.10/32",
                "requested_capabilities": ["telemetry"],
            }
        )
    )
    ent = tmp_path / "e.json"
    subprocess.run(
        ["make", "-C", str(ROLE_ROOT), "authz-sign", f"IDENTITY={ident}", "CAPS=telemetry", f"OUT={ent}"],
        check=True,
        capture_output=True,
    )
    reg = tmp_path / "r.json"
    reg.write_text(
        json.dumps(
            {
                "role": "registry",
                "schema_version": "1.0.0",
                "master_public_key_b64": _op_pub(),
                "authorizations": [json.loads(ent.read_text())],
            }
        )
    )
    res = subprocess.run(
        ["make", "-C", str(ROLE_ROOT), "registry-verify", f"REGISTRY={reg}"], capture_output=True, text=True, check=True
    )
    assert "OK" in res.stdout or res.returncode == 0


@needs_keys
def test_wg_render_limits_to_32(tmp_path):
    ident = tmp_path / "id.json"
    ident.write_text(
        json.dumps(
            {
                "node_id": "t3",
                "role": "peer",
                "wireguard_public_key_b64": "C" * 44,
                "overlay_ipv4": "10.100.0.11/32",
                "requested_capabilities": ["telemetry"],
            }
        )
    )
    ent = tmp_path / "e.json"
    subprocess.run(
        ["make", "-C", str(ROLE_ROOT), "authz-sign", f"IDENTITY={ident}", "CAPS=telemetry", f"OUT={ent}"],
        check=True,
        capture_output=True,
    )
    reg = tmp_path / "r.json"
    reg.write_text(
        json.dumps(
            {
                "role": "registry",
                "schema_version": "1.0.0",
                "master_public_key_b64": _op_pub(),
                "authorizations": [json.loads(ent.read_text())],
            }
        )
    )
    wg = tmp_path / "wg0.conf"
    subprocess.run(
        ["make", "-C", str(ROLE_ROOT), "wg-render-master", f"REGISTRY={reg}", f"OUT={wg}"],
        check=True,
        capture_output=True,
    )
    assert wg.is_file()
    txt = wg.read_text()
    assert "AllowedIPs = 10.100.0.11/32" in txt


@needs_keys
def test_capabilities_cannot_inject_python_code(tmp_path):
    """CAPS used to be interpolated into a Python here-doc after the key load."""
    ident = tmp_path / "id.json"
    ident.write_text(
        json.dumps(
            {
                "node_id": "inject",
                "role": "peer",
                "wireguard_public_key_b64": "D" * 44,
                "overlay_ipv4": "10.100.0.12/32",
                "requested_capabilities": ["telemetry"],
            }
        )
    )
    marker = tmp_path / "pwned"
    caps = f"telemetry'); open('{marker}', 'w').write('owned'); ('"
    out = tmp_path / "e.json"
    result = subprocess.run(
        ["make", "-C", str(ROLE_ROOT), "authz-sign", f"IDENTITY={ident}", f"CAPS={caps}", f"OUT={out}"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert not marker.exists()
    assert not out.exists()
