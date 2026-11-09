"""Step 4: Master-side wg0 rendering rules."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROLE_ROOT = Path(__file__).resolve().parent.parent
FABRIC_ROOT = ROLE_ROOT.parent
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
def test_wg_render_excludes_revoked_and_enforces_32_and_idempotent(tmp_path):
    # valid peer
    ident = tmp_path / "id.json"
    ident.write_text(
        json.dumps(
            {
                "node_id": "p1",
                "role": "peer",
                "wireguard_public_key_b64": "C" * 44,
                "overlay_ipv4": "10.100.0.11/32",
                "requested_capabilities": ["telemetry"],
            }
        )
    )
    ent = tmp_path / "e.json"
    subprocess.run(
        ["make", "-C", str(ROLE_ROOT), "authz-sign", f"IDENTITY={ident}", "CAPS=telemetry", f"OUT={ent}"], check=True
    )
    # revoked
    ent_r = tmp_path / "er.json"
    subprocess.run(["make", "-C", str(ROLE_ROOT), "revoke", f"IDENTITY={ident}", f"OUT={ent_r}"], check=True)
    reg = tmp_path / "r.json"
    reg.write_text(
        json.dumps(
            {
                "role": "registry",
                "schema_version": "1.0.0",
                "authorizations": [json.loads(ent.read_text()), json.loads(ent_r.read_text())],
            }
        )
    )
    wg1 = tmp_path / "wg1.conf"
    wg2 = tmp_path / "wg2.conf"
    subprocess.run(["make", "-C", str(ROLE_ROOT), "wg-render-master", f"REGISTRY={reg}", f"OUT={wg1}"], check=True)
    subprocess.run(["make", "-C", str(ROLE_ROOT), "wg-render-master", f"REGISTRY={reg}", f"OUT={wg2}"], check=True)
    assert wg1.read_text() == wg2.read_text()  # idempotent
    txt = wg1.read_text()
    assert "10.100.0.11/32" in txt  # valid included
    # revoked entry means we only have the valid one stanza present once
    # count peer stanzas
    assert txt.count("[Peer]") == 1


def _signed_registry(tmp_path, overlay: str, node_id: str) -> Path:
    """Sign one identity at the given overlay and wrap it in a registry."""
    ident = tmp_path / "id.json"
    ident.write_text(
        json.dumps(
            {
                "node_id": node_id,
                "role": "peer",
                "wireguard_public_key_b64": "E" * 44,
                "overlay_ipv4": overlay,
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
                "authorizations": [json.loads(ent.read_text())],
            }
        )
    )
    return reg


@needs_keys
def test_no_stanza_can_carry_a_mask_wider_than_one_32(tmp_path):
    """DoD (5): a wider mask would let a peer source-spoof a sibling."""
    reg = _signed_registry(tmp_path, "10.100.0.0/24", "wide")
    wg = tmp_path / "wg0.conf"
    subprocess.run(
        ["make", "-C", str(ROLE_ROOT), "wg-render-master", f"REGISTRY={reg}", f"OUT={wg}"],
        check=True,
        capture_output=True,
    )
    txt = wg.read_text()
    assert "[Peer]" not in txt, f"a /24 entry was rendered:\n{txt}"
    assert "10.100.0.0/24" not in txt
    for line in txt.splitlines():
        if "AllowedIPs" in line:
            assert line.strip().endswith("/32"), line


@needs_keys
def test_an_entry_that_does_not_verify_is_never_rendered(tmp_path):
    """DoD (3): unsigned or tampered entries fall out of the render."""
    reg = _signed_registry(tmp_path, "10.100.0.14/32", "tampered")
    data = json.loads(reg.read_text())
    data["authorizations"][0]["signature_b64"] = "A" * 60  # not this entry's sig
    reg.write_text(json.dumps(data))
    wg = tmp_path / "wg0.conf"
    subprocess.run(
        ["make", "-C", str(ROLE_ROOT), "wg-render-master", f"REGISTRY={reg}", f"OUT={wg}"],
        check=True,
        capture_output=True,
    )
    txt = wg.read_text()
    assert "[Peer]" not in txt, f"a tampered entry was rendered:\n{txt}"


@needs_keys
def test_an_expired_entry_is_never_rendered(tmp_path):
    """DoD (3): expired entries, though perfectly signed, fall out too."""
    state = state_dir()
    ident = tmp_path / "id.json"
    ident.write_text(
        json.dumps(
            {
                "node_id": "expired",
                "role": "peer",
                "wireguard_public_key_b64": "G" * 44,
                "overlay_ipv4": "10.100.0.15/32",
                "requested_capabilities": ["telemetry"],
            }
        )
    )
    ent = tmp_path / "e.json"
    # signed for real, with a ttl that is already over
    subprocess.run(
        [
            sys.executable,
            str(FABRIC_ROOT / "shared" / "sparknet-authz.py"),
            "sign",
            str(ident),
            "--master-key",
            str(state / "keys" / "operational.ed25519"),
            "--capabilities",
            "telemetry",
            "--ttl-days",
            "-1",
            "--out",
            str(ent),
        ],
        check=True,
        capture_output=True,
    )
    reg = tmp_path / "r.json"
    reg.write_text(
        json.dumps(
            {
                "role": "registry",
                "schema_version": "1.0.0",
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
    txt = wg.read_text()
    assert "[Peer]" not in txt, f"an expired entry was rendered:\n{txt}"


@needs_keys
def test_registry_and_out_paths_cannot_inject_python(tmp_path):
    reg = tmp_path / "reg'quote.json"
    reg.write_text(json.dumps({"schema_version": "1.0.0", "authorizations": []}))
    out = tmp_path / "out'quote.conf"
    marker = tmp_path / "pwned"
    subprocess.run(
        ["make", "-C", str(ROLE_ROOT), "wg-render-master", f"REGISTRY={reg}", f"OUT={out}"],
        check=True,
        capture_output=True,
    )
    assert out.is_file()
    assert not marker.exists()
