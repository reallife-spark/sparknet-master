"""Step 4: Master-side wg0 rendering rules."""

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
    if STATE is not None: return STATE
    probe = subprocess.run(
        ["bash", "-c", f'. "{ROLE_ROOT}/scripts/sparknet-master-env.sh" >/dev/null && printf "%s" "$SPARKNET_STATE_DIR"'],
        capture_output=True, text=True, check=True,
        env={**os.environ, "HOME": os.environ.get("HOME","/nonexistent")},
    )
    STATE = Path(probe.stdout.strip()); return STATE

needs_keys = pytest.mark.skipif(
    not all((state_dir()/ "keys"/f"{n}.ed25519").is_file() for n in ("cluster","operational","identity")),
    reason="keys missing"
)

@needs_keys
def test_wg_render_excludes_revoked_and_enforces_32_and_idempotent(tmp_path):
    # valid peer
    ident = tmp_path / "id.json"
    ident.write_text(json.dumps({
        "node_id":"p1","role":"peer",
        "wireguard_public_key_b64":"C"*44,
        "overlay_ipv4":"10.100.0.11/32",
        "requested_capabilities":["telemetry"],
    }))
    ent = tmp_path / "e.json"
    subprocess.run(["make","-C",str(ROLE_ROOT),"authz-sign",f"IDENTITY={ident}","CAPS=telemetry",f"OUT={ent}"], check=True)
    # revoked
    ent_r = tmp_path / "er.json"
    subprocess.run(["make","-C",str(ROLE_ROOT),"revoke",f"IDENTITY={ident}",f"OUT={ent_r}"], check=True)
    reg = tmp_path / "r.json"
    reg.write_text(json.dumps({"role":"registry","schema_version":"1.0.0","authorizations":[json.loads(ent.read_text()), json.loads(ent_r.read_text())]}))
    wg1 = tmp_path / "wg1.conf"; wg2 = tmp_path / "wg2.conf"
    subprocess.run(["make","-C",str(ROLE_ROOT),"wg-render-master",f"REGISTRY={reg}",f"OUT={wg1}"], check=True)
    subprocess.run(["make","-C",str(ROLE_ROOT),"wg-render-master",f"REGISTRY={reg}",f"OUT={wg2}"], check=True)
    assert wg1.read_text() == wg2.read_text()  # idempotent
    txt = wg1.read_text()
    assert "10.100.0.11/32" in txt  # valid included
    # revoked entry means we only have the valid one stanza present once
    # count peer stanzas
    assert txt.count("[Peer]") == 1
