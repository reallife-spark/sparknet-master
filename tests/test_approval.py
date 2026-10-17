"""Step 5: guard approval issuance."""

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
def test_approval_issue_tracks_nonces_and_deliver_records(tmp_path):
    content = tmp_path / "c.txt"
    content.write_text("hello")
    app1 = tmp_path / "a1.json"
    app2 = tmp_path / "a2.json"
    issue = ["make", "-C", str(ROLE_ROOT), "approval-issue", "TARGET=/x", f"CONTENT={content}"]
    subprocess.run([*issue, f"OUT={app1}"], check=True)
    subprocess.run([*issue, f"OUT={app2}"], check=True)
    # different nonces
    assert json.loads(app1.read_text())["nonce"] != json.loads(app2.read_text())["nonce"]
    # nonce file tracks
    nf = state_dir() / "approval_nonces.json"
    assert nf.is_file()
    nonces = json.loads(nf.read_text())
    assert len(nonces) >= 2
    # deliver
    fp = json.loads(app1.read_text())["content_digest"][:16]
    deliv = tmp_path / "d.json"
    deliver = ["make", "-C", str(ROLE_ROOT), "approval-deliver", f"FINGERPRINT={fp}", f"PAYLOAD={app1}"]
    subprocess.run([*deliver, f"OUT={deliv}"], check=True)
    d = json.loads(deliv.read_text())
    assert d["fingerprint"] == fp
