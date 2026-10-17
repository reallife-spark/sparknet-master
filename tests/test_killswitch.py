from __future__ import annotations

from pathlib import Path

ROLE_ROOT = Path(__file__).resolve().parent.parent
SERVICES = ROLE_ROOT / "services"


def test_killswitch_root_gated():
    code = (SERVICES / "sparknet-killswitch.py").read_text()
    assert "geteuid" in code
