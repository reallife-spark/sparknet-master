"""Step 7: 8090 listener constraints."""

from __future__ import annotations

from pathlib import Path

ROLE_ROOT = Path(__file__).resolve().parent.parent
SERVICES = ROLE_ROOT / "services"


def test_listener_binds_overlay_only():
    # Import by reading the module logic
    code = (SERVICES / "sparknet-registry-listener.py").read_text()
    assert "10.100.0.1" in code
    assert "0.0.0.0" not in code
