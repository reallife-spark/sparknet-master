"""The Master overlay anchor: it must come back at boot, kernel module or not.

The overlay is the transport every Master decision travels over, so losing it on
reboot makes the Master unreachable. On Jetson/L4T hosts (`CONFIG_WIREGUARD=n`)
`wg-quick` cannot restore it, so the anchor delegates to the peer's userspace
bring-up helper, resolved by path — this role keeps one implementation and never
a copy, exactly as it loads the peer's services.
"""

from __future__ import annotations

import stat
import subprocess
from pathlib import Path

VAULT_ROOT = Path(__file__).resolve().parent.parent
ANCHOR = VAULT_ROOT / "scripts" / "sparknet-master-wireguard-anchor.sh"
UNIT = VAULT_ROOT / "systemd" / "sparknet-master-wireguard-anchor.service"
MAKEFILE = VAULT_ROOT / "Makefile"


def test_master_anchor_exists_and_is_executable() -> None:
    assert ANCHOR.is_file()
    assert stat.S_IMODE(ANCHOR.stat().st_mode) & 0o111


def test_master_anchor_uses_the_peers_bringup_by_path() -> None:
    text = ANCHOR.read_text()
    assert "sparknet-wg-bringup.sh" in text
    assert "SPARKNET_PEER_NODE" in text, "the peer helper must be resolved by path, never copied in"
    assert "wg-quick" not in text, "wg-quick cannot bring the overlay up on a kernel-module-less host"


def test_master_anchor_pins_and_unlocks_the_config() -> None:
    text = ANCHOR.read_text()
    assert "chattr +i" in text, "the overlay config must be pinned"
    assert "chattr -i" in text, "a previously pinned config must be unlocked before re-pinning"


def test_master_anchor_repins_on_failure() -> None:
    """A failed run must not leave the Master's live overlay config writable.

    The Master pins its config, so losing the pin would let the overlay be
    dropped — the anchor must restore it on any non-zero exit between the unlock
    and the final pin.
    """
    text = ANCHOR.read_text()
    trap_line = next((ln for ln in text.splitlines() if ln.strip().startswith("trap ")), "")
    assert "EXIT" in trap_line, f"the anchor must trap on EXIT, got: {trap_line!r}"
    handler_name = trap_line.split()[1]
    handler_body = text.split(f"{handler_name}()", 1)[1].split("\n}", 1)[0]
    assert "chattr +i" in handler_body, "the failure handler must re-pin the config"


def test_master_anchor_help_is_safe() -> None:
    proc = subprocess.run([str(ANCHOR), "--help"], capture_output=True, text=True, check=False, timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.stdout.strip()


def test_overlay_anchor_unit_is_installed_and_enabled_by_make() -> None:
    assert UNIT.is_file()
    makefile = (VAULT_ROOT / "Makefile").read_text()
    assert UNIT.name in makefile, "the unit must be in the Makefile's UNITS set, or nothing enables it"
    unit_text = UNIT.read_text()
    assert "/usr/local/libexec/sparknet/sparknet-master-wireguard-anchor" in unit_text
    assert "WantedBy=multi-user.target" in unit_text


def test_overlay_anchor_is_not_written_as_a_user_service() -> None:
    """It needs CAP_NET_ADMIN; a User= line would make it fail to bring the tunnel up."""
    assert "User=" not in UNIT.read_text()


def test_master_anchor_script_is_executable() -> None:
    assert stat.S_IMODE(ANCHOR.stat().st_mode) & stat.S_IXUSR
