"""Shared fixtures for the master-node suite.

The state dir is resolved here, once, by asking the same env script production
asks. It used to be hardcoded as `<role>/.state` in three separate test files.

That hardcoding was not merely untidy. It was load-bearing in the wrong
direction: Step 1 generated the Master's real keypair into `<role>/.state/keys`,
which sits under the tree `configs/admin-surface/docker-compose.admin.yml`
bind-mounts read-only into an LLM-driven container. The keys had to move out to
`$XDG_STATE_HOME`, and a test that resolved the state dir itself would have
followed the move while a hardcoded one would have gone on asserting the old
location — silently passing about a directory that no longer holds anything.

Resolution therefore goes through `scripts/sparknet-master-env.sh`, and
`test_admin_surface.py::test_the_compose_mounts_do_not_reach_the_signing_key`
additionally refuses a state dir that is inside any admin bind mount.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROLE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROLE_ROOT.parent / "shared"))


def resolve_state_dir() -> Path:
    """Ask the env script, exactly as keygen and the signer do."""
    probe = subprocess.run(
        [
            "bash",
            "-c",
            f'. "{ROLE_ROOT}/scripts/sparknet-master-env.sh" >/dev/null && printf "%s" "$SPARKNET_STATE_DIR"',
        ],
        capture_output=True,
        text=True,
        check=True,
        # HOME is pinned so a test run under an unusual environment still resolves
        # a real path rather than failing on an unset HOME.
        env={**os.environ, "HOME": os.environ.get("HOME", "/nonexistent")},
    )
    resolved = probe.stdout.strip()
    assert resolved, "the env script did not resolve SPARKNET_STATE_DIR"
    return Path(resolved)


@pytest.fixture(scope="session")
def state_dir() -> Path:
    return resolve_state_dir()
