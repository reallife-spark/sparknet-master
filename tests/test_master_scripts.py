"""The master role's scripts: thin, and correct about where keys come from.

Two properties, both of which a future edit can quietly break:

1. **No duplicated implementation.** The scripts must not contain cryptography or
   key parsing. `Step 16`'s original DoD said they should delegate to the peer's
   scripts, which turned out to be impossible — `peer-node/scripts/sparknet-env.sh`
   hardcodes `SPARKNET_ROLE="peer"` and its own vault root, and
   `sparknet-keygen.sh` produces a single `ed25519-<role>` seed rather than the
   three named keys this role needs. So the achievable form of "thin" is: delegate
   to `shared/sparknet-authz.py`, which *is* role-agnostic, and say in the header
   which peer script could not be delegated to and why.

2. **Keys actually work.** The keygen is exercised end to end here, into a tmp
   state dir, and the generated material is verified through `authz` — because a
   script that writes plausible-looking base64 to the wrong filenames is a silent
   failure that only shows up as a rejected signature much later.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROLE_ROOT = Path(__file__).resolve().parent.parent
FABRIC_ROOT = ROLE_ROOT.parent
SCRIPTS = ROLE_ROOT / "scripts"

MASTER_SCRIPTS = ("sparknet-master-env.sh", "sparknet-master-keygen.sh")

#: Keys this role needs, and what each is allowed to sign.
KEY_ROLES = ("cluster", "operational", "identity")


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    # The sys.modules registration is not optional: @dataclass resolves its own
    # module through sys.modules and fails with an AttributeError about __dict__
    # that names neither the cause nor the file.
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def authz():
    return _load("sparknet_authz_scripts", FABRIC_ROOT / "shared" / "sparknet-authz.py")


def test_every_master_script_exists_and_is_executable():
    for name in MASTER_SCRIPTS:
        path = SCRIPTS / name
        assert path.is_file(), f"{name} is missing from master-node/scripts/"
        assert os.access(path, os.X_OK), f"{name} is not executable"


def test_scripts_contain_no_cryptography_of_their_own():
    """The invariant behind "thin".

    An earlier version of the keygen had a Python heredoc that built Ed25519 keys
    itself. It worked, and it was still a second implementation of key generation
    in the one role whose whole claim is that it handles keys correctly.
    """
    for name in MASTER_SCRIPTS:
        raw = (SCRIPTS / name).read_text()
        # Strip comment lines first. The header of these scripts *discusses*
        # cryptography in prose ("this script contains no cryptography"), and a
        # substring check over the whole file would flag its own explanation.
        code = "\n".join(line for line in raw.splitlines() if not line.lstrip().startswith("#"))
        for forbidden in (
            "Ed25519PrivateKey",
            "from_private_bytes",
            "from cryptography",
            "import cryptography",
            "hmac",
            "hashlib.sha256(",
        ):
            assert forbidden not in code, (
                f"{name} contains {forbidden!r} outside a comment; key work belongs in shared/sparknet-authz.py"
            )


def test_keygen_delegates_to_the_shared_implementation():
    text = (SCRIPTS / "sparknet-master-keygen.sh").read_text()
    assert "sparknet-authz.py" in text, "the keygen must call the shared implementation by path"
    assert "generate-keypair" in text, "and must use its keypair subcommand, not a hand-rolled equivalent"


def test_keygen_header_says_why_it_cannot_delegate_to_the_peer():
    """The unsatisfiable half of the DoD is recorded rather than quietly dropped."""
    text = (SCRIPTS / "sparknet-master-keygen.sh").read_text()
    header = text.split("set -euo pipefail", 1)[0]
    assert "peer" in header.lower(), (
        "the header must state the peer script relationship, since a reader will "
        "otherwise assume the omission was an oversight"
    )


def test_env_script_resolves_this_role_and_the_peer():
    result = subprocess.run(
        [str(SCRIPTS / "sparknet-master-env.sh")],
        capture_output=True,
        text=True,
        check=True,
    )
    out = result.stdout
    assert "master-node" in out
    assert "peer-node" in out, "the parity loader's dependency must be reported"
    assert str(ROLE_ROOT) in out


def test_keygen_writes_three_keys_that_load_and_sign(tmp_path, authz):
    """End to end: run the script, then use what it wrote.

    Asserting only that files appeared would pass for a script writing garbage, so
    each key is loaded by `authz` and required to produce a verifiable signature.
    """
    result = subprocess.run(
        [str(SCRIPTS / "sparknet-master-keygen.sh")],
        capture_output=True,
        text=True,
        env={**os.environ, "SPARKNET_STATE_DIR": str(tmp_path)},
    )
    assert result.returncode == 0, result.stderr

    keys_dir = tmp_path / "keys"
    for role in KEY_ROLES:
        priv = keys_dir / f"{role}.ed25519"
        pub = keys_dir / f"{role}.pub.b64"
        assert priv.is_file(), f"{role} private key not written"
        assert pub.is_file(), f"{role} public key not written"

        # Mode is the control that stops a key being read by another local account.
        assert priv.stat().st_mode & 0o077 == 0, f"{role}.ed25519 must be 0600; a readable private key is a leaked one"

        key = authz.private_key_from_b64(priv.read_text().strip())
        assert authz.public_key_b64(key.public_key()) == pub.read_text().strip(), (
            f"{role} public key does not correspond to its private key"
        )

        message = f"canonical bytes for {role}".encode()
        signature = authz.sign_bytes(key, message)
        assert authz.verify_signature(key.public_key(), signature, message)
        assert not authz.verify_signature(key.public_key(), signature, b"tampered")


def test_keygen_never_writes_into_the_vault(tmp_path, authz):
    """Given a state dir elsewhere, nothing at all lands in the vault.

    The docstring here used to claim "the state dir is outside the vault by
    construction". That was true only while `$SPARKNET_STATE_DIR` had never been
    exercised — it defaults to `<role>/.state`, which is *inside* the vault, and
    Step 1 then generated real keys there. The blanket `rglob("*.ed25519")` below
    started failing on the legitimate ones, and the obvious "fix" was to weaken the
    assertion until it went green.

    Split into the two claims instead. With the state dir pointed elsewhere,
    absolutely nothing may appear in the vault — unchanged, and still strict.
    Where the keys *do* go by default is asserted separately in
    `test_step1_keypair.py`, which knows the state dir exists and polices it rather
    than pretending it does not.
    """
    before = {p for p in ROLE_ROOT.rglob("*") if p.is_file()}
    subprocess.run(
        [str(SCRIPTS / "sparknet-master-keygen.sh")],
        capture_output=True,
        text=True,
        check=True,
        env={**os.environ, "SPARKNET_STATE_DIR": str(tmp_path)},
    )
    after = {p for p in ROLE_ROOT.rglob("*") if p.is_file()}
    assert after == before, f"keygen touched the vault: {after ^ before}"

    state_dir = os.environ.get("SPARKNET_STATE_DIR", str(ROLE_ROOT / ".state"))
    strays = [p for p in ROLE_ROOT.rglob("*.ed25519") if not str(p).startswith(str(state_dir))]
    assert not strays, f"a key landed inside the vault, outside the state dir: {strays}"


def test_keygen_is_idempotent(tmp_path):
    """Re-running must not rotate keys: a regenerated operational key would
    invalidate every registry entry the old one signed."""
    env = {**os.environ, "SPARKNET_STATE_DIR": str(tmp_path)}
    subprocess.run([str(SCRIPTS / "sparknet-master-keygen.sh")], capture_output=True, text=True, check=True, env=env)
    first = (tmp_path / "keys" / "operational.ed25519").read_text()
    subprocess.run([str(SCRIPTS / "sparknet-master-keygen.sh")], capture_output=True, text=True, check=True, env=env)
    second = (tmp_path / "keys" / "operational.ed25519").read_text()
    assert first == second, "the keygen replaced an existing key; rotation must be deliberate"
