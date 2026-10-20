"""The isolated signer: what it signs, what it refuses, and what cannot reach it.

Step 17 is the step where a bug in this role stops being a bug. Every other
service here failing means a node misbehaves; the signer failing means something
that should not have been able to authorise the fabric did.

So these tests are mostly about refusals. A test that only proves the happy path
would pass against a signer that also signs arbitrary bytes, and that is the
specific failure this step exists to prevent.

Three clusters:

1. **Root binding** — the signer pins one trust root at start and refuses anything
   else. A forged, stale, or valid-but-another-node root must all be refused.
2. **Refusals** — key permissions, socket path, caller-supplied bytes, unknown
   capabilities, expired approvals.
3. **Topology** — the signer is unreachable from the peer surface. This is a
   statement about the file layout and imports, and it is the weakest of the three:
   it proves the wiring, not that a real deployment held. See
   `test_deployed_containment_is_not_verified_here`.

Every key in this file is generated per-test into `tmp_path`. No test reads or
writes anything under the real state directory, and no fixture key is a real node's.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import itertools
import json
import os
import re
import shlex
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROLE_ROOT = Path(__file__).resolve().parent.parent
FABRIC_ROOT = ROLE_ROOT.parent
SHARED = FABRIC_ROOT / "shared"
SIGNER_PATH = ROLE_ROOT / "services" / "sparknet-signer.py"
STATE_DIR = ROLE_ROOT / ".state"

CLOCK = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    # Not optional: @dataclass resolves its own module through sys.modules and
    # fails with an AttributeError about __dict__ that names neither cause nor file.
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def authz():
    module = _load("signer_test_authz", SHARED / "sparknet-authz.py")
    # _entry() needs the real fingerprint() to build a consistent entry, and the
    # signer module was loaded against a *different* instance of this file, so it
    # cannot be reached through signer_module.
    _MODULE_CACHE["authz"] = module
    return module


@pytest.fixture(scope="module")
def consensus():
    return _load("signer_test_consensus", SHARED / "sparknet-consensus.py")


@pytest.fixture(scope="module")
def signer_module():
    return _load("signer_under_test", SIGNER_PATH)


def _keypair(seed: str) -> tuple[str, str]:
    """A real Ed25519 keypair from a fixed seed, base64. Deterministic and genuine."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed.encode()).digest())
    private = base64.b64encode(
        key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
    ).decode()
    public = base64.b64encode(
        key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).decode()
    return private, public


MASTER = "alpha"


def _unsigned_root(master: str = MASTER, nonce: str = "root-1", previous_root_id: str = "") -> dict:
    """A root's claims, with no signatures yet.

    Built unsigned on purpose. An earlier version returned a *signed* root, and the
    test that then tried to re-sign it with attacker keys hit `merge_root_signatures`'
    equivocation refusal — which was the fixture's fault, and hid the behaviour the
    test was meant to check.
    """
    members = []
    for name in ("alpha", "beta", "gamma"):
        members.append(
            {
                "node_id": name,
                "fingerprint": hashlib.sha256(f"fp-{name}".encode()).hexdigest(),
                "wireguard_pubkey": _keypair(f"wg-{name}")[1],
                "cluster_pubkey": _keypair(f"cluster-{name}")[1],
            }
        )
    return {
        "version": "1.1",
        "nonce": nonce,
        "formed_at": CLOCK.isoformat(),
        "members": members,
        "master_node_id": master,
        "master_pubkey": _keypair(f"operational-{master}")[1],
        "previous_root_id": previous_root_id,
    }


def _sign(consensus, root: dict, cluster_key_seed: str = "cluster") -> dict:
    """Sign a root one key at a time and merge, using the production ceremony.

    `cluster_key_seed` is what makes a forged root forged: pass something else and
    the members' *names* stay the same while the keys that signed are strangers.
    """
    maps = [
        consensus.sign_root(root, m["node_id"], _keypair(f"{cluster_key_seed}-{m['node_id']}")[0])
        for m in root["members"]
    ]
    return consensus.merge_root_signatures(root, maps)


def _valid_root(consensus, master: str = MASTER, nonce: str = "root-1", previous_root_id: str = "") -> dict:
    return _sign(consensus, _unsigned_root(master=master, nonce=nonce, previous_root_id=previous_root_id))


@pytest.fixture
def operational_key(tmp_path):
    private, public = _keypair(f"operational-{MASTER}")
    path = tmp_path / "operational.ed25519"
    path.write_text(private + "\n")
    path.chmod(0o600)
    return path, public


@pytest.fixture
def root(consensus, authz):
    return _valid_root(consensus)


@pytest.fixture
def signer(signer_module, operational_key, root, authz, consensus, tmp_path):
    key_path, _ = operational_key
    return signer_module.Signer(
        MASTER,
        key_path,
        root,
        authz,
        consensus,
        tmp_path / "ledger.json",
        clock=lambda: CLOCK,
    )


def _identity(capabilities=("telemetry",)) -> dict:
    return {
        "node_id": "peer-1",
        "role": "peer",
        "wireguard_public_key_b64": _keypair("peer-1-wg")[1],
        "overlay_ipv4": "10.100.0.11/32",
        "requested_capabilities": list(capabilities),
    }


def _entry(capabilities=("telemetry",), revoked: bool = False, fingerprint: str | None = None) -> dict:
    """A registry entry the way authz requires one to be filed.

    The fingerprint is derived from the identity, not passed in. Taking it as an
    argument is how a test ends up filing an identity under a hash of something
    else, which authz then refuses as `unknown_fingerprint` — a confusing way to
    learn a rule the signer is supposed to enforce rather than discover.
    """
    identity = _identity(capabilities)
    return {
        "fingerprint": fingerprint or _MODULE_CACHE["authz"].fingerprint(identity),
        "identity": identity,
        "capabilities": list(capabilities),
        "issued_at": CLOCK.isoformat(),
        "expires_at": (CLOCK + timedelta(days=30)).isoformat(),
        "revoked": revoked,
    }


_MODULE_CACHE: dict = {}


def _job(mode: str = "decompose", expires_in_minutes: int = 10) -> dict:
    """A cluster job the way `authz.cluster_job_message` requires one.

    `subtasks` is populated because the partition is inside the signature: a job
    without a partition is exactly the replayable bare job-id this op must refuse.
    """
    return {
        "job_id": "job-1",
        "conversation_id": "conv-1",
        "initiator_node_id": "peer-1",
        "created_at": CLOCK.isoformat(),
        "expires_at": (CLOCK + timedelta(minutes=expires_in_minutes)).isoformat(),
        "mode": mode,
        "prompt": "summarise the incident timeline",
        "running_summary": "",
        "context": {"index": "master-local"},
        "budget": {"max_tokens": 2048, "deadline_s": 60},
        "subtasks": [
            {"node_id": "beta", "role": "gather", "prompt": "collect logs"},
            {"node_id": "gamma", "role": "gather", "prompt": "collect metrics"},
        ],
    }


# --- 1. root binding ---------------------------------------------------------


def test_it_signs_for_the_node_its_root_names(signer):
    response = signer.handle({"op": "root-id"})
    assert response["ok"] and response["node_id"] == MASTER


def test_the_happy_path_signs_a_registry_entry(signer, authz, root):
    response = signer.handle({"op": "sign-registry-entry", "root_id": signer.root_id, "entry": _entry()})
    assert response["ok"], response.get("error")
    entry = response["entry"]
    assert entry["fingerprint"] == authz.fingerprint(entry["identity"])

    # The signature must satisfy the real verifier, not just exist.
    # Two things here are easy to get wrong and both fail as `malformed_record`
    # rather than as a signature error, which is a misleading way to learn them:
    # evaluate() takes an Ed25519PublicKey object, not base64 text, and the
    # registry is {"authorizations": [entry]}, not a dict keyed by fingerprint.
    decision = authz.evaluate(
        entry["identity"],
        {"authorizations": [entry]},
        authz.public_key_from_b64(_keypair(f"operational-{MASTER}")[1]),
        now=CLOCK,
    )
    assert decision.allowed, f"the signed entry was refused by authz: {decision.reason}"


def test_it_refuses_a_forged_root(signer_module, operational_key, authz, consensus, tmp_path):
    """A root naming this node and this key, signed by three strangers.

    The membership claims are the genuine ones. Only the signatures are wrong, which
    is the attack that matters: nothing about the document looks wrong to a reader
    or to a diff.
    """
    key_path, public = operational_key
    forged = _sign(consensus, _unsigned_root(nonce="forged"), cluster_key_seed="attacker")
    # The root still names this node and this key — the claim is intact.
    assert forged["master_node_id"] == MASTER
    assert forged["master_pubkey"] == public

    with pytest.raises(signer_module.SignerError, match="not valid"):
        signer_module.Signer(MASTER, key_path, forged, authz, consensus, tmp_path / "l.json")


def test_a_stale_root_is_valid_on_its_own_which_is_the_problem(
    signer_module, operational_key, authz, consensus, root, tmp_path
):
    """Establishes why the plain check is not enough.

    The old root names this node, names this key, and carries all three member
    signatures. `verify_root` accepts it. So "is this root well-formed" cannot
    detect that the cluster has since re-formed, and a signer relying on that alone
    would keep signing for a Master role that has moved.
    """
    assert consensus.verify_root(root)[0], "if this ever fails, the staleness tests below are testing nothing"


def test_restarting_under_the_same_root_is_not_a_revert(signer_module, operational_key, authz, consensus, tmp_path):
    """Establishes the boundary: a plain restart must NOT be refused.

    Stated first because it is the case that a blunt staleness check gets wrong.
    The signer's root id equals the root already in the ledger, so nothing has
    moved and refusing here would make the signer impossible to restart.
    """
    key_path, _ = operational_key
    root = _valid_root(consensus, nonce="root-a")
    ledger = tmp_path / "ledger.json"
    first = signer_module.Signer(MASTER, key_path, root, authz, consensus, ledger, clock=lambda: CLOCK)
    assert first.handle({"op": "sign-registry-entry", "root_id": first.root_id, "entry": _entry()})["ok"]

    restarted = signer_module.Signer(MASTER, key_path, root, authz, consensus, ledger, clock=lambda: CLOCK)
    assert restarted.root_id == first.root_id


def test_it_refuses_to_be_pointed_back_at_a_superseded_root(signer_module, operational_key, authz, consensus, tmp_path):
    """The real revert: the cluster re-formed, and someone points the signer back.

    A valid root alone cannot detect this — the old root still verifies. The
    chain and the ledger together are what remember which root is in force: a
    *different* id than the one already recorded means the Master role has
    moved, and unless that id descends from the ledger's last root the change
    is a stranger or a trip backward, not a re-formation.
    """
    key_path, _ = operational_key
    old_root = _valid_root(consensus, nonce="root-old")
    new_root = _valid_root(consensus, nonce="root-new")
    ledger = tmp_path / "ledger.json"

    # First term signs under the old root, recording its id.
    first = signer_module.Signer(MASTER, key_path, old_root, authz, consensus, ledger, clock=lambda: CLOCK)
    first.handle({"op": "sign-registry-entry", "root_id": first.root_id, "entry": _entry()})

    # The cluster re-forms. Adopting the new root is allowed, but only when said.
    with pytest.raises(signer_module.SignerError, match="accept-requalification"):
        signer_module.Signer(MASTER, key_path, new_root, authz, consensus, ledger, clock=lambda: CLOCK)
    second_term = signer_module.Signer(
        MASTER,
        key_path,
        new_root,
        authz,
        consensus,
        ledger,
        clock=lambda: CLOCK,
        allow_requalification=True,
    )
    # It has to sign something: the ledger remembering the new root is the whole
    # mechanism, and a signer that never signs leaves nothing to revert from.
    assert second_term.handle({"op": "sign-registry-entry", "root_id": second_term.root_id, "entry": _entry()})["ok"]

    # Now the revert: back to the old root, with no flag.
    with pytest.raises(signer_module.SignerError, match="already signed under root"):
        signer_module.Signer(MASTER, key_path, old_root, authz, consensus, ledger, clock=lambda: CLOCK)


def test_requalification_is_possible_but_must_be_asked_for(signer_module, operational_key, authz, consensus, tmp_path):
    key_path, _ = operational_key
    old_root = _valid_root(consensus, nonce="root-old")
    ledger = tmp_path / "ledger.json"
    first = signer_module.Signer(MASTER, key_path, old_root, authz, consensus, ledger, clock=lambda: CLOCK)
    first.handle({"op": "sign-registry-entry", "root_id": first.root_id, "entry": _entry()})

    new_root = _valid_root(consensus, nonce="root-new")
    requalified = signer_module.Signer(
        MASTER,
        key_path,
        new_root,
        authz,
        consensus,
        ledger,
        clock=lambda: CLOCK,
        allow_requalification=True,
    )
    assert requalified.root_id != first.root_id
    assert requalified.handle({"op": "sign-registry-entry", "root_id": requalified.root_id, "entry": _entry()})["ok"]
    # Both terms stay in the ledger, each tagged with the root it was issued under.
    # Re-qualification must not rewrite history: the record of what was signed under
    # the old root is the thing that makes the next revert detectable.
    roots_in_ledger = {block["data"]["root_id"] for block in json.loads(ledger.read_text())["blocks"]}
    assert roots_in_ledger == {first.root_id, requalified.root_id}


def test_a_chained_descendant_root_is_adopted_without_the_flag(
    signer_module, operational_key, authz, consensus, tmp_path
):
    """Re-formation forward (policy B) needs no flag: the chain proves direction.

    A descendant root names the ledger's root in force as its `previous_root_id`.
    That parentage is a signed ordering inside the root itself, so the signer can
    adopt it knowing it is provably newer — the `--accept-requalification` word is
    no longer needed for the case the protocol can prove.
    """
    key_path, _ = operational_key
    genesis_root = _valid_root(consensus, nonce="root-genesis")
    ledger = tmp_path / "ledger.json"

    first = signer_module.Signer(MASTER, key_path, genesis_root, authz, consensus, ledger, clock=lambda: CLOCK)
    first.handle({"op": "sign-registry-entry", "root_id": first.root_id, "entry": _entry()})

    descendant = _valid_root(consensus, nonce="root-reformed", previous_root_id=consensus.root_id(genesis_root))
    adopted = signer_module.Signer(MASTER, key_path, descendant, authz, consensus, ledger, clock=lambda: CLOCK)
    assert adopted.root_id != first.root_id, "the descendant is a new root, not the held one"
    assert consensus.canonical_root(descendant)["previous_root_id"] == first.root_id
    assert adopted.handle({"op": "sign-registry-entry", "root_id": adopted.root_id, "entry": _entry()})["ok"]


def test_starting_records_the_root_binding_once_per_root(signer_module, operational_key, authz, consensus, tmp_path):
    """The agreement events a peer cannot observe are recorded at the moment this
    node becomes able to observe them: at signer start.

    A genesis formation appends `trust_root_formed`; a chained re-formation
    appends `trust_root_reformed`; and a restart under a root already recorded
    appends nothing, so a routine service restart does not grow the chain. The
    ledger remembering which roots this node has served is the whole mechanism
    `check_not_reverted` reads, so a term that never signed would leave nothing to
    detect a later rollback from.
    """
    key_path, _ = operational_key
    genesis = _valid_root(consensus, nonce="root-genesis")
    ledger = tmp_path / "ledger.json"

    first = signer_module.Signer(MASTER, key_path, genesis, authz, consensus, ledger, clock=lambda: CLOCK)
    after_first = json.loads(ledger.read_text())["blocks"]
    assert [block["data"]["event"] for block in after_first] == ["trust_root_formed"]
    assert after_first[0]["data"]["root_id"] == first.root_id

    # A restart under the same root records nothing further.
    signer_module.Signer(MASTER, key_path, genesis, authz, consensus, ledger, clock=lambda: CLOCK)
    assert json.loads(ledger.read_text())["blocks"] == after_first

    # A chained descendant is a re-formation, recorded as such.
    descendant = _valid_root(consensus, nonce="root-reformed", previous_root_id=first.root_id)
    adopted = signer_module.Signer(MASTER, key_path, descendant, authz, consensus, ledger, clock=lambda: CLOCK)
    events = [block["data"]["event"] for block in json.loads(ledger.read_text())["blocks"]]
    assert events == ["trust_root_formed", "trust_root_reformed"]
    assert adopted.root_id != first.root_id


def test_a_descent_forward_then_a_revert_back_is_still_refused(
    signer_module, operational_key, authz, consensus, tmp_path
):
    """The chain protects the ledger's forward edge; the ledger protects the past.

    After adopting the descendant, pointing the signer back at the genesis root is
    the same old revert — the descendant is what the ledger last saw, and the
    genesis root does not descend from it. The chain and the ledger have to agree
    for adoption; refusing a step backward is the joint consequence of both.
    """
    key_path, _ = operational_key
    genesis_root = _valid_root(consensus, nonce="root-genesis")
    descendant = _valid_root(consensus, nonce="root-reformed", previous_root_id=consensus.root_id(genesis_root))
    ledger = tmp_path / "ledger.json"

    first = signer_module.Signer(MASTER, key_path, genesis_root, authz, consensus, ledger, clock=lambda: CLOCK)
    first.handle({"op": "sign-registry-entry", "root_id": first.root_id, "entry": _entry()})
    adopted = signer_module.Signer(MASTER, key_path, descendant, authz, consensus, ledger, clock=lambda: CLOCK)
    assert adopted.handle({"op": "sign-registry-entry", "root_id": adopted.root_id, "entry": _entry()})["ok"]

    with pytest.raises(signer_module.SignerError, match="already signed under root"):
        signer_module.Signer(MASTER, key_path, genesis_root, authz, consensus, ledger, clock=lambda: CLOCK)
    with pytest.raises(signer_module.SignerError, match="accept-requalification"):
        signer_module.Signer(
            MASTER,
            key_path,
            _valid_root(consensus, nonce="root-stranger"),
            authz,
            consensus,
            ledger,
            clock=lambda: CLOCK,
        )


def test_a_corrupt_ledger_stops_the_signer_starting(signer_module, operational_key, authz, consensus, root, tmp_path):
    """Better to refuse than to run without knowing which root is in force."""
    key_path, _ = operational_key
    ledger = tmp_path / "ledger.json"
    ledger.write_text("{not json")
    with pytest.raises(signer_module.SignerError, match="corrupt"):
        signer_module.Signer(MASTER, key_path, root, authz, consensus, ledger, clock=lambda: CLOCK)


def test_it_refuses_a_valid_root_that_elected_someone_else(signer_module, operational_key, authz, consensus, tmp_path):
    """A replacement Master running on the node that lost. Unambiguously refused."""
    key_path, _ = operational_key
    other = _valid_root(consensus, master="beta")
    with pytest.raises(signer_module.SignerError, match="names 'beta' as Master"):
        signer_module.Signer(MASTER, key_path, other, authz, consensus, tmp_path / "l.json")


def test_it_refuses_a_key_the_root_does_not_authorise(signer_module, root, authz, consensus, tmp_path):
    """The check that stops any node from starting a signer and being believed."""
    private, _ = _keypair("someone-elses-operational-key")
    key_path = tmp_path / "operational.ed25519"
    key_path.write_text(private + "\n")
    key_path.chmod(0o600)

    with pytest.raises(signer_module.SignerError, match="not the key this root authorises"):
        signer_module.Signer(MASTER, key_path, root, authz, consensus, tmp_path / "l.json")


def test_a_request_may_not_substitute_its_own_root(signer, root, consensus):
    other = consensus.root_id(_valid_root(consensus, nonce="root-9"))
    response = signer.handle({"op": "sign-registry-entry", "root_id": other, "entry": _entry()})
    assert not response["ok"] and "pinned" in response["error"]


# --- 2. refusals -------------------------------------------------------------


def test_the_signer_holds_exactly_one_capability(signer):
    response = signer.handle({"op": "capabilities"})
    assert response["capabilities"] == ["sign"], (
        "the signer's capability set must contain nothing else; a second entry "
        "would be a second thing this process could be talked into"
    )


def test_it_refuses_to_sign_caller_supplied_bytes(signer):
    for op in ("sign-bytes", "sign", "sign-raw", "raw-sign"):
        response = signer.handle({"op": op, "bytes_b64": base64.b64encode(b"x").decode()})
        assert not response["ok"], f"{op} must not be answerable"


def test_it_refuses_unknown_operations(signer):
    response = signer.handle({"op": "read-file", "path": "/etc/shadow"})
    assert not response["ok"] and "unknown operation" in response["error"]


def test_it_refuses_an_entry_filed_under_the_wrong_fingerprint(signer, authz):
    """The signer must not mint an authorization no peer will ever honour.

    `authz.evaluate` refuses an entry whose identity does not hash to the
    fingerprint it is filed under, reporting `unknown_fingerprint`. A signer that
    did not check this would happily produce a perfectly valid signature over a
    useless entry: the operator sees `ok`, and the grant silently does nothing.
    """
    entry = _entry()
    entry["fingerprint"] = "b" * 64
    response = signer.handle({"op": "sign-registry-entry", "root_id": signer.root_id, "entry": entry})
    assert not response["ok"]
    assert "unknown_fingerprint" in response["error"]
    assert "hashes to" in response["error"]

    # And confirm the claim: the same entry, filed correctly, is accepted.
    good = _entry()
    assert good["fingerprint"] == authz.fingerprint(good["identity"])


def test_it_refuses_unknown_capabilities_in_a_registry_entry(signer):
    response = signer.handle(
        {
            "op": "sign-registry-entry",
            "root_id": signer.root_id,
            "entry": _entry(capabilities=("telemetry", "become-master")),
        }
    )
    assert not response["ok"] and "become-master" in response["error"]


def test_it_refuses_a_registry_entry_missing_signed_fields(signer):
    entry = _entry()
    del entry["expires_at"]
    response = signer.handle({"op": "sign-registry-entry", "root_id": signer.root_id, "entry": entry})
    assert not response["ok"] and "expires_at" in response["error"]


def test_it_refuses_a_signature_the_caller_supplied(signer):
    """A caller must not be able to smuggle a signature in and have it recorded."""
    entry = _entry(revoked=True)
    entry["signature_b64"] = base64.b64encode(b"forged").decode()
    response = signer.handle({"op": "sign-registry-entry", "root_id": signer.root_id, "entry": entry})
    assert response["ok"]
    assert response["entry"]["signature_b64"] != entry["signature_b64"], (
        "the signer returned the caller's signature instead of its own"
    )


def test_it_refuses_a_blank_guard_approval(signer):
    response = signer.handle(
        {
            "op": "sign-guard-approval",
            "root_id": signer.root_id,
            "approval": {"peer_fingerprint": "f" * 64},
        }
    )
    assert not response["ok"] and "blank approval" in response["error"]


def test_it_refuses_an_already_expired_approval(signer):
    response = signer.handle(
        {
            "op": "sign-guard-approval",
            "root_id": signer.root_id,
            "approval": {
                "peer_fingerprint": "f" * 64,
                "guard_protocol_version": "1.0",
                "target_path": "/srv/sparknet/ledger.json",
                "action": "replace",
                "expires_at": (CLOCK - timedelta(hours=1)).isoformat(),
            },
        }
    )
    assert not response["ok"] and "expired" in response["error"]


def test_a_valid_guard_approval_is_signed(signer):
    response = signer.handle(
        {
            "op": "sign-guard-approval",
            "root_id": signer.root_id,
            "approval": {
                "peer_fingerprint": "f" * 64,
                "guard_protocol_version": "1.0",
                "target_path": "/srv/sparknet/ledger.json",
                "action": "replace",
                "expires_at": (CLOCK + timedelta(minutes=10)).isoformat(),
            },
        }
    )
    assert response["ok"], response.get("error")
    assert response["approval"]["signature_b64"]


def test_a_valid_cluster_job_is_signed_over_its_canonical_bytes(signer, authz, operational_key):
    response = signer.handle({"op": "sign-cluster-job", "root_id": signer.root_id, "job": _job()})
    assert response["ok"], response.get("error")
    signed = response["job"]
    assert signed["signature_b64"]

    _, public_b64 = operational_key
    public = authz.public_key_from_b64(public_b64)
    message = authz.cluster_job_message(signed)
    assert authz.verify_signature(public, signed["signature_b64"], message), (
        "the signature must verify against the canonical projection the signer built"
    )


def test_the_cluster_job_signature_covers_the_partition(signer, authz, operational_key):
    """A signature over a job id alone would replay against any partition.

    This is the reason `subtasks` is inside the signed projection rather than a
    convenience field: changing who does what must invalidate the signature.
    """
    response = signer.handle({"op": "sign-cluster-job", "root_id": signer.root_id, "job": _job()})
    assert response["ok"], response.get("error")
    signed = response["job"]

    _, public_b64 = operational_key
    public = authz.public_key_from_b64(public_b64)
    original = authz.cluster_job_message(signed)

    tampered = json.loads(json.dumps(signed))
    tampered["subtasks"][0]["node_id"] = "delta"
    assert authz.cluster_job_message(tampered) != original
    assert not authz.verify_signature(public, signed["signature_b64"], authz.cluster_job_message(tampered))


def test_it_refuses_a_cluster_job_without_a_job_object(signer):
    response = signer.handle({"op": "sign-cluster-job", "root_id": signer.root_id})
    assert not response["ok"] and "requires a 'job' object" in response["error"]


def test_it_refuses_a_cluster_job_missing_required_fields(signer):
    job = _job()
    del job["job_id"]
    response = signer.handle({"op": "sign-cluster-job", "root_id": signer.root_id, "job": job})
    assert not response["ok"] and "job_id" in response["error"]


def test_it_refuses_a_cluster_job_with_an_empty_partition(signer):
    job = _job()
    job["subtasks"] = []
    response = signer.handle({"op": "sign-cluster-job", "root_id": signer.root_id, "job": job})
    assert not response["ok"] and "non-empty list" in response["error"]


def test_it_refuses_a_cluster_job_with_an_unknown_mode(signer):
    response = signer.handle({"op": "sign-cluster-job", "root_id": signer.root_id, "job": _job(mode="freestyle")})
    assert not response["ok"] and "freestyle" in response["error"]


def test_it_refuses_an_already_expired_cluster_job(signer):
    response = signer.handle(
        {
            "op": "sign-cluster-job",
            "root_id": signer.root_id,
            "job": _job(expires_in_minutes=-5),
        }
    )
    assert not response["ok"] and "expired" in response["error"]


def test_it_refuses_a_cluster_job_with_an_unparseable_expiry(signer):
    job = _job()
    job["expires_at"] = "not a timestamp"
    response = signer.handle({"op": "sign-cluster-job", "root_id": signer.root_id, "job": job})
    assert not response["ok"] and "expired" in response["error"]


def test_it_refuses_a_signature_the_caller_supplied_on_a_cluster_job(signer):
    job = _job()
    job["signature_b64"] = base64.b64encode(b"forged").decode()
    response = signer.handle({"op": "sign-cluster-job", "root_id": signer.root_id, "job": job})
    assert response["ok"], response.get("error")
    assert response["job"]["signature_b64"] != job["signature_b64"], (
        "the signer returned the caller's signature instead of its own"
    )


# --- admin requests (admin-supervise, fabric Step 29 phase 2) -----------------


def _admin_request(expires_in_minutes: int = 10, action: str = "set_user_role") -> dict:
    """An admin request the way `authz.admin_request_message` requires one.

    The target is a peer (this fabric's peer-1), so the role and the fields
    match what a Master actually signs for a peer's Open WebUI.
    """
    return {
        "request_id": "admin-req-0001",
        "conversation_id": None,
        "master_node_id": MASTER,
        "target_node_id": "peer-1",
        "target_fingerprint": hashlib.sha256(b"fp-peer-1").hexdigest(),
        "issued_at": CLOCK.isoformat(),
        "expires_at": (CLOCK + timedelta(minutes=expires_in_minutes)).isoformat(),
        "nonce": "nonce-0001",
        "action": action,
        "user_id": "user-07",
        "user_email": "ana@example.test",
        "role": "user",
        "kb_id": None,
        "chat_id": None,
    }


def test_a_valid_admin_request_is_signed_over_its_canonical_bytes(signer, authz, operational_key):
    response = signer.handle({"op": "sign-admin-request", "root_id": signer.root_id, "request": _admin_request()})
    assert response["ok"], response.get("error")
    signed = response["admin_request"]
    assert signed["signature_b64"]

    _, public_b64 = operational_key
    public = authz.public_key_from_b64(public_b64)
    assert authz.verify_signature(public, signed["signature_b64"], authz.admin_request_message(signed)), (
        "the signature must verify against the canonical projection the signer built"
    )


def test_the_admin_request_signature_covers_the_action(signer, authz, operational_key):
    """Changing the action must invalidate the signature — it is the scope."""
    response = signer.handle({"op": "sign-admin-request", "root_id": signer.root_id, "request": _admin_request()})
    assert response["ok"], response.get("error")
    signed = response["admin_request"]

    _, public_b64 = operational_key
    public = authz.public_key_from_b64(public_b64)

    tampered = json.loads(json.dumps(signed))
    tampered["action"] = "approve_user"
    assert authz.admin_request_message(tampered) != authz.admin_request_message(signed)
    assert not authz.verify_signature(public, signed["signature_b64"], authz.admin_request_message(tampered))


def test_it_refuses_an_admin_request_without_a_request_object(signer):
    response = signer.handle({"op": "sign-admin-request", "root_id": signer.root_id})
    assert not response["ok"] and "requires an 'admin-request' object" in response["error"]


def test_it_refuses_an_admin_request_missing_required_fields(signer):
    request = _admin_request()
    del request["target_fingerprint"]
    response = signer.handle({"op": "sign-admin-request", "root_id": signer.root_id, "request": request})
    assert not response["ok"] and "target_fingerprint" in response["error"]


def test_it_refuses_an_admin_request_with_an_unknown_action(signer):
    response = signer.handle(
        {
            "op": "sign-admin-request",
            "root_id": signer.root_id,
            "request": _admin_request(action="root-everything"),
        }
    )
    assert not response["ok"] and "unknown admin action" in response["error"]


def test_it_refuses_an_already_expired_admin_request(signer):
    response = signer.handle(
        {
            "op": "sign-admin-request",
            "root_id": signer.root_id,
            "request": _admin_request(expires_in_minutes=-5),
        }
    )
    assert not response["ok"] and "expired" in response["error"]


def test_it_refuses_a_signature_the_caller_supplied_on_an_admin_request(signer):
    request = _admin_request()
    request["signature_b64"] = base64.b64encode(b"forged").decode()
    response = signer.handle({"op": "sign-admin-request", "root_id": signer.root_id, "request": request})
    assert response["ok"], response.get("error")
    assert response["admin_request"]["signature_b64"] != request["signature_b64"], (
        "the signer returned the caller's signature instead of its own"
    )


def test_it_refuses_a_group_readable_key(signer_module, root, authz, consensus, tmp_path):
    private, _ = _keypair(f"operational-{MASTER}")
    key_path = tmp_path / "loose.ed25519"
    key_path.write_text(private + "\n")
    key_path.chmod(0o644)
    with pytest.raises(signer_module.SignerError, match="must not be readable by group or other"):
        signer_module.check_key_permissions(key_path)


def test_it_refuses_a_tcp_socket_path(signer_module, tmp_path):
    with pytest.raises(signer_module.SignerError, match="unix socket only"):
        signer_module.check_socket_path(Path("tcp://0.0.0.0:9090"))


def test_it_refuses_a_socket_outside_the_state_dir(signer_module, tmp_path, monkeypatch):
    monkeypatch.setattr(signer_module, "DEFAULT_STATE_DIR", tmp_path / "state")
    with pytest.raises(signer_module.SignerError, match="must live under"):
        signer_module.check_socket_path(Path("/tmp/somewhere-else.sock"))


def test_it_accepts_a_socket_inside_the_state_dir(signer_module, tmp_path, monkeypatch):
    monkeypatch.setattr(signer_module, "DEFAULT_STATE_DIR", tmp_path / "state")
    signer_module.check_socket_path(tmp_path / "state" / "signer.sock")


def test_it_accepts_a_socket_path_coming_straight_from_argparse(signer_module, tmp_path, monkeypatch):
    """argparse hands check_socket_path an unconverted *string* — that is the
    documented contract, and a str carries no .resolve(). Regression: the
    scheme check ran fine and then the Path methods crashed on the str, so the
    signer could not be started by the CLI at all.
    """
    monkeypatch.setattr(signer_module, "DEFAULT_STATE_DIR", tmp_path / "state")
    signer_module.check_socket_path(str(tmp_path / "state" / "signer.sock"))


# --- 3. topology -------------------------------------------------------------


def test_no_peer_service_imports_the_signer():
    """The parity allowlist already excludes it; this asserts the file itself.

    A peer service that could import the signer would make the isolation a naming
    convention, so this is a statement about the whole peer surface at once.
    """
    for path in sorted((FABRIC_ROOT / "peer-node" / "services").glob("*.py")):
        text = path.read_text()
        assert "sparknet-signer" not in text, f"{path.name} references the signer"
        assert "sparknet_signer" not in text


def test_the_parity_loader_cannot_load_the_signer(signer_module):
    parity = _load("parity_for_isolation", ROLE_ROOT / "services" / "sparknet-parity.py")
    with pytest.raises(parity.ParityError):
        parity.load_peer_service("sparknet-signer.py")


def test_no_vendor_manifest_points_at_the_signer_port():
    """The signer is not on the declared port list, so no deployment will expose it.

    Scans the port *declarations*, not the prose. An earlier version scanned the
    whole serialised document and started failing when port 8088's note explained
    that authority messages are signed elsewhere and never on the admin page — the
    note reassuring a reader that the signer is unreachable tripped a test whose
    job is to keep the signer unreachable. The distinction that matters is whether
    a port is *declared for* the signer, not whether the word appears nearby.
    """
    ports = json.loads((FABRIC_ROOT / "contracts" / "ports.json").read_text())["ports"]
    for number, spec in ports.items():
        # A declared port is an invitation to expose it, so check the fields that
        # actually name a service.
        declared = json.dumps(
            {
                "service": spec.get("service"),
                "binds_to": spec.get("binds_to"),
            },
            sort_keys=True,
        ).lower()
        for needle in ("signer", "signing"):
            assert needle not in declared, (
                f"port {number} is declared as {spec.get('service')!r}; the signer "
                f"must have no declared port, because a declared port is an "
                f"invitation to expose it"
            )


def test_the_signer_source_opens_no_tcp_listener(signer_module):
    """No AF_INET, no bind-to-port, no http. Stated as a source property because a
    test cannot prove a negative about all future edits."""
    source = SIGNER_PATH.read_text()
    for forbidden in ("AF_INET", "SOCK_DGRAM", "http.server", "socketserver", "urlopen"):
        assert forbidden not in source, (
            f"the signer references {forbidden!r}; it must not be able to open a network listener of any kind"
        )
    assert "AF_UNIX" in source, "it must actually use the unix socket it documents"


def test_describe_states_the_posture_rather_than_implying_it(signer_module):
    posture = signer_module.describe()
    assert posture["capabilities"] == ["sign"]
    assert "unix socket" in posture["transport"]
    assert any("caller-supplied bytes" in r for r in posture["refuses"])
    assert any("Open WebUI" in entry for entry in posture["not_reachable_from"])


def test_deployed_containment_is_not_verified_here():
    """The DoD's `confirm: user` item, recorded rather than quietly dropped.

    Every topology test in this file proves the *wiring* — imports, allowlists,
    declared ports, source shape. None of them proves that a real deployment held:
    that needs a machine with the signer and Open WebUI on it, someone attempting a
    crossing from the web surface, and an observation that it failed. This test
    exists so a reader of a green suite does not mistake wiring for containment.
    """
    assert True, (
        "wiring is asserted above; deployed containment is NOT verified on the "
        "development host and requires Step 17 DoD item 3 to be confirmed by the user"
    )


# --- 4. over a real socket ---------------------------------------------------


def test_it_answers_over_a_unix_socket_and_records_to_the_ledger(signer, authz, tmp_path, consensus):
    """End to end over the real transport, in a thread so the test can talk to it.

    Threaded rather than forked because the point is that the socket path, the
    0600 mode and the line protocol work, not that the process survives a fork.
    """
    socket_dir = tmp_path / "state" / "signer"
    socket_dir.mkdir(parents=True)
    socket_path = socket_dir / "signer.sock"
    mode_before = stat_mode_of_dir(tmp_path)

    thread = threading.Thread(target=_serve_forever, args=(signer, socket_path), daemon=True)
    thread.start()
    _wait_for_socket(socket_path)

    try:
        assert stat_mode_of_path(socket_path) == 0o600, "the socket must not be group-accessible"
        assert mode_before is not None

        response = _request(socket_path, {"op": "capabilities"})
        assert response["capabilities"] == ["sign"]

        response = _request(
            socket_path,
            {"op": "sign-registry-entry", "root_id": signer.root_id, "entry": _entry()},
        )
        assert response["ok"], response.get("error")

        # Starting the signer records the root it runs under, so the ledger opens
        # with trust_root_formed; the registry signature lands on top of it.
        ledger = json.loads((tmp_path / "ledger.json").read_text())
        assert [block["data"]["event"] for block in ledger["blocks"]] == [
            "trust_root_formed",
            "signature_issued",
        ]
        data = ledger["blocks"][-1]["data"]
        assert data["event"] == "signature_issued"
        assert data["operation"] == "sign-registry-entry"
        assert data["root_id"] == signer.root_id
        assert response["entry"]["signature_b64"] == data["signature_b64"]

        # And the chain must be intact, checked by the module that owns verification.
        import importlib.util as _u

        spec = _u.spec_from_file_location("ledger_for_isolation", ROLE_ROOT / "services" / "sparknet-ledger.py")
        ledger_module = _u.module_from_spec(spec)
        spec.loader.exec_module(ledger_module)
        ok, detail = ledger_module.verify_chain(ledger)
        assert ok, detail
    finally:
        thread.join(timeout=1)


def test_the_serve_transport_accepts_a_socket_path_string_as_the_cli_hands_it(
    signer,
    tmp_path,
):
    """The CLI passes --socket as an unconverted *string*; serve must bind and
    answer on that shape too. Regression: check_socket_path accepted the string,
    then serve crashed on str.exists()/os.chmod(str), so the signer could not be
    started by its own command line at all.
    """
    socket_dir = tmp_path / "state" / "signer"
    socket_dir.mkdir(parents=True)
    socket_path = str(socket_dir / "signer.sock")

    thread = threading.Thread(target=_serve_forever, args=(signer, socket_path), daemon=True)
    thread.start()
    _wait_for_socket(Path(socket_path))

    try:
        response = _request(Path(socket_path), {"op": "capabilities"})
        assert response["capabilities"] == ["sign"]
    finally:
        thread.join(timeout=1)


def test_a_second_connection_is_served_while_the_first_is_silent(signer, tmp_path):
    """DoD (2): a connected-but-silent client must not queue later clients.

    The serve loop reads every connection on its own thread, so the second
    connection's request completes without waiting for the first connection's
    read deadline. The silent client is given a generous 3 s bound: if the
    transport were still serial, the second request would sit behind the sleeping
    connection for all 3 s before being answered.
    """
    socket_dir = tmp_path / "state" / "signer"
    socket_dir.mkdir(parents=True)
    socket_path = socket_dir / "signer.sock"
    thread = threading.Thread(
        target=_serve_forever,
        args=(signer, socket_path),
        kwargs={"read_timeout": 3.0},
        daemon=True,
    )
    thread.start()
    _wait_for_socket(socket_path)
    try:
        silent = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        silent.connect(str(socket_path))
        try:
            started = time.monotonic()
            response = _request(
                socket_path,
                {"op": "sign-registry-entry", "root_id": signer.root_id, "entry": _entry()},
            )
            elapsed = time.monotonic() - started
        finally:
            silent.close()
        assert response["ok"], response
        assert response["entry"]["signature_b64"]
        assert elapsed < 0.75, f"second client waited {elapsed:.2f}s behind a silent one"
    finally:
        thread.join(timeout=0.3)


def test_a_silent_client_is_answered_timeout_and_closed(signer, tmp_path):
    """DoD (1): a client that connects and never sends a line is answered
    `{"ok": false, "error": "timeout"}` and closed within the read bound instead
    of holding a connection (and, under serialisation, the whole signer) forever.
    """
    socket_dir = tmp_path / "state" / "signer"
    socket_dir.mkdir(parents=True)
    socket_path = socket_dir / "signer.sock"
    thread = threading.Thread(
        target=_serve_forever,
        args=(signer, socket_path),
        kwargs={"read_timeout": 0.3},
        daemon=True,
    )
    thread.start()
    _wait_for_socket(socket_path)
    try:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.connect(str(socket_path))
        started = time.monotonic()
        client.settimeout(5.0)
        buffered = b""
        while b"\n" not in buffered:
            chunk = client.recv(4096)
            if not chunk:
                break
            buffered += chunk
        elapsed = time.monotonic() - started
        client.close()
        assert json.loads(buffered) == {"ok": False, "error": "timeout"}
        assert 0.05 <= elapsed < 3.0, f"timeout was not bounded, took {elapsed:.2f}s"
    finally:
        thread.join(timeout=0.3)


def test_read_line_treats_socket_timeout_as_the_read_deadline(signer_module):
    """The 3.9/3.10 timeout-class split must not turn a silent client into a bare EOF.

    On Python 3.9 `socket.timeout` and `TimeoutError` are distinct classes, so a
    transport that catches only `TimeoutError` lets the socket timeout escape:
    the serving thread dies and the client sees an empty close instead of
    `{"ok": false, "error": "timeout"}`. `_read_line` must translate *both* into
    its own `_ReadTimeout`. The fake raises the class the stdlib actually raises,
    so on a 3.9 interpreter this fails unless `socket.timeout` is named too.
    """

    class _SilentSocket:
        def settimeout(self, _value):  # the deadline logic sets this before recv
            pass

        def recv(self, _size):
            raise socket.timeout("timed out")  # noqa: UP041 - the class 3.9 raises

    with pytest.raises(signer_module._ReadTimeout):
        signer_module._read_line(_SilentSocket(), 1 << 20, 0.5)


def test_two_concurrent_requests_serialise_into_one_intact_chain(signer, tmp_path):
    """DoD (3): the single-key invariant survives concurrency.

    The ledger opens with the signer's own trust_root_formed block; two requests
    signed back-to-back over the socket then land as two signature_issued blocks —
    the signer lock serialises the handle, so no block is lost to a
    read-modify-write race and order is a strict total order — each chaining to
    the previous, and the production ledger verifier accepts the result.
    """
    socket_dir = tmp_path / "state" / "signer"
    socket_dir.mkdir(parents=True)
    socket_path = socket_dir / "signer.sock"
    thread = threading.Thread(
        target=_serve_forever,
        args=(signer, socket_path),
        kwargs={"read_timeout": 3.0},
        daemon=True,
    )
    thread.start()
    _wait_for_socket(socket_path)
    try:
        responses: list = []
        responses_lock = threading.Lock()

        def _sign() -> None:
            response = _request(
                socket_path,
                {"op": "sign-registry-entry", "root_id": signer.root_id, "entry": _entry()},
            )
            with responses_lock:
                responses.append(response)

        requesters = [threading.Thread(target=_sign) for _ in range(2)]
        for requester in requesters:
            requester.start()
        for requester in requesters:
            requester.join(timeout=5.0)
        assert all(response["ok"] for response in responses), responses

        ledger = json.loads((tmp_path / "ledger.json").read_text())
        blocks = ledger["blocks"]
        assert [block["data"]["event"] for block in blocks] == [
            "trust_root_formed",
            "signature_issued",
            "signature_issued",
        ]
        assert blocks[0]["prev_hash"] == ""
        assert blocks[1]["prev_hash"] == blocks[0]["hash"]
        assert blocks[2]["prev_hash"] == blocks[1]["hash"]

        spec = importlib.util.spec_from_file_location(
            "ledger_for_concurrency", ROLE_ROOT / "services" / "sparknet-ledger.py"
        )
        ledger_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ledger_module)
        ok, detail = ledger_module.verify_chain(ledger)
        assert ok, detail
    finally:
        thread.join(timeout=0.3)


def test_concurrent_requests_never_run_handle_twice_at_once(signer, tmp_path):
    """DoD (3), made deterministic: the transport serialises Handle calls.

    The real-signer chain test above proves the ledger survives real races, but
    that race only *sometimes* loses a block under the GIL. This test makes the
    corruption impossible to miss: a fake signer whose `handle` sleeps while
    counting how many callers are inside it. If the transport really serialises,
    the events alternate enter/exit and `max_inside` stays 1; if the lock is
    removed the sleep forces both calls inside at once and the assertion fails
    every run, not occasionally.
    """
    socket_dir = tmp_path / "state" / "signer"
    socket_dir.mkdir(parents=True)
    socket_path = socket_dir / "signer.sock"
    thread = threading.Thread(
        target=_serve_forever,
        args=(_serialisable_signer := _SerialisingSigner(), socket_path),
        kwargs={"read_timeout": 3.0},
        daemon=True,
    )
    thread.start()
    _wait_for_socket(socket_path)
    try:
        requesters = [threading.Thread(target=_request, args=(socket_path, {"op": "anything"})) for _ in range(2)]
        for requester in requesters:
            requester.start()
        for requester in requesters:
            requester.join(timeout=5.0)
        with _serialisable_signer.monitor:
            assert _serialisable_signer.events == [
                ("enter", 1),
                ("exit", 0),
                ("enter", 1),
                ("exit", 0),
            ], _serialisable_signer.events
            assert _serialisable_signer.max_inside == 1
            assert _serialisable_signer.answers == 2
    finally:
        thread.join(timeout=0.3)


def test_two_signatures_chain_on_top_of_each_other(signer, tmp_path, authz, consensus):
    """Ledger order is part of what the chain attests, so prev_hash must advance."""
    first = signer.handle({"op": "sign-registry-entry", "root_id": signer.root_id, "entry": _entry()})
    second = signer.handle({"op": "sign-registry-entry", "root_id": signer.root_id, "entry": _entry()})
    assert first["ok"] and second["ok"]
    assert first["ledger_block"] != second["ledger_block"]

    ledger = json.loads((tmp_path / "ledger.json").read_text())
    blocks = ledger["blocks"]
    # The signer's own root binding opens the chain; every later block links to
    # the one before it, so order — not just content — is what the chain attests.
    assert [block["data"]["event"] for block in blocks] == [
        "trust_root_formed",
        "signature_issued",
        "signature_issued",
    ]
    for previous, block in itertools.pairwise(blocks):
        assert block["prev_hash"] == previous["hash"]
    assert blocks[0]["prev_hash"] == ""


def test_a_refused_request_appends_nothing_to_the_ledger(signer, tmp_path):
    # Starting the signer records its root binding, so the ledger already exists;
    # what a refusal must not do is *append* a block to it. A run of failed
    # requests would otherwise leave a record of nothing having happened.
    before = json.loads((tmp_path / "ledger.json").read_text())
    signer.handle({"op": "sign-registry-entry", "root_id": "wrong", "entry": _entry()})
    after = json.loads((tmp_path / "ledger.json").read_text())
    assert after["blocks"] == before["blocks"]


# --- helpers -----------------------------------------------------------------


class _SerialisingSigner:
    """A `handle` that sleeps, so two concurrent calls must overlap unless the
    transport serialises them. Only `.handle` is used, so this stands in for the
    real signer at the transport level."""

    def __init__(self) -> None:
        self.monitor = threading.Lock()
        self.inside = 0
        self.max_inside = 0
        self.answers = 0
        self.events: list[tuple[str, int]] = []

    def handle(self, request: dict) -> dict:
        with self.monitor:
            self.inside += 1
            self.max_inside = max(self.max_inside, self.inside)
            self.events.append(("enter", self.inside))
        time.sleep(0.05)
        with self.monitor:
            self.inside -= 1
            self.answers += 1
            self.events.append(("exit", self.inside))
        return {"ok": True}


def _serve_forever(signer, socket_path: Path, *, read_timeout: float | None = None) -> None:
    import importlib.util as _u

    spec = _u.spec_from_file_location("signer_serve_helper", SIGNER_PATH)
    module = _u.module_from_spec(spec)
    sys.modules["signer_serve_helper"] = module
    spec.loader.exec_module(module)
    try:
        if read_timeout is None:
            module.serve(signer, socket_path)
        else:
            module.serve(signer, socket_path, read_timeout=read_timeout)
    except OSError:
        pass


def _wait_for_socket(socket_path: Path, timeout: float = 5.0) -> None:
    import time

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if socket_path.exists():
            return
        time.sleep(0.01)
    raise AssertionError(f"signer socket {socket_path} never appeared")


def _request(socket_path: Path, payload: dict) -> dict:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client.connect(str(socket_path))
        client.sendall(json.dumps(payload).encode("utf-8") + b"\n")
        buffered = b""
        while b"\n" not in buffered:
            chunk = client.recv(4096)
            if not chunk:
                break
            buffered += chunk
        return json.loads(buffered.split(b"\n", 1)[0].decode("utf-8"))
    finally:
        client.close()


def stat_mode_of_path(path: Path) -> int:
    return path.stat().st_mode & 0o777


def stat_mode_of_dir(path: Path) -> int | None:
    return path.stat().st_mode & 0o777 if path.exists() else None


def test_the_signer_is_never_started_by_anything_but_its_own_unit():
    """Step 16 shipped no signer unit. If something else started it, that would be
    a surface nobody reviewed."""
    # ExecStart lines only. Asserting over whole unit files flags a *description*
    # that merely mentions the signer, which is documentation, not a start path.
    exec_lines = [
        line.strip()
        for unit in (ROLE_ROOT / "systemd").glob("*.service")
        for line in unit.read_text().splitlines()
        if line.strip().lower().startswith("execstart")
    ]
    starting_the_signer = [line for line in exec_lines if "signer" in line]
    assert len(starting_the_signer) <= 1, (
        f"more than one unit starts the signer: {starting_the_signer}. Each start "
        f"path is a place the key becomes reachable, and only one has been reviewed"
    )


def test_the_signers_systemd_execstart_matches_the_real_cli():
    """The signer unit's ExecStart must be a command the signer CLI actually parses.

    Regression: the unit called `sparknet-signer.py serve --node-id …`. The CLI
    has no `serve` subcommand — argparse rejects the stray positional with
    "unrecognized arguments", so the unit would have failed on the Master host on
    first start after the election. No suite read this unit, which is how the
    phantom subcommand survived Step 16, the Step 11 signer work and the Step 12
    rehearsal (which starts the signer directly, never via systemd).
    """
    unit = (ROLE_ROOT / "systemd" / "sparknet-master-signer.service").read_text()
    lines = unit.splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip().lower().startswith("execstart="))
    block = [lines[start].strip()]
    while block[-1].endswith("\\"):
        start += 1
        block.append(lines[start].strip())
    joined = " ".join(piece[:-1] if piece.endswith("\\") else piece for piece in block)
    argv = shlex.split(joined[len("ExecStart=") :])
    # argv[0]=/usr/bin/env argv[1]=python3 argv[2]=the script; the flags follow.
    substituted = [re.sub(r"\$\{[^}]+\}|%h", "/tmp/opencode/signer-unit-check", arg) for arg in argv[3:]]
    # --describe parses the whole flag surface and exits before touching files,
    # so the check is "argparse accepts the unit's own command line", not a start.
    result = subprocess.run(
        [sys.executable, str(SIGNER_PATH), "--describe", *substituted],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_cli_refuses_to_start_without_a_key(tmp_path):
    """A missing or unreadable key must stop it, not degrade to unsigned mode."""
    result = subprocess.run(
        [
            sys.executable,
            str(SIGNER_PATH),
            "--node-id",
            MASTER,
            "--root",
            str(tmp_path / "absent.json"),
        ],
        capture_output=True,
        text=True,
        env={**os.environ, "SPARKNET_STATE_DIR": str(tmp_path)},
    )
    assert result.returncode == 1
    assert "not found" in result.stderr or "not valid" in result.stderr
    assert "refusing" in result.stderr or "not found" in result.stderr
