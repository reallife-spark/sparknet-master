#!/usr/bin/env python3
"""The isolated signer. It signs, and it does nothing else.

This process holds the operational key: the key that authorizes the entire
fabric. Everything else in this role — Open WebUI, the dispatch bridge, the
agent ports — is multi-user, LLM-driven, and reads configuration as input. If that
surface could reach this key, a prompt injection would grant itself the one
capability the peer roles deliberately withhold, and the fabric's central
premise would invert.

So the isolation is **structural**, not a permission rule. A `deny` in an ACL is a
policy statement that the governed surface may later ignore; a separate process
with a key that exists nowhere else on the machine is not. The reasons are
recorded in `../security/key-management.md`; the topology is asserted in
`../tests/test_signer_isolation.py`.

## What it will sign

Exactly six payload types, all built from structured input:

| Operation | Signs |
|---|---|
| `sign-registry-entry` | a registry entry, via `authz.authorization_message` |
| `sign-registry-publication` | a registry's distribution publication, via `authz.registry_publication_message` |
| `sign-guard-approval` | a `guard-apply` approval for one named peer |
| `sign-cluster-job` | a cluster job, via `authz.cluster_job_message` |
| `sign-admin-request` | an `admin-supervise` admin request, via `authz.admin_request_message` |
| `sign-rfi-answer` | an RFI answer for one named peer's inbox, via `authz.rfi_answer_message` |

There is deliberately **no "sign these bytes" operation**. The build plan's
wording for this step was "accepts only canonical bytes already co-signed by the
cluster root", and this implementation is stricter than that: it never signs
caller-supplied bytes at all, because the moment a signer will sign arbitrary
bytes, every upstream canonicalisation bug becomes a key-compromise bug. The
canonical form is derived here, from typed fields, by the one implementation in
`../../shared/`.

## What it will refuse

- A request whose `root_id` is not the root this process was started with.
- Any root that is not valid, or that does not name this node as the Master.
- A root whose `master_pubkey` does not match this process's own key. Without this
  check, any node could start a signer and every signature it produced would
  satisfy `verify_root` — the root is what authorises the key, so the key must
  prove it is the one the root names.
- A key file readable by group or other.
- A socket path outside the state directory, or any TCP address.
- A capability other than `sign`. Exposed as `{"op": "capabilities"}` so the claim
  is checkable rather than asserted.

## Transport

A unix socket at 0600, one JSON object per line. No TCP, ever: a TCP port would
put this inside the reach of the WireGuard surface this whole design exists to
keep it out of. `bind` refuses a non-local address rather than trusting the
operator's flag.

## It does not decide anything

The signer does not know who should be granted what. It signs what it is asked,
for a caller that has already been authorised elsewhere, and records that it did
so. Policy lives in the trust root and the registry; this file's only policy is
refusal.
"""

from __future__ import annotations

import argparse
import errno
import importlib.util
import json
import os
import re
import socket
import stat
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROLE_ROOT = Path(__file__).resolve().parent.parent


def _default_state_dir() -> Path:
    """Outside the vault, always. See scripts/sparknet-master-env.sh.

    The admin surface bind-mounts the vault read-only into an LLM-driven
    container, so a signing key anywhere under this tree is readable from it.
    `make keys-check` fails if SPARKNET_STATE_DIR is overridden back inwards;
    this default keeps the door shut when nobody set anything at all.
    """
    import os

    env = os.environ.get("SPARKNET_STATE_DIR")
    if env:
        return Path(env)
    xdg = os.environ.get("XDG_STATE_HOME")
    if xdg:
        return Path(xdg) / "sparknet" / "master-node"
    return Path.home() / ".local" / "state" / "sparknet" / "master-node"


DEFAULT_STATE_DIR = _default_state_dir()

#: How long one request may take to arrive before the signer answers
#: ``{"ok": false, "error": "timeout"}`` and closes that connection. The bound is
#: per-connection, not per-byte: a client that connects and never finishes a line
#: is the one failure mode the accept loop cannot absorb, so a trickle of bytes
#: must not be able to stretch the wait indefinitely. 30 s is generous for a
#: local, interactive, unix-socket peer.
REQUEST_READ_TIMEOUT_SECONDS = 30.0

#: The signer's entire capability set. One entry, and it is not negotiable at
#: runtime. If a future need appears — say, the signer also decrypting backups —
#: that is a different process with its own key, not a second entry here.
SIGNER_CAPABILITIES = frozenset({"sign"})

#: Operations this process answers. Anything else is refused, including future
#: additions someone makes in a hurry while the socket is open.
SIGN_OPERATIONS = (
    "sign-registry-entry",
    "sign-registry-publication",
    "sign-guard-approval",
    "sign-cluster-job",
    "sign-admin-request",
    "sign-rfi-answer",
    "sign-share-ratification",
    "record-share-evidence",
    "sign-trust-transition",
)
READ_OPERATIONS = ("capabilities", "public-key", "root-id", "ping")
OPERATIONS = SIGN_OPERATIONS + READ_OPERATIONS

#: The guard-approval envelope is *not* defined here. Its rule lives in
#: shared/sparknet-authz.py (GUARD_APPROVAL_FIELDS, guard_approval_message),
#: because the peer verifies approvals with that same rule. A local copy of the
#: field list is how the signer and the guard drifted apart in the first place:
#: each signed and verified a different shape, and both kept working.


class SignerError(Exception):
    """A refusal. Every refusal is a message the caller can act on."""


# --- loading the one implementations ----------------------------------------


def _load(name: str, path: Path):
    """Load a shared module by path, registering it in sys.modules first.

    The registration is not optional: `@dataclass` resolves its own module
    through `sys.modules` and raises an AttributeError about `__dict__` that
    names neither the cause nor the file.
    """
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise SignerError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _shared_dir() -> Path:
    candidates = [
        Path(os.environ["SPARKNET_SHARED_DIR"]) if os.environ.get("SPARKNET_SHARED_DIR") else None,
        ROLE_ROOT.parent / "shared",
        ROLE_ROOT / "shared",
        Path("/srv/sparknet/shared"),
    ]
    for candidate in candidates:
        if candidate and (candidate / "sparknet-authz.py").is_file():
            return candidate.resolve()
    raise SignerError("cannot find shared/; set SPARKNET_SHARED_DIR")


def load_modules(shared_dir: Path | None = None) -> tuple[Any, Any]:
    shared = shared_dir or _shared_dir()
    authz = _load("sparknet_signer_authz", shared / "sparknet-authz.py")
    consensus = _load("sparknet_signer_consensus", shared / "sparknet-consensus.py")
    return authz, consensus


# --- refusing things ---------------------------------------------------------


def check_key_permissions(key_path: Path) -> None:
    """Refuse a key anyone but the owner can read.

    Not a style check. A 0644 operational key means the Open WebUI process — which
    runs as the same user on most of these nodes — can read it, at which point the
    isolation this process exists to provide is a directory boundary nobody
    enforces.
    """
    if not key_path.is_file():
        raise SignerError(f"operational key not found: {key_path}")
    mode = stat.S_IMODE(key_path.stat().st_mode)
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise SignerError(
            f"operational key {key_path} is mode {mode:04o}; it must not be "
            f"readable by group or other. Fix with: chmod 600 {key_path}"
        )


def check_socket_path(socket_path: str | Path) -> None:
    """Refuse anything that is not a local socket path in the state directory.

    Takes `str | Path` and checks the *string* first, deliberately. `Path` collapses
    `tcp://host:port` to `tcp:/host:port`, so a scheme check run against a Path
    would miss exactly the input it exists to catch. Callers that got their argument
    from argparse must therefore pass the unconverted string.
    """
    text = str(socket_path)
    if "://" in text or text.startswith(("tcp:", "udp:", "http:")):
        raise SignerError(
            f"refusing {text}: this signer serves a unix socket only. A TCP port "
            f"would place the operational key inside the WireGuard surface this "
            f"process exists to stay out of."
        )
    try:
        state = DEFAULT_STATE_DIR.resolve()
    except OSError:
        state = DEFAULT_STATE_DIR
    path = Path(socket_path)
    try:
        resolved_parent = path.resolve().parent
    except OSError:
        resolved_parent = path.parent
    if state not in (resolved_parent, *resolved_parent.parents):
        raise SignerError(
            f"refusing socket at {socket_path}: it must live under {state}. A "
            f"socket in a shared directory is a socket another process can replace "
            f"with its own listener."
        )


def check_root(root: dict[str, Any], consensus: Any, node_id: str) -> None:
    """The root must be valid, must name this node Master, and must name this key.

    Three separate refusals because they fail for different reasons, and an
    operator seeing one of them learns something different than from the others:

    - invalid: the root is malformed, short of the members' signatures, or its
      signatures do not verify against the keys the root itself names;
    - not-this-node: a perfectly valid root that elected someone else. A
      replacement Master running on the old one hits exactly this;
    - key-mismatch: the valid root names a different operational key than the one
      loaded. This is the check that stops *any* node from starting a signer and
      having its output accepted.
    """
    ok, reason = consensus.verify_root(root)
    if not ok:
        raise SignerError(f"cluster trust root is not valid: {reason}")
    canonical = consensus.canonical_root(root)
    if canonical["master_node_id"] != node_id:
        raise SignerError(
            f"this node is {node_id!r} but the root names {canonical['master_node_id']!r} as Master; refusing to sign"
        )


def check_key_matches_root(public_key_b64: str, root: dict[str, Any], consensus: Any) -> None:
    authorised = consensus.canonical_root(root)["master_pubkey"]
    if public_key_b64 != authorised:
        raise SignerError(
            f"the loaded operational key ({public_key_b64[:12]}...) is not the key "
            f"this root authorises ({authorised[:12]}...). Any node could pass this "
            f"check otherwise, and every signature it produced would verify."
        )


def check_not_reverted(ledger_path: Path, consensus: Any, root: dict[str, Any], allow_requalification: bool) -> None:
    """Refuse to start against a root older than one this node has already served.

    A stale root is the hardest case in this file, because on its own it is
    *valid*: it names this node, it names this key, every member signed it. If
    the cluster later re-formed and this node's Master role moved, the old root
    still verifies, so "is this root well-formed" cannot detect the problem.

    The ledger is what remembers. Every signature this node ever issued records the
    `root_id` it was issued under, so a ledger containing a different `root_id`
    means this process is being pointed back at a superseded root — either an
    accidental revert, or someone rolling the Master back. Both are refused unless
    the operator passes `--accept-requalification`, which makes the reversal a
    deliberate act with a word for it, rather than a thing you can do by editing a
    file.

    Re-formation *forward* is the chain (policy B): a root whose
    `previous_root_id` names the ledger's root in force descends-monotonically
    from it, so it is provably newer than what this signer signed under, and is
    adopted without the flag. The chain is what makes forward adoption
    automatic, so the flag is left for the cases the chain cannot prove —
    a rollback, or a jump to a root with no lineage to the ledger's last one.
    """
    if not ledger_path.is_file():
        return
    try:
        ledger = json.loads(ledger_path.read_text())
    except json.JSONDecodeError as exc:
        raise SignerError(
            f"ledger at {ledger_path} is corrupt: {exc}. Refusing to sign rather "
            f"than starting a signer that cannot say which root it is under."
        ) from exc

    incoming = consensus.root_id(root)
    ledgers = [block.get("data", {}).get("root_id") for block in ledger.get("blocks", []) if isinstance(block, dict)]
    ledgers = [root_id for root_id in ledgers if root_id]
    if not ledgers:
        return
    in_force = ledgers[-1]
    if incoming == in_force:
        return
    if not allow_requalification and consensus.canonical_root(root).get("previous_root_id", "") == in_force:
        # Chained re-formation, policy B: this root names the ledger's root in
        # force as its parent, so it is provably newer than anything this signer
        # has signed under — forward adoption, not a revert. The chain is the
        # `--accept-requalification` decision now made by the protocol instead
        # of a human flag, which is the point of re-formation.
        return
    if allow_requalification:
        return
    listed = ", ".join(sorted({r[:16] + "..." for r in ledgers}))
    raise SignerError(
        f"this node has already signed under root(s) {listed}, but was started "
        f"with a root ({incoming[:16]}...) that neither matches the root in "
        f"force nor names it as previous_root_id (chained re-formation). "
        f"--accept-requalification makes this deliberate."
    )


# --- ledger ------------------------------------------------------------------


def _block_hash(block: dict[str, Any], authz: Any) -> str:
    return authz.ledger_block_hash(block)


def record_event(
    ledger_path: Path,
    node_id: str,
    event: str,
    data: dict[str, Any],
    root_id: str,
    *,
    authz: Any,
    private_key: Any,
    node_pubkey_b64: str,
    clock=None,
) -> dict[str, Any]:
    """Append one Master-side block whose *header* the node key signs.

    The block's `data` is `{"event": event, "node_id": node_id, "root_id": root_id,
    **data}`: the event, the node that recorded it and the root in force are part
    of every block, so `check_not_reverted` can read the lineage from any of them
    and the header signature binds position, timestamp and payload to the key.
    Without that header signature a block could be deleted or reordered and the
    chain would still verify.

    `signature_issued` (an operation's own signature recorded inside `data`) rides
    this same path, and so do the agreement events a peer cannot observe — a trust
    root being formed or re-formed, an election outcome. All of them are Master
    events signed by the operational key; none may be written by an unsigned
    process.

    The ledger is written atomically with a 0600 mode. Requests are serialised by
    the signer lock (one lock around `Signer.handle` in the transport), and the
    header signature covers the previous hash, so a lost block is visible as a
    broken chain rather than invisible.

    `append` lives here rather than in `sparknet-ledger.py` on purpose: that
    module can only verify, because appending requires this key. One process
    writes, and it is the one holding the key.
    """
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    if ledger_path.is_file():
        try:
            ledger = json.loads(ledger_path.read_text())
        except json.JSONDecodeError as exc:
            raise SignerError(f"ledger is corrupt, refusing to sign: {exc}") from exc
    else:
        ledger = {"version": "2.0", "genesis_hash": "", "blocks": []}

    blocks = ledger["blocks"]
    previous = blocks[-1]["hash"] if blocks else str(ledger.get("genesis_hash", ""))
    index = len(blocks)
    now = (clock or (lambda: datetime.now(timezone.utc)))()
    block: dict[str, Any] = {
        "block_id": f"{index:08d}",
        "prev_hash": previous,
        "timestamp": now.isoformat().replace("+00:00", "Z"),
        "node_pubkey_b64": node_pubkey_b64,
        "data": {
            "event": event,
            "node_id": node_id,
            "root_id": root_id,
            **data,
        },
    }
    block["signature"] = authz.sign_bytes(private_key, authz.ledger_block_signable(block))
    block["hash"] = _block_hash(block, authz)
    blocks.append(block)
    _atomic_write(ledger_path, json.dumps(ledger, indent=2) + "\n", mode=0o600)
    return block


def _atomic_write(path: Path, content: str, mode: int) -> None:
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        os.chmod(path, mode)
    except Exception:
        if tmp.exists():
            tmp.unlink()
        raise


# --- the signer --------------------------------------------------------------


class Signer:
    """State and policy. No I/O beyond the socket and the ledger."""

    def __init__(
        self,
        node_id: str,
        key_path: Path,
        root: dict[str, Any],
        authz: Any,
        consensus: Any,
        ledger_path: Path,
        clock=None,
        allow_requalification: bool = False,
    ) -> None:
        self.node_id = node_id
        self.authz = authz
        self.consensus = consensus
        self.ledger_path = ledger_path
        self.clock = clock
        self.key = authz.private_key_from_b64(key_path.read_text().strip())
        self.public_key_b64 = authz.public_key_b64(self.key.public_key())

        check_root(root, consensus, node_id)
        check_key_matches_root(self.public_key_b64, root, consensus)
        check_not_reverted(ledger_path, consensus, root, allow_requalification)

        # The root this process was started with is pinned. A request may name a
        # root, but only this one is acceptable — which is what makes a stale or
        # forged root unusable rather than merely unverified.
        self.root = consensus.canonical_root(root)
        self.root_id = consensus.root_id(root)
        self.signed_count = 0

        # Record the root this term runs under, if the ledger has not already seen
        # it. The ledger is what remembers which roots this node has served — that
        # is the whole mechanism `check_not_reverted` reads — so a term that never
        # signed anything would leave nothing to detect a later rollback from. A
        # genesis formation appends `trust_root_formed`; a re-formation (a root
        # whose `previous_root_id` names the ledger's root in force) appends
        # `trust_root_reformed`. Re-starting under a root already recorded appends
        # nothing, so a routine restart does not grow the chain.
        self._record_root_binding()

    def _record_root_binding(self) -> None:
        recorded = self._roots_in_ledger()
        if self.root_id in recorded:
            return
        previous = self.root.get("previous_root_id", "")
        reformed = bool(previous) and previous in recorded
        record_event(
            self.ledger_path,
            self.node_id,
            "trust_root_reformed" if reformed else "trust_root_formed",
            {
                "epoch": self.root.get("epoch", 0),
                "previous_root_id": previous,
                "master_pubkey": self.root.get("master_pubkey", ""),
            },
            self.root_id,
            authz=self.authz,
            private_key=self.key,
            node_pubkey_b64=self.public_key_b64,
            clock=self.clock,
        )

    def _roots_in_ledger(self) -> set[str]:
        """Every `root_id` the ledger already records, from any Master event."""
        if not self.ledger_path.is_file():
            return set()
        try:
            ledger = json.loads(self.ledger_path.read_text())
        except json.JSONDecodeError:
            return set()
        roots = {block.get("data", {}).get("root_id") for block in ledger.get("blocks", []) if isinstance(block, dict)}
        return {str(root) for root in roots if root}

    # -- operations

    def handle(self, request: Any) -> dict[str, Any]:
        if not isinstance(request, dict):
            return self._refuse("malformed request: expected a JSON object")
        op = request.get("op")
        if op not in OPERATIONS:
            return self._refuse(f"unknown operation {op!r}; this signer answers only {', '.join(OPERATIONS)}")

        if op in READ_OPERATIONS:
            return self._read(op)
        return self._sign(op, request)

    def _read(self, op: str) -> dict[str, Any]:
        if op == "capabilities":
            return {"ok": True, "capabilities": sorted(SIGNER_CAPABILITIES)}
        if op == "public-key":
            return {"ok": True, "public_key_b64": self.public_key_b64}
        if op == "root-id":
            return {"ok": True, "root_id": self.root_id, "node_id": self.node_id}
        return {"ok": True, "pong": True}

    def _refuse(self, message: str) -> dict[str, Any]:
        return {"ok": False, "error": message}

    def _require_this_root(self, request: dict[str, Any]) -> None:
        named = request.get("root_id")
        if named != self.root_id:
            raise SignerError(
                f"request names root {named!r} but this signer was started with "
                f"{self.root_id!r}. A trust root is pinned at start; a request "
                f"cannot substitute its own."
            )

    def _sign(self, op: str, request: dict[str, Any]) -> dict[str, Any]:
        try:
            self._require_this_root(request)
        except SignerError as exc:
            return self._refuse(str(exc))

        if op == "sign-registry-entry":
            return self._sign_registry_entry(op, request)
        if op == "sign-registry-publication":
            return self._sign_registry_publication(op, request)
        if op == "sign-cluster-job":
            return self._sign_cluster_job(op, request)
        if op == "sign-admin-request":
            return self._sign_admin_request(op, request)
        if op == "sign-rfi-answer":
            return self._sign_rfi_answer(op, request)
        if op == "sign-share-ratification":
            return self._sign_share_ratification(op, request)
        if op == "record-share-evidence":
            return self._record_share_evidence(op, request)
        if op == "sign-trust-transition":
            return self._sign_trust_transition(op, request)
        return self._sign_guard_approval(op, request)

    def _sign_registry_entry(self, op: str, request: dict[str, Any]) -> dict[str, Any]:
        entry = request.get("entry")
        if not isinstance(entry, dict):
            return self._refuse("sign-registry-entry requires an 'entry' object")

        unsigned = {k: v for k, v in entry.items() if k != "signature_b64"}
        required = ("fingerprint", "identity", "capabilities", "issued_at", "expires_at")
        missing = [f for f in required if f not in unsigned]
        if missing:
            return self._refuse(
                f"registry entry missing {', '.join(missing)}. The signer builds the "
                f"canonical envelope itself; it will not sign a partial entry."
            )

        try:
            message = self.authz.authorization_message(unsigned)
        except Exception as exc:
            return self._refuse(f"registry entry is not canonicalisable: {exc}")

        unknown = [c for c in unsigned["capabilities"] if c not in self.authz.KNOWN_CAPABILITIES]
        if unknown:
            return self._refuse(f"refusing to grant unknown capabilities: {unknown}")

        # The registry is filed *by* fingerprint, and `authz.evaluate` refuses an
        # entry whose identity does not hash to the fingerprint it is filed under.
        # Signing such an entry would produce a signature that no peer will ever
        # honour, and the operator would see a valid-looking authorization that
        # silently does nothing. Catch it here, where the mistake is still fixable.
        try:
            actual = self.authz.fingerprint(unsigned["identity"])
        except Exception as exc:
            return self._refuse(f"registry entry identity is malformed: {exc}")
        if actual != unsigned["fingerprint"]:
            return self._refuse(
                f"registry entry is filed under fingerprint {str(unsigned['fingerprint'])[:16]}... "
                f"but its identity hashes to {actual[:16]}... . This is the same defect "
                f"authz.evaluate calls 'unknown_fingerprint'; signing it would mint an "
                f"authorization no peer would accept."
            )

        # A revoked entry and a live entry are signed the same way — the signed
        # bytes already carry `revoked`, so revocation cannot be flipped after the
        # fact. This branch exists so the *ledger* records which it was.
        revoked = bool(unsigned.get("revoked", False))
        signature_b64 = self.authz.sign_bytes(self.key, message)
        subject = str(unsigned["fingerprint"])
        block = self._record(op, subject, signature_b64)
        return {
            "ok": True,
            "entry": {**unsigned, "signature_b64": signature_b64},
            "ledger_block": block["hash"],
            "revoked": revoked,
        }

    def _sign_registry_publication(self, op: str, request: dict[str, Any]) -> dict[str, Any]:
        publication = request.get("publication")
        if not isinstance(publication, dict):
            return self._refuse("sign-registry-publication requires a 'publication' object")

        # The digest is computed *here*, never taken from the caller. A caller
        # cannot hand the signer a digest that names one registry and a document
        # that says another, because the digest is derived from the document.
        unsigned = {k: publication.get(k) for k in ("sequence", "published_at")}
        unsigned["registry"] = publication.get("registry")
        if not isinstance(unsigned["registry"], dict):
            return self._refuse("publication requires a 'registry' object")
        try:
            unsigned["registry_sha256"] = self.authz.registry_digest(unsigned["registry"])
            message = self.authz.registry_publication_message(unsigned)
        except self.authz.AuthzError as exc:
            return self._refuse(f"refusing to sign this publication: {exc}")
        except Exception as exc:
            return self._refuse(f"publication is not canonicalisable: {exc}")

        # Re-validating the entries here would duplicate the schema checker and
        # the peer. The signer's job is the *publication*: sequence, digest and
        # time. A registry whose entries were never signed is caught by
        # registry-publish (which checks the document before calling this) and
        # again by every peer (which evaluates each entry on install).
        signature_b64 = self.authz.sign_bytes(self.key, message)
        block = self._record(op, f"sequence-{unsigned['sequence']}", signature_b64)
        return {
            "ok": True,
            "publication": unsigned,
            "signature_b64": signature_b64,
            "ledger_block": block["hash"],
        }

    def _sign_guard_approval(self, op: str, request: dict[str, Any]) -> dict[str, Any]:
        approval = request.get("approval")
        if not isinstance(approval, dict):
            return self._refuse("sign-guard-approval requires an 'approval' object")
        # The canonical bytes come from the one implementation in shared/. It
        # refuses an approval that names no peer, no path or no nonce, and it
        # refuses one that carries a field outside the envelope — an unsigned
        # field in an envelope that carries authority is how a second, unchecked
        # channel into the guard would appear.
        try:
            message = self.authz.guard_approval_message(approval)
        except self.authz.AuthzError as exc:
            return self._refuse(
                f"refusing to sign this approval: {exc}. An approval names one peer, one "
                f"protected path and one piece of content, and nothing else; a blank approval "
                f"would be a key that signs whatever it is handed."
            )
        # An approval whose expiry is already in the past would be signed into the
        # ledger as a valid record of something nobody can use. Refuse it instead.
        expires = str(approval["expires_at"])
        if expires < (self.clock or (lambda: datetime.now(timezone.utc)))().isoformat():
            return self._refuse(f"refusing to sign an approval that expired at {expires}")

        signature_b64 = self.authz.sign_bytes(self.key, message)
        block = self._record(op, str(approval["peer_fingerprint"]), signature_b64)
        # The signature travels beside the envelope, never inside it. The
        # canonical rule covers exactly the envelope's fields and refuses an
        # extra one, so an approval that carried its own signature would be an
        # approval the peer refuses — signed by the Master itself.
        return {
            "ok": True,
            "approval": dict(approval),
            "signature_b64": signature_b64,
            "ledger_block": block["hash"],
        }

    def _sign_cluster_job(self, op: str, request: dict[str, Any]) -> dict[str, Any]:
        job = request.get("job")
        if not isinstance(job, dict):
            return self._refuse("sign-cluster-job requires a 'job' object")

        # The caller may echo a signature back; the signer always rebuilds over
        # the projected fields, so a smuggled one is discarded rather than recorded.
        unsigned = {k: v for k, v in job.items() if k != "signature_b64"}
        try:
            message = self.authz.cluster_job_message(unsigned)
        except Exception as exc:
            return self._refuse(f"cluster job is not canonicalisable: {exc}")

        now = (self.clock or (lambda: datetime.now(timezone.utc)))()
        if self.authz.is_expired(unsigned["expires_at"], now):
            return self._refuse(f"refusing to sign a cluster job that expired at {unsigned['expires_at']}")

        signature_b64 = self.authz.sign_bytes(self.key, message)
        block = self._record(op, str(unsigned["job_id"]), signature_b64)
        return {
            "ok": True,
            "job": {**unsigned, "signature_b64": signature_b64},
            "ledger_block": block["hash"],
        }

    def _sign_admin_request(self, op: str, request: dict[str, Any]) -> dict[str, Any]:
        """Admin requests (admin-supervise) are signed the way cluster jobs are:
        rebuilt over the canonical projection so a smuggled signature is
        discarded, expiry is checked, and the ledger records the request_id."""
        admin = request.get("request")
        if not isinstance(admin, dict):
            return self._refuse("sign-admin-request requires an 'admin-request' object")

        unsigned = {k: v for k, v in admin.items() if k != "signature_b64"}
        try:
            message = self.authz.admin_request_message(unsigned)
        except Exception as exc:
            return self._refuse(f"admin request is not canonicalisable: {exc}")

        now = (self.clock or (lambda: datetime.now(timezone.utc)))()
        if self.authz.is_expired(unsigned["expires_at"], now):
            return self._refuse(f"refusing to sign an admin request that expired at {unsigned['expires_at']}")

        signature_b64 = self.authz.sign_bytes(self.key, message)
        block = self._record(op, str(unsigned["request_id"]), signature_b64)
        return {
            "ok": True,
            "admin_request": {**unsigned, "signature_b64": signature_b64},
            "ledger_block": block["hash"],
        }

    def _sign_rfi_answer(self, op: str, request: dict[str, Any]) -> dict[str, Any]:
        """Sign one RFI answer (contracts/rfi-schema.json) for a peer's 01_Inbox.

        The payload arrives base64-encoded because JSON cannot carry raw bytes; it
        is decoded strictly here and ``content_sha256`` is computed by
        ``authz.sign_rfi_answer`` from those bytes, never taken from the caller —
        the same rule as the registry publication, so a caller cannot hand the
        signer a digest naming one payload and content that is another. The
        destination ``item_name`` is inside the signed projection, so a name that
        traverses out of ``01_Inbox/`` is refused here rather than at the write.
        An empty payload is legitimate ("nothing found"); refusing it would push a
        Master to invent content.
        """
        answer = request.get("answer")
        if not isinstance(answer, dict):
            return self._refuse("sign-rfi-answer requires an 'answer' object")

        content_b64 = answer.get("content_b64")
        if not isinstance(content_b64, str):
            return self._refuse(
                "sign-rfi-answer requires 'content_b64' (the answer payload, base64; '' is a legitimate empty answer)"
            )
        try:
            content = self.authz.decode_b64_strict(content_b64, what="rfi answer content")
        except self.authz.AuthzError as exc:
            return self._refuse(f"rfi answer content is not valid base64: {exc}")

        try:
            signed = self.authz.sign_rfi_answer(
                content=content,
                item_name=answer.get("item_name"),
                peer_fingerprint=answer.get("peer_fingerprint"),
                request_id=answer.get("request_id"),
                master_private_key=self.key,
                now=(self.clock or (lambda: datetime.now(timezone.utc)))(),
            )
        except self.authz.AuthzError as exc:
            return self._refuse(f"refusing to sign this rfi answer: {exc}")

        signature_b64 = signed["signature_b64"]
        block = self._record(op, str(signed["request_id"]), signature_b64)
        return {
            "ok": True,
            "answer": signed,
            "ledger_block": block["hash"],
        }

    def _sign_share_ratification(self, op: str, request: dict[str, Any]) -> dict[str, Any]:
        """Sign one share ratification and record it as a Master ledger event.

        The envelope is the shared projection in ``shared/sparknet-authz.py``.
        A ratification whose 2 h deadline already passed is refused rather than
        signed into a valid-looking record nobody can use.
        """
        ratification = request.get("ratification")
        if not isinstance(ratification, dict):
            return self._refuse("sign-share-ratification requires a 'ratification' object")
        unsigned = {key: value for key, value in ratification.items() if key != "signature_b64"}
        try:
            self.authz.share_ratification_message(unsigned)
        except self.authz.AuthzError as exc:
            return self._refuse(f"share ratification is not canonicalisable: {exc}")
        now = (self.clock or (lambda: datetime.now(timezone.utc)))()
        if unsigned["decision"] == "ratified" and self.authz.is_expired(unsigned["deadline"], now):
            return self._refuse(f"refusing to ratify a share whose deadline passed at {unsigned['deadline']}")
        signed = self.authz.sign_share_ratification(unsigned, self.key)
        self.signed_count += 1
        block = record_event(
            self.ledger_path,
            self.node_id,
            "share_ratified",
            {
                "share_id": unsigned["share_id"],
                "node_id": unsigned["node_id"],
                "grant_id": unsigned["grant_id"],
                "decision": unsigned["decision"],
                "signature_b64": signed["signature_b64"],
            },
            self.root_id,
            authz=self.authz,
            private_key=self.key,
            node_pubkey_b64=self.public_key_b64,
            clock=self.clock,
        )
        return {"ok": True, "ratification": signed, "ledger_block": block["hash"]}

    def _record_share_evidence(self, op: str, request: dict[str, Any]) -> dict[str, Any]:
        """Record the hash and metadata of one evidence event in the signed ledger.

        The evidence file itself lives in the git review repository; the ledger
        records only the digest and the share identities, so a clone can check the
        file against the chain without the ledger carrying page content.
        """
        evidence = request.get("evidence")
        if not isinstance(evidence, dict):
            return self._refuse("record-share-evidence requires an 'evidence' object")
        required = ("event_type", "grant_id", "node_pair", "share_type", "content_sha256", "captured_at")
        missing = [name for name in required if not isinstance(evidence.get(name), str) or not evidence[name].strip()]
        if missing:
            return self._refuse(f"evidence missing non-empty field(s): {', '.join(missing)}")
        digest = evidence["content_sha256"]
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            return self._refuse("evidence content_sha256 must be 64 lowercase hex characters")
        self.signed_count += 1
        block = record_event(
            self.ledger_path,
            self.node_id,
            "share_evidence",
            {
                "event_type": evidence["event_type"],
                "grant_id": evidence["grant_id"],
                "node_pair": evidence["node_pair"],
                "share_type": evidence["share_type"],
                "content_sha256": digest,
                "captured_at": evidence["captured_at"],
            },
            self.root_id,
            authz=self.authz,
            private_key=self.key,
            node_pubkey_b64=self.public_key_b64,
            clock=self.clock,
        )
        return {"ok": True, "ledger_block": block["hash"], "content_sha256": digest}

    def _sign_trust_transition(self, op: str, request: dict[str, Any]) -> dict[str, Any]:
        """Sign a reversible trust belief and record it as a Master ledger event."""
        transition = request.get("transition")
        if not isinstance(transition, dict):
            return self._refuse("sign-trust-transition requires a 'transition' object")
        unsigned = {key: value for key, value in transition.items() if key != "signature_b64"}
        try:
            self.authz.trust_transition_message(unsigned)
        except self.authz.AuthzError as exc:
            return self._refuse(f"trust transition is not canonicalisable: {exc}")
        signed = self.authz.sign_trust_transition(unsigned, self.key)
        self.signed_count += 1
        block = record_event(
            self.ledger_path,
            self.node_id,
            "trust_level_changed",
            {
                "node_id": unsigned["node_id"],
                "level": unsigned["level"],
                "previous_level": unsigned["previous_level"],
                "reason": unsigned["reason"],
                "signature_b64": signed["signature_b64"],
            },
            self.root_id,
            authz=self.authz,
            private_key=self.key,
            node_pubkey_b64=self.public_key_b64,
            clock=self.clock,
        )
        return {"ok": True, "transition": signed, "ledger_block": block["hash"]}

    def _record(self, op: str, subject: str, signature_b64: str) -> dict[str, Any]:
        self.signed_count += 1
        return record_event(
            self.ledger_path,
            self.node_id,
            "signature_issued",
            {
                "operation": op,
                "subject": subject,
                "signature_b64": signature_b64,
            },
            self.root_id,
            authz=self.authz,
            private_key=self.key,
            node_pubkey_b64=self.public_key_b64,
            clock=self.clock,
        )


# --- transport ---------------------------------------------------------------


def serve(
    signer: Signer,
    socket_path: Path,
    max_request_bytes: int = 1 << 20,
    read_timeout: float = REQUEST_READ_TIMEOUT_SECONDS,
) -> None:
    """One JSON object per line; each connection served on its own thread.

    This replaces the original single-threaded loop. A silent client used to
    hold the whole signer: the accept loop blocked in ``recv`` on the first
    connection, so every later request queued behind one stalled caller. Now:

    * every connection is read on its own daemon thread, so a second client is
      served while the first is still connected and silent;
    * every read is bounded by ``read_timeout``, and the bound is deadline-based,
      so trickling one byte at a time does not stretch it (bytes are bound
      separately by ``max_request_bytes``);
    * a client that exceeds the bound is answered ``{"ok": false,
      "error": "timeout"}`` and closed;
    * ``signer.handle`` is still serialised by one lock. The signer appends to a
      hash chain, and the order blocks land in is part of what the chain attests;
      the lock keeps that order a strict total order. One process still holds the
      key, and one request still mutates the ledger at a time — the difference is
      simply that a stalled caller no longer blocks the whole signer.
    """
    # The CLI hands this a string (the scheme check in check_socket_path needs the
    # unconverted text); normalise here so the transport itself only ever sees a Path.
    socket_path = Path(socket_path)
    if not hasattr(socket, "AF_UNIX"):  # pragma: no cover - defensive
        raise SignerError("this platform has no unix sockets; refusing to substitute TCP for a key service")
    if socket_path.exists():
        socket_path.unlink()
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sign_lock = threading.Lock()
    try:
        server.bind(str(socket_path))
        # 0600 on the socket itself: the peer surface runs as the same uid on most
        # nodes, so directory permissions alone would not keep it out.
        os.chmod(socket_path, 0o600)
        server.listen(8)
        while True:
            connection, _ = server.accept()
            threading.Thread(
                target=_serve_one,
                args=(signer, connection, max_request_bytes, read_timeout, sign_lock),
                name="signer-client",
                daemon=True,
            ).start()
    finally:
        server.close()
        if socket_path.exists():
            socket_path.unlink()


class _ReadTimeout(Exception):
    """The client did not finish its line before the read deadline."""


class _RequestTooLarge(Exception):
    """The client's line exceeded the per-request size cap."""


def _read_line(connection: socket.socket, max_request_bytes: int, read_timeout: float) -> bytes:
    """One line. Deadline-based, so a trickle of bytes does not reset the clock."""
    deadline = time.monotonic() + read_timeout
    buffered = b""
    while b"\n" not in buffered:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _ReadTimeout()
        connection.settimeout(remaining)
        try:
            chunk = connection.recv(4096)
        except (TimeoutError, socket.timeout):  # noqa: UP041 - distinct on ≤3.9
            # `socket.timeout` and `TimeoutError` are the same class only from
            # Python 3.10; on the 3.9 hosts this fabric deploys to they are
            # distinct, so both must be named or the timeout escapes, kills the
            # thread, and the client sees a bare EOF instead of the refusal.
            raise _ReadTimeout() from None
        if not chunk:
            return b""
        buffered += chunk
        if len(buffered) > max_request_bytes:
            raise _RequestTooLarge()
    return buffered.split(b"\n", 1)[0]


def _serve_one(
    signer: Signer,
    connection: socket.socket,
    max_request_bytes: int,
    read_timeout: float,
    sign_lock: threading.Lock,
) -> None:
    """Read one line, answer once, close. Runs in a per-connection thread.

    The size cap is a memory bound, not politeness: an unbounded `recv` loop is a
    way for a caller to make this process hold a gigabyte before parsing it. The
    read deadline (``read_timeout``) is the bound on silence: without it a
    connected-but-silent client would hold this thread's slot forever.
    """
    with connection:
        try:
            line = _read_line(connection, max_request_bytes, read_timeout)
        except _ReadTimeout:
            connection.settimeout(None)
            _send(connection, {"ok": False, "error": "timeout"})
            return
        except _RequestTooLarge:
            connection.settimeout(None)
            _send(connection, {"ok": False, "error": "request exceeds the size limit"})
            return
        if not line:
            return  # peer closed without a full line
        connection.settimeout(None)

        try:
            request = json.loads(line.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            _send(connection, {"ok": False, "error": f"malformed JSON: {exc}"})
            return

        with sign_lock:
            try:
                response = signer.handle(request)
            except Exception as exc:
                # The signer stays up. A process that exits on a malformed request turns a
                # bug in a caller into a cluster-wide loss of signing.
                response = {"ok": False, "error": f"internal error: {exc}"}
        _send(connection, response)


def _send(connection: socket.socket, payload: dict[str, Any]) -> None:
    connection.sendall(json.dumps(payload).encode("utf-8") + b"\n")


# --- CLI ---------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Sparknet isolated signer. Signs registry entries and guard approvals; nothing else."
    )
    parser.add_argument("--node-id", help="this node's id; the root must name it Master")
    parser.add_argument("--root", type=Path, help="cluster trust root naming this node Master")
    parser.add_argument("--key", type=Path, default=DEFAULT_STATE_DIR / "keys" / "operational.ed25519")
    # Left as a string, not type=Path, so check_socket_path can see the scheme.
    # Path() collapses "tcp://host:port" to "tcp:/host:port" and the check that
    # exists to catch exactly that input would miss it.
    parser.add_argument("--socket", default=str(DEFAULT_STATE_DIR / "signer" / "signer.sock"))
    parser.add_argument("--ledger", type=Path, default=ROLE_ROOT / "blockchain" / "ledger.json")
    parser.add_argument(
        "--accept-requalification",
        action="store_true",
        help=(
            "allow starting against a root other than the one this node's ledger "
            "already records. Required for re-formation and refused by default, so "
            "rolling the Master back takes a deliberate flag"
        ),
    )
    parser.add_argument(
        "--describe",
        action="store_true",
        help="print the isolation posture and exit without binding a socket",
    )
    args = parser.parse_args(argv)

    if args.describe:
        # Checked before the required-argument split so an operator can inspect the
        # posture on a machine with no key and no root, which is exactly where they
        # would want to read it.
        print(json.dumps(describe(), indent=2))
        return 0

    if not args.node_id or not args.root:
        parser.error("--node-id and --root are required unless --describe is given")

    try:
        check_key_permissions(args.key)
        check_socket_path(args.socket)
        authz, consensus = load_modules()
        root = json.loads(args.root.read_text())
        signer = Signer(
            args.node_id,
            args.key,
            root,
            authz,
            consensus,
            Path(args.ledger),
            allow_requalification=args.accept_requalification,
        )
    except (SignerError, OSError, json.JSONDecodeError) as exc:
        print(f"[signer] {exc}", file=sys.stderr)
        return 1

    print(
        f"[signer] node {args.node_id} is Master under root {signer.root_id[:16]}...\n"
        f"[signer] capabilities: {', '.join(sorted(SIGNER_CAPABILITIES))}\n"
        f"[signer] socket: {args.socket} (0600, unix only)",
        file=sys.stderr,
    )
    try:
        serve(signer, args.socket)
    except KeyboardInterrupt:
        return 0
    except OSError as exc:
        if exc.errno == errno.EADDRINUSE:
            print(f"[signer] socket in use: {args.socket}", file=sys.stderr)
            return 1
        raise
    return 0


def describe() -> dict[str, Any]:
    """The isolation posture, so `--describe` states it rather than implying it."""
    return {
        "capabilities": sorted(SIGNER_CAPABILITIES),
        "operations": list(OPERATIONS),
        "signs": list(SIGN_OPERATIONS),
        "transport": "unix socket, mode 0600, one JSON object per line",
        "refuses": [
            "a TCP address for the socket",
            "a socket path outside $SPARKNET_STATE_DIR",
            "a key file readable by group or other",
            "a root that is not valid, or that names another node as Master",
            "a root whose master_pubkey is not the loaded key",
            "a request naming any root but the pinned one",
            "caller-supplied bytes to sign",
            "registry entries granting unknown capabilities",
            "guard approvals missing peer, version, path, action or expiry",
            "guard approvals whose expiry has already passed",
            "cluster jobs missing a job id, conversation, initiator, mode, prompt or subtasks",
            "cluster jobs naming an unknown mode",
            "cluster jobs whose expiry has already passed or cannot be parsed",
        ],
        "not_reachable_from": [
            "the dispatch bridge",
            "agent ports",
            "the Open WebUI network",
            "any peer service, which loads by path and never imports this module",
        ],
    }


if __name__ == "__main__":
    raise SystemExit(main())
