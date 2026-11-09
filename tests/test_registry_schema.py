"""The registry's shape must be stated once and checked, not described.

Master build plan Step 2 asked for a machine-checkable schema for the registry
and for the "specified, not built" status to be detectable. The draft schema it
found described a shape nothing produced: a ``role`` field no document carries,
a ``schema_version`` of ``1.0.0`` while the shipped registry says ``1.0``, and
an entry signature field named ``signature`` while the one implementation emits
and verifies ``signature_b64``. Nothing loaded the schema, so none of that was
caught.

These tests are the catch. They pin the shape to the implementation rather than
to a draft, which is the only version of this that can stay true.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from sparknet_loader import load_by_path

ROLE_ROOT = Path(__file__).resolve().parent.parent
FABRIC_ROOT = ROLE_ROOT.parent

SCHEMA = FABRIC_ROOT / "contracts" / "registry-schema.json"
MASTER_SCHEMA = ROLE_ROOT / "manifests" / "registry.schema.json"
SHIPPED_REGISTRY = FABRIC_ROOT / "peer-node" / "manifests" / "node-authorizations.json"


def _load(name: str, path: Path):
    """Load a fabric module by path, once."""
    return load_by_path(name, path)


@pytest.fixture(scope="module")
def checker():
    return _load("registry_schema_checker", FABRIC_ROOT / "shared" / "sparknet-registry-schema.py")


@pytest.fixture(scope="module")
def authz():
    return _load("registry_schema_authz", FABRIC_ROOT / "shared" / "sparknet-authz.py")


@pytest.fixture(scope="module")
def schema():
    return json.loads(SCHEMA.read_text())


def _signed_document(authz, tmp_path: Path, *, capabilities: list[str] | None = None) -> dict:
    """A registry the implementation itself produced: one signed entry."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private = Ed25519PrivateKey.generate()
    public_b64 = base64.b64encode(private.public_key().public_bytes_raw()).decode("ascii")
    identity = {
        "node_id": "node-test",
        "role": "peer",
        "wireguard_public_key_b64": base64.b64encode(b"\x02" * 32).decode("ascii"),
        "overlay_ipv4": "10.100.0.9",
        "requested_capabilities": capabilities if capabilities is not None else ["telemetry"],
    }
    entry = authz.sign_authorization(identity, private, identity["requested_capabilities"], ttl_days=1)
    return {
        "schema_version": "1.0",
        "master_public_key_b64": public_b64,
        "description": "a registry minted by the implementation itself",
        "authorizations": [entry],
    }


# --- DoD (1): the schema exists, and it validates the shipped registry ----------


def test_the_shipped_registry_conforms_to_the_contract_schema(checker, schema, authz) -> None:
    """DoD (1): the shipped registry validates against the schema.

    The document a peer actually starts from — the one under
    `peer-node/manifests/` — must be the shape the contract states. A schema
    that the shipped file fails is a schema nobody checks.
    """
    document = json.loads(SHIPPED_REGISTRY.read_text())
    problems = checker.validate_document(document, schema, authz)
    assert problems == [], f"the shipped registry does not conform: {problems}"


def test_the_masters_schema_is_the_contract_schema_and_not_a_copy() -> None:
    """One shape, one file. The Master's path is a symlink to the contract.

    Two copies of a registry's shape would be two answers to "what does a
    registry look like", and the copies would drift — which is exactly what
    happened with the draft that sat here before.
    """
    assert MASTER_SCHEMA.is_symlink(), (
        "master-node/manifests/registry.schema.json must be a symlink to "
        "contracts/registry-schema.json, not a copy of it"
    )
    assert MASTER_SCHEMA.resolve() == SCHEMA.resolve()


def test_the_schema_accepts_what_the_implementation_mints(checker, schema, authz, tmp_path) -> None:
    """The shape the Master produces is a shape the contract accepts.

    This is the property the draft broke: `sign_authorization` emits
    `signature_b64`, the draft asked for `signature`, and no test compared the
    two. Minting a registry with the implementation and checking it against the
    contract is what makes that impossible to reintroduce.
    """
    document = _signed_document(authz, tmp_path)
    problems = checker.validate_document(document, schema, authz)
    assert problems == [], f"a registry the implementation produced does not conform: {problems}"


# --- the draft's mistakes are refused ------------------------------------------


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ({"role": "registry"}, "undeclared field 'role'"),
        ({"schema_version": "1.0.0"}, "expected '1.0'"),
    ],
)
def test_the_shape_the_draft_described_is_refused(checker, schema, authz, tmp_path, mutation, expected) -> None:
    """A registry carrying the draft's fields does not conform.

    The draft schema asked for a `role` field and for version `1.0.0`; the
    shipped document carries neither. If the contract ever drifts back to the
    draft, the shipped registry stops validating — which is the point.
    """
    document = _signed_document(authz, tmp_path)
    document.update(mutation)
    problems = checker.validate_document(document, schema, authz)
    assert any(expected in problem for problem in problems), f"expected {expected!r} in {problems}"


def test_the_draft_signature_field_name_is_refused(checker, schema, authz, tmp_path) -> None:
    """`signature` is not the field. `signature_b64` is.

    The draft named it `signature`; the implementation emits and verifies
    `signature_b64` and has never read any other name. An entry carrying
    `signature` is unsigned as far as every role is concerned.
    """
    document = _signed_document(authz, tmp_path)
    entry = dict(document["authorizations"][0])
    entry["signature"] = entry.pop("signature_b64")
    document["authorizations"] = [entry]
    problems = checker.validate_document(document, schema, authz)
    assert any("signature_b64" in problem for problem in problems), f"expected a signature_b64 problem in {problems}"


def test_an_entry_whose_fingerprint_does_not_match_its_identity_is_refused(checker, schema, authz, tmp_path) -> None:
    """The fingerprint is the lookup key and must be the identity's.

    A mismatch means the entry is filed under a name it does not have, and the
    signature no longer covers what the peer would verify.
    """
    document = _signed_document(authz, tmp_path)
    entry = dict(document["authorizations"][0])
    entry["fingerprint"] = "0" * 64
    document["authorizations"] = [entry]
    problems = checker.validate_document(document, schema, authz)
    assert any("fingerprint" in problem for problem in problems), f"expected a fingerprint problem in {problems}"


def test_a_capability_outside_the_vocabulary_is_refused(checker, schema, authz, tmp_path) -> None:
    """The capability vocabulary is closed, and the contract says so.

    An entry granting a capability nobody declared is not narrowed to what was
    declared — it is refused.
    """
    document = _signed_document(authz, tmp_path)
    entry = dict(document["authorizations"][0])
    entry["capabilities"] = ["telemetry", "not-a-capability"]
    document["authorizations"] = [entry]
    problems = checker.validate_document(document, schema, authz)
    assert any("vocabulary" in problem for problem in problems), f"expected a capability problem in {problems}"


def test_an_entry_whose_signature_does_not_verify_is_refused(checker, schema, authz, tmp_path) -> None:
    """Shape conformance is not authorisation.

    A registry can have every field right and still carry a signature nobody
    made. The checker verifies each entry under the key the document names.
    """
    document = _signed_document(authz, tmp_path)
    entry = dict(document["authorizations"][0])
    entry["signature_b64"] = base64.b64encode(b"\x00" * 64).decode("ascii")
    document["authorizations"] = [entry]
    problems = checker.validate_document(document, schema, authz)
    assert any("does not verify" in problem for problem in problems), f"expected a signature problem in {problems}"


# --- the contract and the implementation agree ----------------------------------


def test_the_contract_still_says_what_the_implementation_does(checker, schema, authz) -> None:
    """The drift gate: contract vs implementation.

    The contract states the shape; the implementation is what runs. If the two
    disagree, the contract is wrong — but it must not stay wrong, and this is
    what notices.
    """
    problems = checker.check_contract(schema, authz)
    assert problems == [], f"the contract drifted from the implementation: {problems}"


def test_a_schema_keyword_the_checker_does_not_implement_is_refused(checker, schema, authz, tmp_path) -> None:
    """A rule nobody enforces is not a rule.

    If the contract grows a keyword the checker does not implement, the checker
    must fail rather than ignore it — otherwise the schema would carry a
    constraint that looks enforced and is not.
    """
    broken = json.loads(json.dumps(schema))
    broken["entry_fields"]["fingerprint"]["multipleOf"] = 2
    document = _signed_document(authz, tmp_path)
    problems = checker.validate_document(document, broken, authz)
    assert any("unknown keyword" in problem for problem in problems), (
        f"expected an unknown-keyword refusal in {problems}"
    )


def test_the_shipped_registry_ships_empty_on_purpose() -> None:
    """Empty by default: a fresh deployment is fail-closed.

    A committed entry grants capabilities to whoever holds the matching
    identity, so the shipped registry carries none.
    """
    document = json.loads(SHIPPED_REGISTRY.read_text())
    assert document.get("authorizations") == [], (
        "the shipped registry must ship empty; a committed entry grants capabilities "
        "to whoever holds the matching identity"
    )
