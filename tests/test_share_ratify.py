"""Share ratification: a real grant check and a real Master signature (Step 10).

The tests use a generated Master key, the real `shared/sparknet-authz.py`
verification path and the real canonical ratification envelope. They never use
the live signer socket or the live registry; a fake signer callback stands in
for the isolated process, and the resulting envelope is verified independently.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROLE_ROOT = Path(__file__).resolve().parent.parent
SHARED = ROLE_ROOT.parent / "shared"
CLOCK = datetime(2026, 10, 29, 12, 0, tzinfo=timezone.utc)


def _load(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def authz() -> ModuleType:
    return _load("share_ratify_authz", SHARED / "sparknet-authz.py")


@pytest.fixture(scope="module")
def ratify() -> ModuleType:
    return _load("share_ratify_service", ROLE_ROOT / "services" / "sparknet-share-ratify.py")


@pytest.fixture(scope="module")
def master_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def _identity() -> dict:
    return {
        "node_id": "peer-1",
        "role": "peer",
        "wireguard_public_key_b64": base64.b64encode(b"k" * 32).decode(),
        "overlay_ipv4": "10.100.0.2/32",
        "requested_capabilities": ["p2p-sync"],
    }


def _registry(tmp_path: Path, authz: ModuleType, master_key: Ed25519PrivateKey, *, revoked: bool = False) -> Path:
    entry = authz.sign_authorization(_identity(), master_key, ["p2p-sync"], ttl_days=1, now=CLOCK, revoked=revoked)
    path = tmp_path / "registry.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "master_public_key_b64": authz.public_key_b64(master_key.public_key()),
                "authorizations": [entry],
            }
        )
    )
    return path


def _grant(authz: ModuleType, master_key: Ed25519PrivateKey, *, ttl_minutes: int = 60, nonce: str = "n1") -> dict:
    return authz.mint_grant(
        node_identity=_identity(),
        grant_id="g1",
        user_identity="operator",
        conversation_key="conversation-1",
        capabilities=["p2p-sync"],
        vault_scope=[],
        ttl_minutes=ttl_minutes,
        nonce=nonce,
        master_private_key=master_key,
        now=CLOCK,
    )


def _request(authz: ModuleType, master_key: Ed25519PrivateKey, **overrides) -> dict:
    request = {
        "share_id": "share-1",
        "node_id": "peer-1",
        "share_type": "kb-view",
        "accepted_at": CLOCK.isoformat(),
        "grant": _grant(authz, master_key),
    }
    request.update(overrides)
    return request


def _ratifier(ratify: ModuleType, authz: ModuleType, registry: Path, master_key: Ed25519PrivateKey, *, signer=True):
    callback = (lambda envelope: authz.sign_share_ratification(envelope, master_key)) if signer else None
    return ratify.ShareRatifier(registry, signer=callback, authz=authz, clock=lambda: CLOCK)


def test_a_valid_grant_is_accepted_and_a_real_ratification_is_signed(
    ratify: ModuleType, authz: ModuleType, master_key: Ed25519PrivateKey, tmp_path: Path
) -> None:
    service = _ratifier(ratify, authz, _registry(tmp_path, authz, master_key), master_key)
    accepted = service.accept_share_request(_request(authz, master_key))
    assert accepted["status"] == "pending"
    assert accepted["deadline"] == (CLOCK + timedelta(hours=2)).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )

    result = service.ratify("share-1")
    assert result["ok"] is True
    assert result["status"] == "ratified"
    assert result["flag_retained"] is True
    signed = result["ratification"]
    assert authz.verify_share_ratification(
        signed, authz.public_key_from_b64(authz.public_key_b64(master_key.public_key()))
    )


def test_a_tampered_grant_is_refused(
    ratify: ModuleType, authz: ModuleType, master_key: Ed25519PrivateKey, tmp_path: Path
) -> None:
    grant = _grant(authz, master_key)
    grant["vault_scope"] = ["secret/page"]
    service = _ratifier(ratify, authz, _registry(tmp_path, authz, master_key), master_key)
    with pytest.raises(ratify.ShareRatifyError, match="invalid-grant"):
        service.accept_share_request(_request(authz, master_key, grant=grant))


def test_a_revoked_node_is_refused(
    ratify: ModuleType, authz: ModuleType, master_key: Ed25519PrivateKey, tmp_path: Path
) -> None:
    service = _ratifier(ratify, authz, _registry(tmp_path, authz, master_key, revoked=True), master_key)
    with pytest.raises(ratify.ShareRatifyError, match="invalid-grant"):
        service.accept_share_request(_request(authz, master_key))


def test_an_expired_grant_is_refused(
    ratify: ModuleType, authz: ModuleType, master_key: Ed25519PrivateKey, tmp_path: Path
) -> None:
    expired = _grant(authz, master_key, ttl_minutes=1)
    service = _ratifier(ratify, authz, _registry(tmp_path, authz, master_key), master_key)
    # The service clock is CLOCK; the grant expired at CLOCK + 1 minute, so move
    # the request's acceptance past that point.
    late = CLOCK + timedelta(minutes=2)
    service.clock = lambda: late
    with pytest.raises(ratify.ShareRatifyError, match="invalid-grant"):
        service.accept_share_request(_request(authz, master_key, grant=expired, accepted_at=late.isoformat()))


def test_a_late_decision_is_a_signed_refusal(
    ratify: ModuleType, authz: ModuleType, master_key: Ed25519PrivateKey, tmp_path: Path
) -> None:
    old = CLOCK - timedelta(hours=3)
    service = _ratifier(ratify, authz, _registry(tmp_path, authz, master_key), master_key)
    service.accept_share_request(_request(authz, master_key, accepted_at=old.isoformat()))

    result = service.ratify("share-1")
    assert result["ok"] is False
    assert result["status"] == "refused"
    assert result["ratification"]["reason"] == "deadline-exceeded"
    assert result["flag_retained"] is True
    assert authz.verify_share_ratification(
        result["ratification"], authz.public_key_from_b64(authz.public_key_b64(master_key.public_key()))
    )


def test_no_signer_fails_closed(
    ratify: ModuleType, authz: ModuleType, master_key: Ed25519PrivateKey, tmp_path: Path
) -> None:
    service = _ratifier(ratify, authz, _registry(tmp_path, authz, master_key), master_key, signer=False)
    service.accept_share_request(_request(authz, master_key))
    with pytest.raises(ratify.ShareRatifyError, match="no-signer"):
        service.ratify("share-1")


def test_a_signer_that_does_not_verify_is_refused(
    ratify: ModuleType, authz: ModuleType, master_key: Ed25519PrivateKey, tmp_path: Path
) -> None:
    service = _ratifier(ratify, authz, _registry(tmp_path, authz, master_key), master_key)
    service.signer = lambda _envelope: {"not": "a ratification"}
    service.accept_share_request(_request(authz, master_key))
    with pytest.raises(ratify.ShareRatifyError, match="bad-signature"):
        service.ratify("share-1")


def test_a_duplicate_share_id_is_refused(
    ratify: ModuleType, authz: ModuleType, master_key: Ed25519PrivateKey, tmp_path: Path
) -> None:
    service = _ratifier(ratify, authz, _registry(tmp_path, authz, master_key), master_key)
    request = _request(authz, master_key)
    service.accept_share_request(request)
    with pytest.raises(ratify.ShareRatifyError, match="duplicate-share"):
        service.accept_share_request(request)


def test_a_share_can_only_be_decided_once(
    ratify: ModuleType, authz: ModuleType, master_key: Ed25519PrivateKey, tmp_path: Path
) -> None:
    service = _ratifier(ratify, authz, _registry(tmp_path, authz, master_key), master_key)
    service.accept_share_request(_request(authz, master_key))
    service.ratify("share-1")
    with pytest.raises(ratify.ShareRatifyError, match="already-decided"):
        service.ratify("share-1")
