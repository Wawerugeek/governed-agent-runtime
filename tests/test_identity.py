import os
import base64
import time

import jwt
import pytest

from control_plane.identity.tokens import mint, verify, Claims
from control_plane.identity.revocation import RevocationStore


@pytest.fixture(autouse=True)
def _key(monkeypatch):
    seed = os.urandom(32)
    monkeypatch.setenv("CONTROL_PLANE_PRIVATE_KEY", base64.b64encode(seed).decode())


def test_mint_and_verify_roundtrip():
    token = mint("agent-1", ["fs.read"])
    claims = verify(token)
    assert isinstance(claims, Claims)
    assert claims.sub == "agent-1"
    assert claims.caps == ["fs.read"]
    assert claims.exp > time.time()


def test_expired_token_rejected():
    token = mint("agent-1", ["fs.read"], ttl_seconds=-1)  # exp in the past
    with pytest.raises(jwt.ExpiredSignatureError):
        verify(token)


def test_wrong_key_rejected(monkeypatch):
    token = mint("agent-1", ["fs.read"])
    # swap to a fresh key — this simulates a forgery attempt
    monkeypatch.setenv(
        "CONTROL_PLANE_PRIVATE_KEY", base64.b64encode(os.urandom(32)).decode()
    )
    with pytest.raises(jwt.InvalidSignatureError):
        verify(token)


def test_tampered_claims_rejected():
    token = mint("agent-1", ["fs.read"])
    header, payload, sig = token.split(".")
    # flip a character in the payload segment
    forged = f"{header}.{payload[:-2]}AA.{sig}"
    with pytest.raises(jwt.PyJWTError):
        verify(forged)


def test_revocation_store():
    store = RevocationStore()
    exp = int(time.time()) + 300
    assert store.is_revoked("jti-1") is False
    store.revoke("jti-1", exp)
    assert store.is_revoked("jti-1") is True
    # unrelated jti stays clean
    assert store.is_revoked("jti-2") is False
