import os
import uuid
from datetime import datetime, timezone, timedelta

import jwt  # PyJWT
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel

ISSUER = "control-plane"
AUDIENCE = "agent-runtime"
ALGORITHM = "EdDSA"


class Claims(BaseModel):
    sub: str          # agent id
    caps: list[str]   # capability claims
    jti: str          # unique token id, used for revocation
    iss: str          # issuer — checked on verify
    aud: str          # audience — checked on verify
    iat: int          # issued at (unix seconds)
    exp: int          # expires at (unix seconds)


def _signing_key() -> Ed25519PrivateKey:
    seed = __import__("base64").b64decode(os.environ["CONTROL_PLANE_PRIVATE_KEY"])
    return Ed25519PrivateKey.from_private_bytes(seed)


def mint(sub: str, caps: list[str], ttl_seconds: int = 300) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": sub,
        "caps": caps,
        "jti": uuid.uuid4().hex,
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl_seconds)).timestamp()),
    }
    return jwt.encode(payload, _signing_key(), algorithm=ALGORITHM)


def verify(token: str) -> Claims:
    """Verify signature, iss, aud, exp. Raises jwt.PyJWTError subclasses
    (ExpiredSignatureError, InvalidAudienceError, InvalidSignatureError, ...).
    Callers should catch jwt.PyJWTError and convert to a PEP decision."""
    public_key = _signing_key().public_key()
    decoded = jwt.decode(
        token,
        public_key,
        algorithms=[ALGORITHM],
        audience=AUDIENCE,
        issuer=ISSUER,
        options={"require": ["exp", "iat", "iss", "aud", "sub", "jti", "caps"]},
    )
    return Claims(**decoded)
