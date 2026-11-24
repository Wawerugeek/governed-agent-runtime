from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from control_plane.identity import tokens
from control_plane.identity.revocation import RevocationStore


app = FastAPI(title="Agent Control Plane")
_revocation = RevocationStore()


class TokenRequest(BaseModel):
    sub: str
    caps: list[str]
    ttl_seconds: int = 300


class TokenResponse(BaseModel):
    token: str
    jti: str
    exp: int


class RevokeRequest(BaseModel):
    jti: str
    exp: int


@app.post("/token", response_model=TokenResponse)
def issue_token(req: TokenRequest) -> TokenResponse:
    # Demo: unauthenticated. Production: admin-only, requires caller identity.
    # Noted in THREAT_MODEL.md (v1.0).
    token = tokens.mint(req.sub, req.caps, req.ttl_seconds)
    claims = tokens.verify(token)  # decode to expose jti/exp
    return TokenResponse(token=token, jti=claims.jti, exp=claims.exp)


@app.post("/revoke")
def revoke(req: RevokeRequest) -> dict:
    # Demo: unauthenticated. Production: admin-only + audit of who revoked what.
    _revocation.revoke(req.jti, req.exp)
    return {"revoked": req.jti}


@app.get("/revoked/{jti}")
def is_revoked(jti: str) -> dict:
    return {"jti": jti, "revoked": _revocation.is_revoked(jti)}


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}
