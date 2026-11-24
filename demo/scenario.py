import os
import time
import json
import base64
import threading

import httpx
import uvicorn
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import jwt as pyjwt

from control_plane.api.app import app
from control_plane.policy.engine import PolicyEngine
from control_plane.audit.log import AuditLog
from control_plane.identity import tokens
from agent_runtime.pep_client import PEPClient
from agent_runtime.graph import run_scripted


CONTROL_PLANE = "http://127.0.0.1:8000"


def _start_api_in_thread() -> None:
    config = uvicorn.Config(app, host="127.0.0.1", port=8000, log_level="warning")
    server = uvicorn.Server(config)
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    # wait for readiness
    for _ in range(20):
        try:
            if httpx.get(f"{CONTROL_PLANE}/health", timeout=0.2).status_code == 200:
                return
        except httpx.HTTPError:
            time.sleep(0.1)
    raise RuntimeError("control plane did not start")


def _forge_token(sub: str, caps: list[str]) -> str:
    """Sign with a fresh key the control plane doesn't know — simulates theft
    of the signing code rather than the signing key. Expect signature failure."""
    fake_sk = Ed25519PrivateKey.generate()
    now = int(time.time())
    payload = {
        "sub": sub, "caps": caps, "jti": "forged",
        "iss": tokens.ISSUER, "aud": tokens.AUDIENCE,
        "iat": now, "exp": now + 300,
    }
    return pyjwt.encode(payload, fake_sk, algorithm=tokens.ALGORITHM)


def main() -> None:
    open("/tmp/hello.txt", "w").write("hello from governed agent\n")

    # PEP checks revocation via the control plane over HTTP.
    def is_revoked(jti: str) -> bool:
        return httpx.get(f"{CONTROL_PLANE}/revoked/{jti}", timeout=1.0).json()["revoked"]

    pep = PEPClient(PolicyEngine(), AuditLog("audit.jsonl"), is_revoked=is_revoked)

    _start_api_in_thread()

    # 1) mint a token via the API (agent would do this in v0.3)
    resp = httpx.post(f"{CONTROL_PLANE}/token", json={
        "sub": "agent-demo-1", "caps": ["fs.read"], "ttl_seconds": 300,
    }).json()
    token, jti, exp = resp["token"], resp["jti"], resp["exp"]

    # 2) normal run — allow + policy-deny
    print("--- normal run ---")
    for r in run_scripted(pep, token):
        print(r)

    # 3) operator revokes mid-run
    print("\n--- revoke() ---")
    print(httpx.post(f"{CONTROL_PLANE}/revoke", json={"jti": jti, "exp": exp}).json())

    # 4) next call fails at the PEP, before OPA
    print("\n--- post-revocation ---")
    print(pep.authorize(token, "read_file", {"path": "/tmp/hello.txt"}))

    # 5) expired token
    print("\n--- expired token ---")
    expired = tokens.mint("agent-demo-1", ["fs.read"], ttl_seconds=-1)
    print(pep.authorize(expired, "read_file", {"path": "/tmp/hello.txt"}))

    # 6) forged token
    print("\n--- forged token ---")
    forged = _forge_token("agent-demo-1", ["fs.read"])
    print(pep.authorize(forged, "read_file", {"path": "/tmp/hello.txt"}))

    # 7) audit chain integrity
    print(f"\naudit chain valid: {pep.audit.verify('audit.jsonl')}")


if __name__ == "__main__":
    main()