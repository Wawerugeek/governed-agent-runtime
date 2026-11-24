from fastapi.testclient import TestClient

from control_plane.api.app import app

client = TestClient(app)


def test_health():
    assert client.get("/health").json() == {"status": "ok"}


def test_issue_and_revoke(monkeypatch):
    import os, base64
    monkeypatch.setenv(
        "CONTROL_PLANE_PRIVATE_KEY",
        base64.b64encode(os.urandom(32)).decode(),
    )
    r = client.post("/token", json={"sub": "a1", "caps": ["fs.read"], "ttl_seconds": 60})
    body = r.json()
    assert {"token", "jti", "exp"} <= body.keys()

    assert client.get(f"/revoked/{body['jti']}").json()["revoked"] is False
    client.post("/revoke", json={"jti": body["jti"], "exp": body["exp"]})
    assert client.get(f"/revoked/{body['jti']}").json()["revoked"] is True
