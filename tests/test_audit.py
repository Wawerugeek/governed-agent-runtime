import json, os, base64
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from control_plane.audit.log import AuditLog

@pytest.fixture(autouse=True)
def _key(monkeypatch):
    seed = os.urandom(32)
    monkeypatch.setenv("AUDIT_PRIVATE_KEY", base64.b64encode(seed).decode())

def test_chain_grows_and_verifies(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    log = AuditLog(p)
    r0 = log.append({"event": "a"})
    r1 = log.append({"event": "b"})
    assert r0["seq"] == 0 and r0["prev_hash"] == "0" * 64
    assert r1["seq"] == 1 and r1["prev_hash"] == r0["hash"]
    assert log.verify(p) is True

def test_tamper_detected(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    log = AuditLog(p)
    log.append({"event": "a"})
    log.append({"event": "b"})
    lines = open(p).readlines()
    rec = json.loads(lines[0]); rec["payload"]["event"] = "TAMPERED"
    lines[0] = json.dumps(rec) + "\n"
    open(p, "w").writelines(lines)
    assert log.verify(p) is False

def test_missing_record_detected(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    log = AuditLog(p)
    for i in range(3):
        log.append({"i": i})
    lines = open(p).readlines()
    open(p, "w").writelines([lines[0], lines[2]])  # drop middle
    assert log.verify(p) is False
