import os
import json
import hashlib
import base64
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ZERO_HASH = "0" * 64


def _canonical(obj: dict) -> bytes:
    # Single source of truth for serialization. Both append() and verify()
    # MUST hash through this function or their hashes will never match.
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


class AuditLog:
    def __init__(self, path: str) -> None:
        self.path = path
        seed = base64.b64decode(os.environ["AUDIT_PRIVATE_KEY"])
        self._sk = Ed25519PrivateKey.from_private_bytes(seed)
        self._pk = self._sk.public_key()
        open(self.path, "a").close()  # ensure file exists

    def _last_record(self) -> dict | None:
        # Demo-scale: read the file each append. Production would keep a
        # cursor or a small index. Honest note in README, not hidden.
        if not os.path.exists(self.path) or os.path.getsize(self.path) == 0:
            return None
        last_line = None
        with open(self.path, "r") as f:
            for line in f:
                if line.strip():
                    last_line = line
        return json.loads(last_line) if last_line else None

    def append(self, payload: dict) -> dict:
        last = self._last_record()
        seq = 0 if last is None else last["seq"] + 1
        prev_hash = ZERO_HASH if last is None else last["hash"]

        # The dict we HASH excludes "hash" and "signature" — those are the
        # outputs of the hash/sign operations, so they can't be inputs.
        hashable = {
            "seq": seq,
            "ts": datetime.now(timezone.utc).isoformat(),
            "prev_hash": prev_hash,
            "payload": payload,
        }
        hash_hex = hashlib.sha256(_canonical(hashable)).hexdigest()
        signature = base64.b64encode(
            self._sk.sign(bytes.fromhex(hash_hex))
        ).decode()

        # The dict we WRITE to disk has all six fields.
        record = {**hashable, "hash": hash_hex, "signature": signature}
        with open(self.path, "a") as f:
            f.write(json.dumps(record) + "\n")
        return record

    def verify(self, path: str | None = None) -> bool:
        target = path or self.path
        if not os.path.exists(target):
            return True

        prev_hash = ZERO_HASH
        expected_seq = 0

        with open(target, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    return False

                # 1) Structure: seq monotonic, prev_hash points at previous record.
                #    Catches deleted or reordered records.
                if rec.get("seq") != expected_seq:
                    return False
                if rec.get("prev_hash") != prev_hash:
                    return False

                # 2) Integrity: recompute hash over the same four fields,
                #    with the same canonical serialization.
                #    Catches payload mutation.
                hashable = {k: rec[k] for k in ("seq", "ts", "prev_hash", "payload")}
                expected_hash = hashlib.sha256(_canonical(hashable)).hexdigest()
                if expected_hash != rec.get("hash"):
                    return False

                # 3) Authenticity: Ed25519 signature over the hash bytes.
                #    Catches full-history rewrite (would need the private key).
                try:
                    self._pk.verify(
                        base64.b64decode(rec["signature"]),
                        bytes.fromhex(rec["hash"]),
                    )
                except (InvalidSignature, ValueError, KeyError):
                    return False

                prev_hash = rec["hash"]
                expected_seq += 1

        return True
