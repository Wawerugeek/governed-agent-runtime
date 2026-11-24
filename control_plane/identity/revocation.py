import time


class RevocationStore:
    """In-memory revocation list keyed by jti. Demo-scale only:
    a production deployment uses Redis/etcd so all PEP instances agree.
    The interface (revoke / is_revoked) is what matters."""

    def __init__(self) -> None:
        self._revoked: dict[str, int] = {}  # jti -> exp (unix seconds)

    def revoke(self, jti: str, exp: int) -> None:
        self._revoked[jti] = exp

    def is_revoked(self, jti: str) -> bool:
        self._sweep()
        return jti in self._revoked

    def _sweep(self) -> None:
        # Drop entries whose token would have expired anyway.
        now = int(time.time())
        self._revoked = {j: e for j, e in self._revoked.items() if e > now}

