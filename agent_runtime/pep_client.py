import hashlib
import json
from typing import Callable

import jwt
from pydantic import BaseModel

from control_plane.audit.log import AuditLog
from control_plane.identity.tokens import verify
from control_plane.policy.engine import PolicyEngine
from control_plane.tools.registry import registry


class PEPDecision(BaseModel):
    allowed: bool
    reason: str
    receipt: dict


class PEPClient:
    """The sole path from an agent to a tool. Verifies token → checks
    revocation → consults policy → audits → returns decision."""

    def __init__(
        self,
        engine: PolicyEngine,
        audit: AuditLog,
        is_revoked: Callable[[str], bool] | None = None,
    ) -> None:
        self.engine = engine
        self.audit = audit
        self._is_revoked = is_revoked or (lambda _jti: False)

    def authorize(self, token: str, tool_name: str, args: dict) -> PEPDecision:
        # Step 1: identity. Fail fast on any token problem — before OPA,
        # before the tool, before any state change.
        try:
            claims = verify(token)
        except jwt.ExpiredSignatureError:
            return self._deny("token_expired", tool_name)
        except jwt.InvalidSignatureError:
            return self._deny("invalid_signature", tool_name)
        except jwt.InvalidAudienceError:
            return self._deny("invalid_audience", tool_name)
        except jwt.InvalidIssuerError:
            return self._deny("invalid_issuer", tool_name)
        except jwt.PyJWTError:
            return self._deny("invalid_token", tool_name)

        # Step 2: revocation. A valid-but-revoked token is denied here,
        # never reaching OPA.
        if self._is_revoked(claims.jti):
            return self._deny("token_revoked", tool_name, agent_id=claims.sub, jti=claims.jti)

        # Step 3: policy. Claims from the verified token become the agent
        # context for OPA — the agent cannot self-assert capabilities.
        tool = registry.get(tool_name)
        if tool is None:
            return self._deny("unknown_tool", tool_name, agent_id=claims.sub, jti=claims.jti)

        decision = self.engine.evaluate(
            {"id": claims.sub, "capabilities": claims.caps},
            tool.model_dump(),
            args,
        )

        receipt = self.audit.append({
            "decision": "allowed" if decision.allow else "denied",
            "reason": decision.reason,
            "tool": tool_name,
            "agent_id": claims.sub,
            "jti": claims.jti,
            "args_digest": hashlib.sha256(
                json.dumps(args, sort_keys=True).encode()
            ).hexdigest(),
        })
        return PEPDecision(allowed=decision.allow, reason=decision.reason, receipt=receipt)

    def _deny(
        self,
        reason: str,
        tool_name: str,
        agent_id: str = "unknown",
        jti: str | None = None,
    ) -> PEPDecision:
        payload = {
            "decision": "denied",
            "reason": reason,
            "tool": tool_name,
            "agent_id": agent_id,
        }
        if jti is not None:
            payload["jti"] = jti
        receipt = self.audit.append(payload)
        return PEPDecision(allowed=False, reason=reason, receipt=receipt)