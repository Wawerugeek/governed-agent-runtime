import hashlib, json
from pydantic import BaseModel
from control_plane.policy.engine import PolicyEngine
from control_plane.audit.log import AuditLog
from control_plane.tools.registry import registry

class PEPDecision(BaseModel):
    allowed: bool
    reason: str
    receipt: dict

class PEPClient:
    """The architectural centerpiece. No agent has ambient tool authority.
    Every tool call goes through authorize() BEFORE execution. Denials are audited too."""

    def __init__(self, engine: PolicyEngine, audit: AuditLog) -> None:
        self.engine = engine
        self.audit = audit

    def authorize(self, agent: dict, tool_name: str, args: dict) -> PEPDecision:
        tool = registry.get(tool_name)
        if tool is None:
            receipt = self.audit.append({
                "decision": "denied", "reason": "unknown_tool",
                "tool": tool_name, "agent_id": agent["id"],
            })
            return PEPDecision(allowed=False, reason="unknown_tool", receipt=receipt)

        decision = self.engine.evaluate(agent, tool.model_dump(), args)
        receipt = self.audit.append({
            "decision": "allowed" if decision.allow else "denied",
            "reason": decision.reason,
            "tool": tool_name,
            "agent_id": agent["id"],
            "args_digest": hashlib.sha256(
                json.dumps(args, sort_keys=True).encode()
            ).hexdigest(),
        })
        return PEPDecision(allowed=decision.allow, reason=decision.reason, receipt=receipt)
