import httpx
from pydantic import BaseModel

class PolicyDecision(BaseModel):
    allow: bool
    reason: str

class PolicyEngine:
    def __init__(self, opa_url: str = "http://localhost:8181") -> None:
        self.opa_url = opa_url
        self._client = httpx.Client(timeout=2.0)

    def evaluate(self, agent: dict, tool: dict, args: dict) -> PolicyDecision:
        payload = {"input": {"agent": agent, "tool": tool, "args": args}}
        r = self._client.post(f"{self.opa_url}/v1/data/agent/tool_access", json=payload)
        r.raise_for_status()
        result = r.json().get("result", {})
        return PolicyDecision(
            allow=result.get("allow", False),
            reason=result.get("reason", "no_reason"),
        )
