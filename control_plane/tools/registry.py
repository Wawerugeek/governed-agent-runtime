from enum import Enum
from pydantic import BaseModel, Field

class RiskTier(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

class ToolSpec(BaseModel):
    name: str
    description: str
    risk_tier: RiskTier
    capability: str  # the capability claim required to call this tool

class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}
    def register(self, spec: ToolSpec) -> None:
        self._tools[spec.name] = spec
    def get(self, name: str) -> ToolSpec | None:
        return self._tools.get(name)
    def all(self) -> list[ToolSpec]:
        return list(self._tools.values())

registry = ToolRegistry()
registry.register(ToolSpec(
    name="read_file",
    description="Read a file within the sandbox",
    risk_tier=RiskTier.LOW,
    capability="fs.read",
))
registry.register(ToolSpec(
    name="send_email",
    description="Send an email",
    risk_tier=RiskTier.HIGH,
    capability="email.send",
))
