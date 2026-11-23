package agent.tool_access

default allow := false
default reason := "unknown"

# --- helper rules -----------------------------------------------------
# These don't produce values; they succeed or fail.
# They exist so the main rules read like English.

high_risk if {
    input.tool.risk_tier == "high"
}

has_capability if {
    input.agent.capabilities[_] == input.tool.capability
}

# --- allow ------------------------------------------------------------
# Allow only when: (1) the agent has the required capability, and
# (2) the tool is NOT high-risk.
# High-risk tools are never auto-allowed, even with the capability —
# they always require human approval (v0.4 adds the approval path).

allow if {
    has_capability
    not high_risk
}

# --- reason -----------------------------------------------------------
# Exactly one of these three must fire. They partition the four
# (high_risk, has_capability) combinations with no overlap.

reason := "high_risk_requires_hitl" if {
    high_risk
}

reason := "capability_missing" if {
    not high_risk
    not has_capability
}

reason := "ok" if {
    not high_risk
    has_capability
}
