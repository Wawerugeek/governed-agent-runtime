# Governed Agent Runtime

## What this is
A control plane that mediates every tool call an agent makes. The LLM/agent has no
ambient tool authority: it proposes, the PEP decides, the audit log records.

## Trust boundaries
1. Agent runtime (untrusted reasoning) → PEP (trusted decision point) → Tool (sandboxed)
2. Agent identity (v0.2: JWT) determines capability claims, never the agent itself.

## Decisions log
- v0.1: scripted agent, static manifest. Why: proves governance layer independently.
- v0.1: OPA for policy. Why: deterministic, external to LLM loop, industry-standard.
- v0.1: Ed25519 hash-chain audit. Why: tamper-evident, verifiable in demo, no DB dependency.