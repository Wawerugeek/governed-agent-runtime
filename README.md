# Governed Agent Runtime

> A control plane that mediates every tool call an AI agent makes. The agent has no ambient authority — it proposes, the policy engine decides, an append-only hash-chained audit log records the decision. Every denial is a signed receipt.

[![status](https://img.shields.io/badge/status-v0.1%20shipped-brightgreen)]()
[![tests](https://img.shields.io/badge/tests-3%20passing-brightgreen)]()
[![python](https://img.shields.io/badge/python-3.11%2B-blue)]()
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

<!-- replace with a 10s screen recording once v0.1 lands -->
<!-- ![demo](docs/demo.gif) -->

---

## Why this exists

Most agent frameworks assume the agent is trustworthy. In production, it is not. An LLM can be prompt-injected, hallucinate a tool name, or call `send_email` when it was only authorized to read a file. Governance cannot live inside the prompt — the model can be talked out of it. It has to live in a deterministic layer the model cannot reach.

This project is that layer.

**Trust boundary:**

```
┌──────────────────┐      authorize()      ┌──────────────┐    allow/deny    ┌────────┐
│  Agent runtime   │ ────────────────────▶ │     PEP      │ ───────────────▶ │  Tool  │
│  (untrusted LLM) │ ◀──────────────────── │ (trusted)    │                  │ (exec) │
└──────────────────┘   decision + receipt  └──────┬───────┘                  └────────┘
                                                  │
                                          ┌───────▼────────┐
                                          │  OPA policies  │
                                          └───────┬────────┘
                                                  │
                                          ┌───────▼────────┐
                                          │  Audit log     │
                                          │  Ed25519 chain │
                                          └────────────────┘
```

The agent proposes. The **Policy Enforcement Point (PEP)** authorizes against declarative OPA/Rego policy. An **Ed25519-signed hash-chained audit log** records both allow and deny decisions, so the record is tamper-evident and independently verifiable.

---

## Status

**v0.1 shipped** — governance loop is working end-to-end. See [Releases](#releases).

| Component | State | Notes |
|---|---|---|
| Tool registry with risk tiers | ✅ v0.1 | LOW / MEDIUM / HIGH |
| OPA policy engine (external to LLM) | ✅ v0.1 | Rego; restart to reload (see note) |
| Policy Enforcement Point (PEP) | ✅ v0.1 | Every tool call goes through it |
| Ed25519 hash-chained audit log | ✅ v0.1 | `verify()` detects mutation + deletion |
| Short-lived scoped JWT per agent | 🚧 v0.2 | Capability claims, `exp`, `jti` |
| Live token revocation | 🚧 v0.2 | Kills agent authority mid-run |
| Ollama-backed LangGraph agent | 🚧 v0.2 | `qwen2.5`, OpenAI-compatible |
| OpenTelemetry tracing (Jaeger) | 🚧 v0.3 | Reasoning → policy → tool spans |
| Live dashboard | 🚧 v0.4 | Streamlit → React |
| Prompt-injection guardrail demo | 🚧 v0.4 | Safe-fallback routing |
| Health checks, retries, CI | 🚧 v1.1 | GitHub Actions |

> **OPA reload note:** the container mounts `policies/` read-only. OPA does not
> watch for changes — run `docker compose restart opa` after editing Rego.
> The alternative (`--watch` flag + writable mount) is deferred to v1.1.


## Releases

### v0.1 — Governance loop *(current)*
- Tool registry, OPA policy (three-branch: allow / high-risk / missing-capability)
- PEP mediates every tool call; allow **and** deny both audited
- Ed25519 hash-chained audit log; `verify()` detects payload mutation and dropped records
- Scripted agent exercises authorized + blocked paths end-to-end
- **Proven:** 3 tests passing, tamper demo returns `False`

## Quickstart

```bash
git clone https://github.com/wawerugeek/governed-agent-runtime.git
cd governed-agent-runtime

python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# one-time: generate the audit signing key
export AUDIT_PRIVATE_KEY=$(python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())")

# start OPA (policy engine)
docker compose up -d opa

# run tests + the demo
pytest tests/ -x
python -m demo.scenario
```

Expected output:

```
('read_file', True, 'ok', 'b1e...')
('read_file_result', True, 'hello from governed agent', None)
('send_email', False, 'high_risk_requires_hitl', 'a3f...')
('read_file', True, 'ok', 'c92...')

audit chain valid: True
```

Now tamper with `audit.jsonl` — change one byte in any payload — and re-run `pep.audit.verify('audit.jsonl')`. It returns `False`. That's the point.

---

## Design decisions

| Decision | Rationale |
|---|---|
| **Governance outside the LLM loop** | Prompt-based guardrails can be jailbroken. A deterministic PEP cannot. |
| **OPA/Rego, not Python if-statements** | Policy is data, not code. Auditable, testable, hot-reloadable, and evolves without redeploying the agent. |
| **Hash-chained + Ed25519 signatures** | Tamper-evident without a database. Any third party can independently verify the log. |
| **Scripted agent in v0.1, LLM in v0.2** | Prove the governance layer against a deterministic agent first. Adding a nondeterministic LLM later is then a controlled change. |
| **Short-lived JWTs (v0.2)** | Identity is verified, not asserted. Revocation is a lookup, not a redeploy. |
| **Docker isolation (v0.1), microVM upgrade path (v1.x)** | Proportional isolation for a portfolio-grade demo; microVM boundary is documented as the production upgrade. |

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the full component view and [`THREAT_MODEL.md`](THREAT_MODEL.md) *(v1.0)* for the OWASP Agentic Top 10 mapping.

---

## Roadmap

- **v0.1** — Governance loop: registry, PEP, OPA, hash-chained audit *(current)*
- **v0.2** — Identity: short-lived JWTs, capability claims, live revocation
- **v0.3** — Observability: OTel traces in Jaeger
- **v0.4** — Dashboard + prompt-injection safe-fallback demo
- **v1.0** — Documentation, threat model, 3-min recording, public release
- **v1.1** — Production close: health checks, retries, structured logs, GitHub Actions CI

Out of scope (documented, not planned): multi-tenant RBAC, HA deployment, Kubernetes manifests. This is a portfolio-grade reference architecture, not a vendor product.

---

## Stack

Python 3.11 · FastAPI · OPA/Rego · LangGraph *(v0.2)* · Ollama `qwen2.5` *(v0.2)* · OpenTelemetry + Jaeger *(v0.3)* · Streamlit *(v0.4)* · Docker Compose · Ed25519 (`cryptography`)

---

## License

MIT — see [LICENSE](LICENSE).