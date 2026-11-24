# Governed Agent Runtime

## What this is
A control plane that mediates every tool call an agent makes. The LLM/agent has no
ambient tool authority: it proposes, the PEP decides, the audit log records.

## Trust boundaries

The agent is untrusted. Tools are the only thing that can affect the world.
Everything between them is a boundary that must be provable.

    ┌──────────────────┐      authorize()      ┌──────────────┐
    │  Agent runtime   │ ────────────────────▶ │     PEP      │
    │  (untrusted)     │ ◀──────────────────── │  (trusted)   │
    └──────────────────┘   decision + receipt  └──────┬───────┘
                                                      │
                                       ┌──────────────┼──────────────┐
                                       ▼                             ▼
                                ┌─────────────┐              ┌──────────────┐
                                │ OPA + Rego  │              │  Audit log   │
                                │ (decision)  │              │ (Ed25519,    │
                                └─────────────┘              │  hash chain) │
                                                             └──────────────┘
                                       │
                                       ▼ (if allowed)
                                ┌─────────────┐
                                │    Tool     │
                                └─────────────┘

1. **Agent → PEP**: the agent has no direct tool access. PEP is the sole path.
2. **PEP → OPA**: policy is evaluated outside the LLM loop; the model cannot
   see, edit, or prompt-inject it.
3. **PEP → Audit**: every decision (allow AND deny) is signed and chained.

## Identity (v0.2a)

The agent never self-asserts capabilities. It presents a **signed JWT**;
the PEP verifies it and constructs the agent context from the *verified
claims*, not from anything the agent sent as text.

    Agent ── token ──▶ PEP ── verify(signature, aud, iss, exp) ──▶ Claims
                         │
                         ├── is_revoked(claims.jti)?  ──▶ deny: token_revoked
                         │
                         └── OPA(claims, tool, args) ──▶ allow | deny

**Why this matters:** in v0.1, `AGENT["capabilities"]` was editable source
code. In v0.2a it is a signed claim the agent cannot mint. Revocation is
a `jti` lookup, so a compromised agent loses authority on its next call.

**Key separation:** `CONTROL_PLANE_PRIVATE_KEY` mints identities;
`AUDIT_PRIVATE_KEY` signs audit records. Different blast radii, different
rotation schedules, never the same key.

**Decision — revocation backend.** JWTs are stateless by design, so
"revoke before expiry" requires shared state. v0.2a uses an in-memory
`RevocationStore` keyed by `jti`. In multi-instance deployments this
becomes Redis/etcd, with a documented propagation delay between
`/revoke` and enforcement. The interface (`revoke` / `is_revoked`) is
backend-agnostic — that is the point.

**Decision — unverified tokens are audited as `agent_id: "unknown"`.**
If the signature fails or the token is expired, we do not trust any claim
inside it, including `sub`. A forged token cannot attribute its attempt
to another agent. Attribution for those cases must come from transport
(mTLS, API gateway logs) — deferred to v1.0.

## Decisions log

- **v0.1: scripted agent, static capability manifest.** Why: proves the
  governance layer independently of LLM nondeterminism. v0.2 introduces a real
  LLM as a *controlled* change — only one new variable.
- **v0.1: OPA/Rego for policy.** Why: deterministic, external to the LLM,
  human-auditable as data, not scattered Python conditionals.
- **v0.1: Ed25519 hash chain, no database.** Why: tamper-evident, independently
  verifiable by a third party, zero infrastructure. Production would use a
  WORM store or append-only ledger; noted as future work.
- **v0.1: `_canonical()` as the single serializer.** Why: hash consistency
  between `append()` and `verify()` is the #1 source of silent audit bugs.
  One function, both callers, no exceptions.
- **v0.1: verify order = structure → hash → signature.** Why: distinguishes
  deletion, mutation, and forgery in incident review. A signature-first order
  masks the others.
- **v0.1: OPA restart to reload, not hot-reload.** Why: `:ro` mount is safer
  than a writable policy directory. `--watch` is a v1.1 convenience, not a
  v0.1 requirement.