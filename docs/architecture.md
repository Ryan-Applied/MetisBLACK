# Architecture

Dependencies point downward; no crate may depend on the application.

```text
app → orchestrator → providers, model-panel, browser-runtime, cloud-runtime
                  → chain-engine, tool-runtime, source-analysis, agent-library
                  → world-model, reporting, integrations
chain-engine → tool-runtime, policy, storage, domain
browser-runtime → policy, storage, domain
model-panel → providers, storage, domain
tool-runtime → policy, evidence, storage
evidence → storage → domain
policy, source-analysis, world-model, agent-library → domain
reporting, integrations → domain, storage
```

The orchestrator owns a persisted engagement state machine and creates the only
common evidence store allowed to produce assessment receipts. The browser and
cloud runtimes emit independently verifiable typed observations which the
orchestrator seals into that store. Provider outputs deserialize into typed
requests or candidates. Tool operations are scoped, budgeted, bounded and
recorded before their output enters model context. Redirects are checked one hop
at a time; DNS answers are checked and pinned to prevent rebinding between check
and use.

Findings hold receipt identifiers and typed proof predicates. Independent replay
is performed by the harness; unsupported predicates remain NeedsReview. Source
claims are symbolic and are never represented as live observations. A Bayesian
belief model selects recon, replay or stop before execution; its decisions are
stored alongside evidence.

Immutable, content-addressed JSON records and atomic snapshots are the initial
storage backend. An encrypted local vault stores secrets behind opaque references.
Output is redacted by default; an explicitly audited secret-redaction override can
persist raw data. The local vault key is stored beside ciphertext under restrictive
permissions: this protects accidental artifact disclosure, not a hostile local
account. Typed account creation generates a password in the runtime and records an
opaque vault reference plus cleanup ledger. UI layers
call the same service; integration publication is an explicit command.

The optional provider loop schedules recon first, bounded concurrent specialists
second, and independent reviewer/refuter contexts against merged evidence third.
Each request reserves shared model step/token budget before egress; runtime tool
limits remain shared across sessions. A finite Bayesian one-step expected-utility
policy chooses recon/assess/reproduce/stop, not a learned long-horizon planner.

An optional heterogeneous model panel creates fresh candidate, reviewer, and
refuter contexts with per-provider budgets. Its receipt allowlist prevents a vote
from manufacturing evidence. Accepted consensus records return to the ordinary
harness validation path. The optional chain engine executes authored typed DAGs
only after receipt-derived facts, runtime capabilities, central scope policy, and
risk/state budgets all pass. Its checkpoints bind the template hash and receipt
integrity; model prose is never converted into a causal edge.

Operator-only expert overrides are propagated through policy, tools, source,
providers, reports and explicit integrations. Audit history is persisted at run
and action level. Unsandboxed shell execution is an explicit exceptional capability,
not a default fallback. Receipt integrity and truthful finding state are invariants:
an explicit acceptance action records operator assurance separately from empirical
replay. See `expert-overrides.md` for the control matrix and dependent gates.
