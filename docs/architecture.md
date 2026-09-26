# Architecture

Dependencies point downward; no crate may depend on the application.

```text
app → orchestrator → providers, model-panel, browser-runtime, cloud-runtime
                  → chain-engine, tool-runtime, web-discovery, source-analysis, agent-library
                  → world-model, reporting, integrations
chain-engine → tool-runtime, policy, storage, domain
browser-runtime → policy, storage, domain
model-panel → providers, storage, domain
tool-runtime → policy, evidence, storage
web-discovery → storage
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

Web discovery is a pure deterministic breadth-first state machine separated from
network acquisition. The orchestrator supplies each frontier item to the typed
runtime only after persisting a pre-send intent, then advances the state machine
only from a sealed receipt. Restart recovers an exact action-bound receipt; a
pending intent without a receipt becomes an explicit indeterminate failure and is
not repeated. The discovery
fetch action enforces the plan's exact origin boundary in addition to engagement
scope, reads a bounded body, and observes one response without following a
redirect. Plan, checkpoint and final artifact are hash-bound; finalization
reconstructs every transition from receipt content hashes. Parsed HTML, robots,
sitemaps, JavaScript hints and OpenAPI declarations describe observed, declared or
omitted surface only. They do not execute scripts, submit forms, invoke APIs, or
create a finding or causal edge.

Findings hold receipt identifiers and typed proof predicates. Independent replay
is performed by the harness; unsupported predicates remain NeedsReview. Source
claims are symbolic and are never represented as live observations. A Bayesian
belief model selects recon, replay or stop before execution; its decisions are
stored alongside evidence.

The initial web validator is intentionally narrow. An open-redirect action builds
a reserved-domain canary inside the runtime, sends one scoped GET with redirects
disabled, and records the first response as a strict typed observation. The proof
predicate is recomputed by the harness from the bound action/observation and
requires an allowed redirect status plus an exact canary `Location`. Replay and
retest use fresh canaries; transport failures are inconclusive, not proof of a fix.
Open-redirect probes use the same pre-send intent discipline, exact actor/action
receipt binding, failed-stage markers and one-shot explicit retry decisions.
Positive coverage is completed only after its finding is durably persisted.

Immutable, content-addressed JSON records and atomic snapshots are the initial
storage backend. An encrypted local vault stores secrets behind opaque references.
Atomic writes sync file contents before rename and fsync the parent directory on
Unix. Non-Unix builds retain atomic rename and file sync, but power-loss directory
durability is not claimed.
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
