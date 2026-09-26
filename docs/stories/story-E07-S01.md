# E07-S01: Receipt-bound dynamic canary-resource chain

## Outcome

Prove one narrow, benign dynamic attack-chain lifecycle: create an authorized
canary resource, derive a typed handle only from its sealed receipt, materialize
and independently replay a verification predicate, delete the resource on every
terminal path, and verify its absence. This story builds the substrate for
receipt-backed dynamic chains; it does not claim code execution, takeover,
lateral movement, credential compromise or broad exploit coverage.

## Acceptance criteria

- A strict, versioned primitive registry binds each operation to an exact input
  schema, capability, impact, semantic validator, cleanup contract and registry
  hash. Stringly typed adapters and arbitrary JSON cannot enter this path.
- Loot is typed, bounded, sensitivity-labelled and bound to its source receipt,
  primitive, extractor and content hashes. Extractors are pure and allowlisted;
  secret material remains an opaque `SecretRef` and is never copied into a chain
  checkpoint, action, report or model prompt.
- Dynamic materialization records bind the template, source receipt, extractor,
  typed loot and resolved-action hashes. The expanded graph is revalidated for
  cycles, dependencies, scope, risk, capability and budgets before enqueue and
  again immediately before execution.
- Request, state-change, loot, fan-out, step, cleanup and risk ceilings are
  centrally enforced. Operational restrictions retain granular audited override
  paths and `unsafe_all`; schema, receipt integrity, graph acyclicity and required
  cleanup are not bypassable.
- A durable intent is persisted before every primary, independent replay and
  cleanup operation. Restart recovers exactly one actor/action-bound sealed
  receipt where possible; a pending intent without one is indeterminate and
  never repeats the operation automatically. Ambiguous receipts fail closed.
- Every accepted receipt is bound to the current run, expected actor, exact typed
  action and operation fingerprint. Cross-run, cross-actor, fabricated, tampered
  and stale receipts are rejected.
- Primary and independent replay must satisfy the same typed semantic predicate;
  transport success alone is insufficient. Replay uses a distinct actor and
  receipt and cannot silently reuse the primary result.
- Cleanup runs in reverse dependency order after success, failure, cancellation
  and recovery. It is centrally policy-checked, idempotent and receipt-backed,
  with bounded retry and explicit quarantined/operator-action-required outcomes.
- Targeted retest uses a fresh canary and repeats the complete create, verify,
  delete and absence-verification lifecycle. Transport or cleanup ambiguity is
  inconclusive and never reported as fixed.
- Markdown, HTML, JSON and SARIF expose claim-to-receipt lineage, materialized and
  traversed edges, redacted loot provenance, replay predicates and cleanup state.
- Deterministic fixtures cover success, denied and overridden controls, rejected
  extractors, derived scope escape, cycle/fan-out/budget rejection, receipt tamper,
  cross-run recovery, replay mismatch, all crash windows and cleanup failures.
  An ignored opt-in test against an explicitly authorized owned lab is required
  before real backend interoperability is claimed.

## Global parity gates

The controls, evidence, replay, redaction, cleanup, reporting, verification and
truthful-capability gates in `docs/parity-roadmap.md` apply. This story is one
benign lifecycle and does not complete E07. Additional typed primitives, chain
families, credential brokerage, host/cloud/browser adapters and live-lab
certification remain separate work.

## Verification record

Status: in progress.

The reusable chain-safety substrate now holds a checkpoint-scoped exclusive lock
across recovery and adapter I/O; persists durable primary, replay and cleanup
intents; binds accepted receipts to the current run, actor, action, intent and
operation fingerprint; distinguishes not-dispatched failures from outcome-unknown
quarantine; applies strict semantic replay predicates; preflights cleanup policy,
capability, risk and state budgets; and prevents cancellation or indeterminate
outcomes from traversing ordinary failure edges. Twenty-nine chain-engine tests,
strict Clippy and the locked workspace gates cover this slice.

The story remains in progress. Typed loot extraction, dynamic materialization,
complete create/verify/delete/absence lifecycle fixtures, targeted retest,
complete report surfaces, authenticated replay-principal separation,
operator-directed ambiguous-state reconciliation and owned-live-lab certification
remain open.
