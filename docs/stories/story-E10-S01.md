# E10-S01: Full engagement scheduler and truthful coverage

## Outcome

Replace the misleading single-mode expectation around `tui` with one strict,
versioned full-engagement plan that can schedule every requested existing runtime
under one authorization, policy, budget, cancellation, evidence and run identity.
The operator must see lifecycle and coverage as separate states: a run may finish
execution while remaining partial, blocked, inconclusive or quarantined.

This story is the integration spine for P0-P2 workstreams. It does not make an
unimplemented validator real, and it must never report an unavailable stage as
passed.

## Acceptance criteria

- Add an independent strict engagement schema without changing the legacy
  `RunConfig` or receipt schema. Typed targets distinguish URLs, hosts, source
  roots, cloud identities and AI endpoints.
- A full plan contains stable stage IDs, typed stage configurations, dependencies,
  required/optional semantics, per-stage ceilings beneath engagement-wide budgets,
  and an always-run reporting finalizer.
- One engagement lock, policy, evidence store/run ID, cancellation token, global
  usage ledger and override epoch are shared across all stages. Independent child
  runs are not used to simulate composition.
- Every stage is persisted before external I/O and has a durable attempt ledger.
  Completed stages verify their exact inputs, artifacts and receipts on resume.
  Failed or indeterminate stages are never repeated without a one-stage,
  one-attempt, spec-hash-bound retry authorization.
- Independent stages continue after a localized failure. Dependents become
  explicitly blocked. Cancellation, missing credentials/capabilities, policy
  denial and outcome ambiguity retain distinct states.
- Web discovery, API validation, browser, source/grey-box, host, cloud, AI,
  provider swarm, model panel, chains, cleanup and reporting run through extracted
  stage adapters rather than alternate CLI execution paths.
- Completion keys are stage-scoped; the same URL cannot cause browser, host or AI
  stages to be skipped after HTTP discovery.
- Coverage records distinguish requested, attempted, completed, partial, blocked,
  skipped, failed, cancelled and indeterminate work. Crawl-cap exhaustion and
  requested provider sessions with no normalized reply reduce coverage.
- Markdown, HTML, JSON, SARIF, CLI and TUI derive from the same coverage manifest.
  Findings never obscure incomplete coverage, and a no-findings partial run never
  implies a clean target.
- `metisblack full --plan ...` previews exact stages/capabilities and exits `3`
  for incomplete required coverage unless `--allow-partial` is explicit. That
  option changes only the exit code, never the manifest.
- Existing single-mode commands remain compatible. `tui` either consumes the same
  full plan or is clearly named and displayed as black-box-only.
- Deterministic fixtures cover mixed-stage success, missing configuration,
  credentials and capabilities, partial crawl, dependency blocking, provider
  zero-work, failure isolation, pause/cancel, exact retry, artifact/receipt tamper,
  global budget enforcement and cross-platform CLI/report rendering.

## Global parity gates

All controls, evidence, replay, redaction, cleanup, reporting, verification and
truthful-capability gates in `docs/parity-roadmap.md` apply. Operational controls
retain explicit audited override paths and `unsafe_all`; schema, receipt integrity,
stage/attempt identity, graph acyclicity, truthful coverage and finding-state
semantics are never bypassed.

## Verification record

Status: in progress.

Implemented in the first slice:

- Independent strict engagement, target, stage, dependency, budget, attempt,
  provider-work, artifact-lineage, coverage and one-attempt retry contracts.
- Central scope ceilings, authorization and explicit audited override binding.
- All-terminal reporting-finalizer semantics and separate lifecycle/coverage
  states, including durable reasons for partial, omitted and indeterminate work.
- Exact requested-provider-session accounting. A normalized reply and immutable
  receipt are required for provider success; zero replies and missing telemetry
  reduce coverage with typed reasons.
- One durable `EngagementEngine` boundary with canonical input-artifact checks,
  configuration fingerprints, a single writer lock, shared policy/evidence/vault/
  cancellation context, target scope preflight and resume-time tamper rejection.
- Root-stage readiness plus a non-reconstructible stage/spec/config-bound
  capability persisted before adapter I/O. Every adapter action is checked
  against the stage kind and typed targets, uses a fixed receipt actor and an
  exact live request/state/account/concurrency ledger. Audited operational
  overrides lift the matching caps without weakening usage accounting.
- Terminal stage outcomes, dependency reconciliation and exact one-attempt retry
  consumption are durable. Resume verifies completed receipt actors/actions and
  output bytes; an interrupted running attempt becomes explicitly indeterminate,
  recovers any sealed attempt receipts and cannot regain live authority.
- Cleanup stages are all-terminal, stateful chains that require cleanup must be
  covered, provider work is deployment-bound, report artifacts exactly match
  requested formats and artifact lineage is restricted to causal dependencies.
- The reporting finalizer atomically seals the canonical coverage manifest and
  transitions the engagement to complete, failed or cancelled. Terminal state,
  coverage and the manifest are revalidated on resume.
- Deterministic domain and engine fixtures cover strict schema, graph/budget/
  authorization failures, provider zero-work, telemetry gaps, exact receipts,
  retry bindings, lock ownership, scope/secret-query preflight, plan/config
  tampering, crash reconciliation, stage budget/tool/target enforcement,
  terminal outcomes and atomic coverage finalization.

Still open: adapter extraction, convergence/frontier scheduling, parallel stage
dispatch/failure isolation, persistent browser/auth artifact propagation, coverage
renderers and exit disposition, `full --plan`, CLI/TUI/live-feed integration and
mixed-runtime fixtures.
