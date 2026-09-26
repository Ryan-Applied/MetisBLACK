# E04-S03: Receipt-backed read-only OpenAPI response-contract validation

## Outcome

Turn explicitly selected OpenAPI v2/v3 declarations from a verified discovery
artifact into bounded, active, independently replayable response-contract checks.
The first slice is intentionally limited to unauthenticated `GET`, `HEAD` and
`OPTIONS` operations with concrete same-plan-origin URLs. It must not route
through the generic HTTP action or imply exploitability from ordinary API drift.

## Acceptance criteria

- A strict versioned validation plan selects exact discovered operations and binds
  the canonical discovery-plan hash. Unknown fields, duplicate selectors,
  unsupported versions and every hard ceiling fail closed.
- The validator reconstructs the selected OpenAPI source from its sealed discovery
  receipt, verifies receipt/content/body lineage, and derives a canonical contract
  hash. Operator-authored response expectations cannot replace the received spec.
- OpenAPI v2/v3 JSON and YAML normalize into the same deterministic response
  contract. Only finite local references and a documented structural schema subset
  are executable; remote, cyclic, ambiguous-server and unsupported constructs are
  explicit omissions or inconclusive coverage.
- Only concrete `GET`, `HEAD` and `OPTIONS` operations are eligible. Unresolved path
  parameters, server variables, mutating methods, authentication requirements and
  secret-bearing request values are not silently weakened into executable probes.
- A dedicated typed action enforces the engagement scope and exact plan origins,
  checked and pinned DNS, disabled environment proxies, no redirects, one request,
  finite response and structural-shape ceilings, and ordinary authorization,
  request, rate, concurrency and timeout controls. `DataSampling` may raise
  defaults only within hard ceilings; all operational bypasses remain explicit and
  audited.
- Actions, durable pre-send intents and receipts remain secret-free. Observations
  contain a raw-body hash and a bounded value-free JSON shape, never API values,
  cookies, authorization headers or response credentials.
- Pending I/O without an exact actor/action-bound sealed receipt becomes an
  indeterminate result and is never repeated automatically. Explicit failed-stage
  retry is one-shot and audited.
- Initial validation and independent replay use separate receipts. A narrow
  response-contract violation is confirmable only when complete, non-truncated
  observations repeat the same exact status/media/structural violation against the
  same verified contract. Transport, policy, timeout, cancellation, malformed or
  truncated data, unsupported schema, rate limiting, gateway errors and missing
  declarations are inconclusive.
- A conforming response produces neutral coverage, not a finding. A confirmed
  violation proves repeated response/declaration inconsistency only; it does not
  prove authorization bypass, injection, data exposure or business impact and
  creates no exploit-chain fact.
- Retest uses a fresh request and preserves present/fixed/inconclusive semantics.
  Reporting exposes spec, contract, initial and replay lineage plus omissions and
  override provenance without persisting response values.
- Deterministic fixtures cover strict contracts, JSON/YAML parity, local-reference
  limits and cycles, exact selection and URL materialization, every cap, policy
  denial and override isolation, redirects, invalid/truncated bodies, timeout and
  cancellation, receipt/plan/contract tamper, crash recovery, explicit retry,
  replay, retest and report serialization. An opt-in owned live lab is still
  required before real framework interoperability is claimed.

## Global parity gates

The controls, evidence, replay, redaction, cleanup, reporting, verification and
truthful-capability gates in `docs/parity-roadmap.md` apply. Authenticated API
roles, authorization differentials, GraphQL execution and state-changing CRUD
validation require later stories with credential isolation and verified cleanup.

## Verification record

Status: in progress.

Local acceptance passed on 2026-09-27 with stable Rust 1.94 on macOS arm64:

```text
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets --all-features
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
```

The all-feature workspace suite passed 271 tests with no failures or ignored tests.
The scoped contract, runtime, policy, orchestration, retest and reporting fixtures
include hostile tamper, crash-recovery, retry, truncation, cancellation, proxy,
redirect and unsupported-contract cases. Final-head CI on the declared Rust 1.88
matrix and dependency-policy job is still required before this story is marked
done.
