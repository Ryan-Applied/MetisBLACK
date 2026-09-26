# Local verification record

Verified on 2026-09-27 using stable Rust 1.94 on macOS arm64. The workspace declares
Rust 1.88 as its dependency-compatible minimum, and CI targets 1.88. That older
toolchain was not installed locally, so this record does not claim an actual local
MSRV build or Linux run.

Passed:

```text
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets --all-features
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
```

The current locked suite passed **331 non-ignored tests**, with no failures. Two
authenticated subscription-CLI probes are deliberately ignored by the fixture
matrix and were run separately. Coverage
includes the exhaustive 32-control registry (default enforcement, exact override,
unrelated-control isolation and unsafe-all), native provider HTTP tool calling,
real tool receipts, independent replay, recon/specialist/reviewer/refuter scheduling,
typed account budgets and vault storage, pause/resume, retest persistence, AI POSTs,
greybox links, multiple source targets, cloud identity, nested Git PR export and
introduced-line classification, source manifests, reporting, CLI acknowledgement,
and audited duplicate-safe integration publication. The added runtime suites
cover mock W3C session/form/storage/screenshot/log workflows, scope-escape
quarantine, plan replay and cancellation; direct-argv AWS/Azure/GCP identity and
read-only workflows; heterogeneous model quorum/dissent/budget/fabrication
handling; and typed chain policy, replay, branching, rollback, resume, and an
orchestrator-to-local-fixture chain. Follow-up regressions cover
failed/timeout account-secret invalidation and cleanup audit, specialist audit
preservation across resume, per-operation authorization (including source-mode
provider and integration egress), replacement-override authorization, coherent
report/history regeneration, malformed-path invariants, meaningful paired-control
isolation and saved-action banners. Network fixtures use loopback
only; no public assessment target or real provider credential was used.

The first production-parity tranche adds isolated authenticated multi-role browser
sessions with role-local secret bindings and neutral comparison hashes; conservative
language-aware lexical source flows that remain review-only; and deterministic,
cycle-safe AWS/Azure/GCP IAM reachability whose traversable edges require common
receipt lineage. Orchestrator tests cover source-flow state semantics and IAM artifact
lineage, and the shipped browser-workflow example is schema-tested.

The E04 foundation adds strict deterministic web-discovery contracts, all finite
cap fixtures, no-redirect one-response acquisition, durable pre-send intents,
missing/pending receipt recovery, canonical run paths, secret-seed policy, and
mid-frontier pause/cancel resume. The open-redirect validator has typed exact
observations, fresh-canary replay/retest, exact intent receipt binding, positive
finding crash recovery, and explicit failed-stage one-shot retry. These paths use
owned loopback fixtures only and do not claim broad web exploitation coverage.

The E04-S03 local acceptance adds receipt-derived OpenAPI v2/v3 JSON/YAML response
contracts for explicitly selected anonymous input-free `GET`, `HEAD` and `OPTIONS`
operations. It covers strict selection and URL materialization, local-reference and
schema ceilings, pinned-DNS/no-proxy/no-redirect acquisition, value-free response
shapes, durable primary/replay/retest intents, exact receipt recovery, tamper
rejection, explicit one-shot retry, exact status/media/violation replay, and
normal-report lineage and omission records. These tests use owned loopback fixtures;
they do not certify interoperability with a public API or real framework.

The E08-S01 provider-runtime acceptance adds fixed direct-argv Claude Code and
Codex subscription transports, bounded machine-output parsing, environment and
credential isolation, executable/version/hash binding, exact dangerous-flag
gating, durable invocation intents, no-repeat ambiguous recovery and exclusion of
native agent activity from target evidence. The two opt-in authenticated probes
passed against Claude Code `2.1.283` and Codex CLI `0.147.0` in unrestricted mode;
their canonical executable targets and hashes are recorded in the E08 story.

The E07-S01 chain-safety tranche adds checkpoint-scoped single-writer execution,
durable primary/replay/cleanup intents, exact current-run/actor/action/operation
receipt binding, typed not-dispatched versus outcome-unknown adapter failures,
semantic replay predicates, cleanup policy/capability/risk/state preflight,
cancellation-safe scheduling and quarantine recovery without repeated adapter I/O.
Twenty-nine chain-engine fixtures cover the new failure boundaries. This is the
safe execution substrate; typed loot, dynamic materialization, complete lifecycle
retest/reporting and live-lab interoperability remain open.

The documented local demo completed at `runs/verified-demo`: two low-severity
empirically confirmed missing-header observations, linked independent replay
receipts, and Markdown/HTML/JSON/SARIF reports. This directory is ignored by Git.

Legacy migration and validation both passed for 435 playbooks in seven categories.
One incomplete-heading warning was retained for `meta/role_pentestfull`.

CI defines locked all-feature platform lanes for Ubuntu, macOS 14 arm64 and
Windows in addition to the strict quality and dependency-policy jobs. GitHub
Actions run
[`36277987141`](https://github.com/Ryan-Applied/MetisBLACK/actions/runs/36277987141)
passed all five jobs from final-head commit `6f45b98` using the declared Rust 1.88
MSRV. This includes locked tests on Ubuntu, macOS 14 arm64 and Windows, the strict
format/check/test/Clippy lane, and dependency policy.

Not executed locally: `cargo deny check` (cargo-deny is not installed), live
provider-cloud accounts, a real WebDriver, authenticated application workflows,
or broad real-target exploit reproduction. Except for the two exact subscription
CLI probes above, live backends are therefore implementation- and mock-verified,
not environment-certified. See `implementation-status.md` for the precise
capability boundary.

The outer repository's tracked files remain unchanged. `MetisBLACK/` is published
as its own repository root, where the nested workflow is active.
