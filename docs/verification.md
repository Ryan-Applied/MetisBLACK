# Local verification record

Verified on 2026-09-27 using stable Rust 1.94 on macOS arm64. The workspace declares
Rust 1.88 as its dependency-compatible minimum, and CI targets 1.88. That older
toolchain was not installed locally, so this record does not claim an actual local
MSRV build or Linux run.

Passed:

```text
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features --locked --offline
cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings
cargo test --workspace --all-features --locked --offline
```

The final suite passed **125 tests**, with no failed or ignored tests. Coverage
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

The documented local demo completed at `runs/verified-demo`: two low-severity
empirically confirmed missing-header observations, linked independent replay
receipts, and Markdown/HTML/JSON/SARIF reports. This directory is ignored by Git.

Legacy migration and validation both passed for 435 playbooks in seven categories.
One incomplete-heading warning was retained for `meta/role_pentestfull`.

Not executed locally: `cargo deny check` (cargo-deny is not installed), remote CI,
live provider authentication, real provider-cloud accounts, a real WebDriver,
authenticated application workflows, or broad real-target exploit reproduction.
The live backends are therefore implementation- and mock-verified, not
environment-certified. See `implementation-status.md` for the precise capability
boundary.

The outer repository's tracked files remain unchanged; its status lists only the
new `MetisBLACK/` directory. The nested CI workflow becomes active when this
directory is published as a repository root, not while it remains nested in the
unchanged original repository.
