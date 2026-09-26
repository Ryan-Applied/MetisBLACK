# MetisBLACK

MetisBLACK is a from-scratch Rust successor to the legacy NeuroSploit platform for authorized,
evidence-backed security assessment. A model may propose typed actions and
findings, but the harness owns scope enforcement, live I/O, receipts, replay,
finding state, checkpoints, and reports.

This is an early `0.1.0` implementation, not yet a production-ready penetration
testing suite. It now includes a deterministic assessment core, staged provider
swarm, W3C WebDriver automation, identity-verified AWS/Azure/GCP CLI workflows,
heterogeneous model validation, and a typed exploit-chain DAG engine. Read the
[implementation status](docs/implementation-status.md) before relying on a mode
or result.

> Only assess systems you own or are explicitly authorized to test. `--authorize`
> gates every active egress operation: target-facing tools, remote model-provider
> calls, and integration publication. It records operator intent; it is not proof
> that authorization exists. Expert overrides can remove safeguards and can expose
> secrets or execute unsandboxed processes with the operator's privileges.

## What makes it different

The important boundary is the runtime, not the prompt:

```text
CLI / REPL / TUI
       |
       v
orchestrator ---> provider adapters / staged playbook swarm / model panel
       |          browser runtime / cloud runtime / typed chain engine
       |
       v
typed action -> central policy -> tool runtime -> immutable receipt
                                      |
                                      v
candidate -> independent replay -> finding state -> reports / CI gate
```

- Every supported live observation crosses a typed tool boundary.
- Scope, DNS results, redirects, paths, ports, budgets, and filesystem roots are
  checked by code.
- Receipts contain the executed action, output, actor, run provenance, content
  hash, and active override provenance.
- Model prose cannot create a receipt or assign a finding state.
- A configured provider runs through mode-selected recon, specialist, and
  independent reviewer stages. Specialists in a stage can run concurrently, but
  all of their actions still cross the same policy/runtime boundary.
- `Confirmed` means the narrow proof predicate passed an independent harness
  replay. An operator acceptance is represented separately and must not be
  interpreted as empirical confirmation.
- Runs checkpoint to private, atomic JSON artifacts and can be inspected or
  resumed.

The workspace is split into small crates for domain contracts, policy, evidence,
tool execution, providers, source analysis, planning, orchestration, storage,
reporting, integrations, browser and cloud execution, model validation, typed
chains, the playbook library, and the application. See
[architecture](docs/architecture.md) for the dependency direction.

## Build and verify

Requirements:

- Rust 1.88 or newer
- Git for PR-mode snapshots
- network access during the first dependency download

From this directory:

```bash
cargo build --locked --workspace
cargo test --locked --workspace --all-features
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo run --locked -p metisblack-app -- --help
```

Run the fully local HTTP fixture first. It does not contact a public target:

```bash
cargo run --locked -p metisblack-app -- demo --output ./runs/demo
```

The command writes a run manifest, content-addressed receipts, Markdown, HTML,
JSON, and SARIF reports under `./runs/demo`.

## Quick start

The deterministic paths do not require a model provider.

```bash
# Source/configuration review
cargo run --locked -p metisblack-app -- \
  whitebox ./path/to/source --output ./runs/source-review

# Authorized HTTP review
cargo run --locked -p metisblack-app -- \
  run https://app.example.test --authorize --output ./runs/http-review

# Explicit TCP exposure inventory
cargo run --locked -p metisblack-app -- \
  host 192.0.2.10 --ports 22,80,443 --authorize --output ./runs/host-review

# Merge-base-aware review of a local Git commit
cargo run --locked -p metisblack-app -- \
  pr ./path/to/repository --base origin/main --head HEAD \
  --output ./runs/pr-review --fail-on high

# Authorized browser observation through a local WebDriver
cargo run --locked -p metisblack-app -- \
  browser https://app.example.test --webdriver http://127.0.0.1:9515 \
  --authorize --output ./runs/browser-review

# Identity-verified live cloud inventory from a strict JSON plan
cargo run --locked -p metisblack-app -- \
  cloud-live ./cloud-plan.json --authorize --output ./runs/cloud-review
```

Use `--dry-run` to inspect a generated configuration without starting the run,
and `--json` for machine-readable command summaries. Global options may be placed
before or after the subcommand.

### Add a model provider

Provider credentials are read from the named environment variable. Do not put a
credential value in an argument or configuration file.

```bash
export NS_OPENAI_KEY='replace-in-your-shell-or-secret-store'
cargo run --locked -p metisblack-app -- \
  run https://app.example.test --authorize \
  --provider openai --model '<supported-model-id>' \
  --key-env NS_OPENAI_KEY --output ./runs/provider-review
```

Native envelopes exist for OpenAI/OpenAI-compatible, Anthropic, Gemini, Ollama,
and llama.cpp-style endpoints. Heterogeneous panels can be added with
`--model-panel`, and typed chain execution with `--chains`. Streaming and native
provider cost telemetry remain unavailable. Local HTTP provider endpoints are
accepted only on loopback by default. See the
[live runtime workflow guide](docs/live-runtime-workflows.md).

## Commands

The application exposes black-box (`run`), WebDriver (`browser`), `whitebox`,
`greybox`, `host`, cloud snapshot (`cloud`), live provider CLI (`cloud-live`), AI
endpoint (`aitest`), `skills`, local Git `pr`, `retest`, `accept`,
expert typed `tool`, `resume`, `inspect`, `demo`, `tui`, provider capability
(`models`), control inventory (`controls`), playbook (`agents`), and explicit
publication (`integrations`) commands. A command name only means the bounded
implementation described in the [mode matrix](docs/implementation-status.md); it
is not a claim of broad technique coverage.

Run `metisblack --help` and `metisblack <command> --help` for the authoritative
CLI syntax.

## Finding and evidence semantics

- A candidate is an unconfirmed claim.
- A reproducible supported predicate is replayed as a separate action and receipt.
- `confirmed` and `retested_present` are empirical harness outcomes.
- `needs_review` includes unsupported/manual predicates, insufficient evidence,
  and failed replay.
- `operator_accepted` is an explicit expert decision, not a replay outcome.
- `rejected` identifies invalid or contradicted candidates.
- `retested_fixed` means a supported proof no longer held on retest.

CI should normally gate only empirical states. If an operator-accepted result is
included in a local policy decision, surface that choice explicitly in the job
output. Reports preserve receipt links, limitations, and override provenance.

## Expert overrides

Every safety control has a named override and `--unsafe-all` disables all of them.
Overrides are never implicit: an active override requires an actor, a meaningful
reason, and acknowledgement. They are printed before execution and recorded in
run and receipt provenance.

```bash
cargo run --locked -p metisblack-app -- \
  run https://lab.example.test --authorize \
  --override rate-limit,request-budget \
  --override-actor "$USER" \
  --override-reason "isolated lab load-test window" \
  --acknowledge-unsafe
```

`--unsafe-all` is an emergency expert escape hatch, not a convenience flag. It
also disables the application's `--authorize` gate for target tools, remote model
providers, and integration publication, but it does not create legal
authorization, credentials, network reachability, software, or OS privileges and
does not turn an operator decision into empirical evidence. Read the complete
[expert override reference](docs/expert-overrides.md) before using it.

## Run artifacts

Depending on the mode, a run directory can contain:

- `run-manifest.json` (including override history), `world-model.json`, `usage.json`, and
  `execution-plan.json`
- `receipts/*.json` and `receipts-manifest.json`
- `findings.json`, `report.json`, `report.md`, `report.html`, and `report.sarif`
- `source-inventory.json`, `diff-context.json`, and an exported PR source snapshot
- `source-flow-analysis.json` with bounded lexical paths and explicit limitations
- provider-step records and account-cleanup state
- `browser-plan-result.json` or `browser-authenticated-workflow-result.json`, private browser artifacts, and common browser receipts
- `cloud-live-result.json`, `cloud-iam-graph.json`, verified identity/command audits, and common cloud receipts
- `model-panel.json` with consensus, dissent, failures, and per-member budgets
- `chains/*-checkpoint.json`, attack graphs, and disabled-template reasons

Run directories and vault material contain sensitive assessment data. They are
created with restrictive Unix permissions, but retention, backup, and deletion
remain operator responsibilities. Redaction is best effort unless deliberately
disabled by an expert override.

## CI and repository layout

The workflows under `.github/workflows` run formatting, compilation, tests,
Clippy, and `cargo-deny` for this directory when it is the repository root. GitHub
does not discover nested workflows in the current parent repository; move this
directory to its own repository or copy the workflows to the outer root when the
rebuild is adopted. This rebuild does not alter the parent repository's existing
workflow.

Further reading: [product requirements](docs/product-requirements.md),
[threat model](docs/threat-model.md), [migration](docs/migration.md), and the
[architecture decisions](docs/adr/).
