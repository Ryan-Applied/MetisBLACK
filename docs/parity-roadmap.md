# MetisBLACK production-parity roadmap

This is the authoritative delivery map for the NeuroSploit parity goal. Legacy
marketing text and imported playbooks are inputs, not evidence of completion.
The current bounded capability descriptions in `implementation-status.md` remain
authoritative until a story satisfies every gate below and updates that document.

## Definition of parity

A capability is complete only when all applicable gates pass:

1. Strict, versioned input/output contracts and truthful capability negotiation.
2. Central scope, authorization, risk, rate, concurrency, timeout, state-change,
   account, filesystem, sampling, secret and cost controls.
3. A granular, explicit, actor/reason/acknowledgement-bound override for every
   operational restriction, plus `unsafe_all`; schema, integrity and truthful
   finding-state invariants are never bypassed.
4. Immutable action and observation receipts with hashes, provenance and redaction.
5. Independent deterministic replay before empirical confirmation.
6. Cleanup, rollback or quarantine for created state and failed sessions.
7. Checkpoint/resume, reporting, retest and machine-readable integration support.
8. Deterministic fixtures covering success, denial, override, timeout, cancellation,
   partial failure, redaction, tamper rejection and restart.
9. An authorized live-lab workflow where mocks cannot prove the external contract.
10. Documentation states the exact boundary and does not imply unsupported breadth.

## Workstreams

| ID | Priority | Workstream | Exit condition | Status |
| --- | --- | --- | --- | --- |
| E01 | P0 | Browser and authenticated web workflows | Isolated multi-role sessions, pre-request enforcement where supported, modern network events, proxying and finding-linked artifacts | In progress |
| E02 | P0 | Source and grey-box analysis | Language-aware syntax, intra/inter-procedural flow, framework routes, dependency reachability and runtime correlation | In progress |
| E03 | P0 | Cloud IAM and validation | Evidence-backed IAM graphs, organization boundaries, typed validation actions, rollback and chain adapters for AWS/Azure/GCP | In progress |
| E04 | P0 | Black-box discovery and web validation | Bounded crawl/API/schema discovery and typed, replayable validation modules for prioritized web vulnerability classes | In progress |
| E05 | P0 | Host, Windows and Active Directory | Protocol-aware discovery, credentialed SSH/WinRM/SMB/LDAP inspection, AD relationships and safe replay | Planned |
| E06 | P0 | AI, MCP and workflow assessment | Multi-turn scenario runner, attacker/judge separation, canaries, tool/RAG/MCP surfaces and reproducible verdicts | Planned |
| E07 | P0 | Attack-chain breadth | Verified primitive registry, evidence-backed dynamic DAGs, loot propagation, typed adapters and cleanup | In progress: E07-S01 now has checkpoint-scoped single-writer execution, durable primary/replay/cleanup intents, exact operation-bound receipt recovery, typed dispatch ambiguity, semantic replay, cleanup preflight and indeterminate quarantine; typed loot, dynamic materialization, full lifecycle retest/reporting and live-lab certification remain |
| E08 | P1 | Provider and swarm platform | Subscription CLIs, provider breadth, streaming, reasoning controls, native cost telemetry, routing and durable workers | In progress: E08-S01 adds audited Claude/Codex subscription transports, explicit autonomous modes, durable pre-spawn intents, exact-receipt recovery and failure-closed panel integration; Gemini/Grok, streaming, durable distributed workers and broader telemetry remain |
| E09 | P1 | SDLC integrations | Remote PR/MR fetch, private clone, reviews, status gates, branch watch, Jira issues and mention automation | Planned |
| E10 | P1 | Operator experience and reports | Natural-language REPL, production TUI, project memory, proxies, targeted retest, PDF/Typst and evidence bundles | In progress: E10-S01 now has strict engagement/stage/coverage/provider contracts plus a durable executable scheduler core: non-reconstructible stage capabilities, stage-scoped dispatch/budgets with audited bypasses, crash-to-indeterminate recovery, exact consumed retry authority, all-terminal cleanup, terminal outcomes, causal lineage and atomic coverage finalization. Adapter composition, frontier convergence, persistent browser/auth propagation, `full --plan`, live feed, coverage renderers/exit semantics, reporting/TUI integration and mixed-runtime fixtures remain |
| E11 | P2 | Runtime and data hardening | OS sandbox, managed keys, evidence retention/deletion, stable configuration migrations and distributed execution | Planned |
| E12 | P2 | Release engineering | Cross-platform CI, live-lab certification, signed artifacts, provenance, SBOMs and dependency automation | In progress: locked Linux/macOS/Windows CI and a verified local optimized build exist; live-lab certification, signing, published provenance/SBOMs and dependency automation remain |

## Ordering and integration rules

- E01-E03 establish reusable typed observations before expanding E04-E07.
- E04-E07 may add causal edges only from receipts accepted by harness validators.
- E08-E10 consume the service layer and cannot create alternate execution paths.
- E11 controls expert processes before general plugin or subscription-CLI expansion.
- E12 signs and publishes only artifacts produced by the complete verification matrix.
- Each story updates `implementation-status.md`, this table, and `sprint-status.yaml`
  only after code review and its scoped verification pass.

E04 has completed three foundation stories: receipt-backed bounded surface
discovery (E04-S01), one observe-only open-redirect validator (E04-S02), and
bounded receipt-derived response-contract validation for explicit anonymous
input-free OpenAPI operations (E04-S03). These stories do not complete the E04 exit
condition:
authenticated discovery and API roles, mutation/cleanup validation, additional
prioritized web vulnerability classes, owned-live-lab certification, and broader
exploit-chain coverage remain future receipt-backed stories.

E08-S01 now provides native Claude Code and Codex subscription transports with
fixed direct argument vectors, bounded input/output/runtime, explicit environment
profiles, executable identity checks and single-use prepared invocations. Safe,
read-only and unrestricted autonomous modes are explicit; unrestricted mode
requires the audited override bundle or `unsafe_all`, and uses only the providers'
exact dangerous flags. Every specialist and panel call is bound to a durable
pre-spawn intent, and ambiguous recovery fails closed instead of repeating a turn.
Native CLI activity is control-plane audit metadata and is never admitted as target
evidence. This does not complete E08 or E11: cross-platform process-tree
containment, an OS sandbox, provider-only egress, managed credential brokerage,
Gemini/Grok subscription adapters, streaming, durable distributed workers, broad
reasoning controls and complete native cost telemetry remain open.

## Current verification baseline

The current locked repository baseline is 363 passing non-ignored local tests.
Two authenticated subscription probes are ignored by the fixture matrix and were
run separately against Claude Code `2.1.283` and Codex CLI `0.147.0`; both passed
in unrestricted mode with their exact dangerous flags. Formatting, all-target and
all-feature checking, strict Clippy and the optimized build pass locally. The local
macOS arm64 `metisblack 0.1.0` artifact has SHA-256
`7f94f8d970c2c9d693f884ea1271bd1abdbe38f2267a9553b87e78678f4c0086`.

GitHub Actions run
[`36283953344`](https://github.com/Ryan-Applied/MetisBLACK/actions/runs/36283953344)
passes E10 scheduler commit `d2b4dec` with the locked Rust 1.88 workspace on Ubuntu,
macOS 14 arm64 and Windows, including strict formatting, checking, tests, Clippy
and dependency policy. This proves the bounded contracts, deterministic fixtures
and tested CLI integrations in this repository; it does not prove production
parity, general external behavior or containment of provider-native agents. The
E04 exit condition, broader E08/E11 work, and E12 live-lab certification, artifact
signing, published provenance/SBOMs and dependency automation remain open.
