# Implementation status

This document describes the code in the `0.1.0` rebuild. “Implemented” means a
bounded path exists and is tested; it does not mean broad technique coverage or
production readiness. The legacy NeuroSploit tree is a read-only reference and
is not modified or invoked by this workspace.

## Mode matrix

| Mode / command | Status | Implemented now | Important limitations |
| --- | --- | --- | --- |
| Black-box HTTP / `run` | Bounded implementation | Receipt-backed finite discovery; exact scope/origin checks; receipt reconstruction; narrow open-redirect replay; optional receipt-derived OpenAPI response-contract checks for concrete anonymous input-free GET/HEAD/OPTIONS operations, with value-free response shapes and exact independent replay | No JavaScript execution, session/cookie jar, form submission, authenticated API/crawl, request parameters or bodies, mutations, broad fuzzing/exploit modules, screenshots, websocket, or service-worker coverage. Contract mismatch proves neither authorization failure nor exploit impact |
| Browser / `browser` | Live bounded implementation | W3C WebDriver HTTP sessions; navigation; DOM find/wait/click/clear/fill/submit; cookies; local/session storage; screenshots; console/network logs; optional capability-gated JavaScript; environment-resolved secrets; plan checkpoints; timeout/cancel/budget/scope enforcement; isolated authenticated multi-role workflows with role-local secret bindings and hash-only neutral comparison records; hash-verifiable observations sealed into common receipts | Requires an installed/configured WebDriver. Classic WebDriver cannot guarantee pre-request interception, so subresource scope validation from performance logs is post-hoc; role comparison does not itself assert an authorization flaw; websocket/service-worker completeness and target-specific authentication semantics are not claimed |
| White-box / `whitebox` | Bounded implementation | Deterministic UTF-8 inventory, source hashes/chunks, common manifest/config recognition, conservative dependency extraction, seven line-oriented security signals, exact-line receipts; bounded language-aware lexical intra-file source-to-sink paths for common HTTP sources and SQL/command/file/request/eval sinks, with explicit sanitizer and unknown-hop records | Not a compiler, framework-aware SAST engine, inter-procedural or whole-program verifier, SBOM/vulnerability database, or exploitability proof; lexical paths remain needs-review; files over limits, binaries, secrets, dependencies, and generated/vendor trees can be omitted |
| Grey-box / `greybox` | Bounded correlation | Runs source analysis and the same receipt-backed web discovery/HTTP validation path, extracts up to five simple `.get(...)`/`route(...)` path literals by default, probes in-scope routes, links source and HTTP receipts in `greybox-links.json`, and accepts strict discovery/API-validation plans | No general framework routing model, semantic source/runtime data-flow correlation, authenticated browser/API flow, mutation validation, or causal exploit-chain inference |
| Host / `host` | Inventory only | TCP connect to explicit scoped ports and optional small passive banner read; open-port replay | No UDP, protocol negotiation, OS/service fingerprinting, credential use, host agent, exploit reproduction, or vulnerability mapping |
| Cloud / `cloud` | Snapshot review only | Reviews a local exported snapshot, requires `cloud-identity.json`, checks an explicitly scoped account ID, applies source/config signals | No live AWS/Azure/GCP SDK, IAM graph, multi-account discovery, credential acquisition, control-plane replay, or cloud API receipt |
| Live cloud / `cloud-live` | Live read-only implementation | Direct-argv AWS/Azure/GCP CLI discovery and version checks, identity verification before enumeration, strict secret-environment allowlists, typed account/subscription/project scopes, bounded pagination/output/commands, normalized assets/IAM/finding inputs, command audit and common receipts; a deterministic provider-neutral graph records only receipt-linked IAM relationships and preserves unknown or denied relationships as non-traversable gaps | Requires installed provider CLIs and operator-supplied credentials. IAM adapters are conservative and do not yet resolve exhaustive effective permissions, organizations, or all conditional semantics; mutation requires a separate typed expert capability and is not wired into the default orchestrator; no cross-provider exploit replay |
| AI endpoint / `aitest` | Benign observation probes | Scoped HTTP observation followed by two messages-array POSTs within the mode's default state-change budget: a baseline marker and a benign instruction-boundary probe; receipts are preserved for review | Assumes a compatible endpoint envelope; no broad multi-turn corpus, model-output judge, tool-abuse harness, leakage canary, authenticated conversation, or automatic vulnerability verdict |
| Skills/workflows / `skills` | Static review only | Source/config review, a distinct `skills-audit.json` inventory for instruction/plugin/MCP/n8n surfaces, and mode-specific provider playbooks | Does not execute workflows, import platform state, simulate triggers, or verify SaaS workflow behavior |
| Local Git PR / `pr` | Bounded implementation | Resolves commits, computes merge base, exports the head tree without hooks, records added/modified/deleted/renamed/type-changed files and bounded patches, maps signals to changed lines, records `introduced`, emits SARIF | Local repository only; no GitHub/GitLab API, remote fetch, review comment, working-tree review, build, or test execution |
| Retest / `retest` | Narrow implementation | Replays supported missing-header, insecure-cookie, source-rule, open-port, typed open-redirect and API response-contract predicates; API retest rebuilds the exact sealed contract and requires the original status/media/violation signature for `retested_present` | Manual/provider narratives cannot be automatically retested; no browser or arbitrary exploit replay |
| Operator acceptance / `accept` | Implemented, explicit | Applies a separately acknowledged `confirmation` override to one eligible, receipt-backed finding and records `operator_accepted` | Cannot accept rejected or receipt-less evidence; never produces empirical confirmation and is excluded from default gates |
| Expert typed action / `tool` | Implemented, exceptional | Executes one JSON-encoded `ToolAction` against a saved run with its scope/budgets/overrides; supports HTTP, account, AI, source, DNS, TCP, and override-gated shell actions | Requires a pre-existing run and authorization for active tools; this is not a general plugin API and unsafe shell remains unsandboxed |
| Multi-target | Basic | Sequential target checkpoints with shared budgets and resumable completion tracking | No distributed workers, cross-target causal reasoning, scheduling UI, or fleet coordination |

## Subsystem status

| Area | Status | Notes |
| --- | --- | --- |
| Typed domain contracts | Implemented | Strict Serde schemas, explicit modes/severity/states/proofs, model requests cannot set finding state |
| Central policy | Implemented for current tools | Network, URL, host, port, CIDR, filesystem, sampling, request/state/account budgets, command classes, and expert controls are evaluated in code |
| HTTP runtime | Implemented, bounded | GET plus typed GET/HEAD/OPTIONS/POST/PUT/PATCH/DELETE; state-changing methods consume budgets and generic mutations require overrides; no inherited proxy/cookie jar; checked DNS and redirects |
| Web discovery | Implemented, bounded | Strict versioned plans/checkpoints/artifacts; finite BFS and hard ceilings; exact allowed origins; one-response no-redirect fetches; HTML, form-shape, robots, sitemap, JavaScript-hint and OpenAPI v2/v3 parsing; explicit omissions; durable pre-send intents; exact receipt recovery; receipt-backed independent artifact rebuild | Observation only: no JavaScript execution, form submission, remote OpenAPI references, API invocation, authenticated state, automatic vulnerability claim or chain edge. Local and final-head E04 foundation gates pass |
| API response-contract validation | Implemented, bounded | Strict hash-bound plans; receipt-derived OpenAPI v2/v3 JSON/YAML normalization; reachable local refs; exact anonymous input-free GET/HEAD/OPTIONS selection; one-request pinned-DNS/no-proxy/no-redirect runtime; value-free bounded shapes; durable primary/replay/retest intents; exact status/media/structural replay; retest and lineage/omission reporting | Remote/cyclic/unsupported selected contracts fail closed with an explicit no-coverage record; no credentials, parameters, request bodies, mutations, GraphQL execution, authorization verdict, exploit impact, or attack-chain fact |
| Source runtime | Implemented, bounded | Canonical scoped path, symlink and secret-path checks, UTF-8 line capture with source hash; conservative hash-bound lexical flows preserve typed sources, sinks, sanitizers and unknown hops and are linked to source receipts by orchestration |
| DNS and TCP runtime | Implemented, bounded | Explicit host/port scope; TCP only and no application payload |
| Expert shell | Implemented only through overrides | Unsandboxed child process with captured output. It requires explicit capability/sandbox/network/filesystem overrides plus command-risk permission. See `expert-overrides.md` |
| Evidence store | Implemented | Private create-once JSON receipts, run/actor/action/output provenance, metadata and content hashes, override provenance, manifest verification, and directory-synced create-new publication on Unix |
| Finding confirmation | Implemented for narrow proofs | Independent replay is required for empirical confirmation. Open redirect recomputes exact status/Location semantics; API contract findings require distinct receipts with the same verified contract, status, media type and structural violation. Unsupported narratives stay reviewable; operator acceptance is separate |
| Provider swarm | Implemented, early | Mode- and observation-selected playbooks run in recon, specialist, then meta-review stages; same-stage specialists can run concurrently with fresh contexts and session audit |
| Provider loop | Implemented, early | HTTP envelopes for OpenAI/OpenAI-compatible, Anthropic, Gemini, Ollama and llama.cpp plus deterministic mock; typed calls and token counts. A strict native subscription transport supports installed Claude Code and Codex CLIs through fixed direct argv, bounded stdin/stdout/stderr/events/turns, explicit environment profiles, executable/version/hash audit, and single-use prepared invocations. Every subscription specialist and panel call has a logical run/session/step binding, durable pre-spawn intent and immutable control-plane receipt; recovery consults the intent before probing the CLI, ambiguous pending turns are not repeated, and typed failure audits preserve bounded termination/output provenance | Claude/Codex native activity is lower-assurance audit metadata, never target evidence. Cross-platform process-tree containment, provider-only egress, Gemini/Grok subscription adapters, streaming, broad reasoning controls and complete native cost telemetry remain absent |
| Heterogeneous model panel | Implemented, opt-in | Two-or-more independently identified provider trust domains; fresh candidate/reviewer/refuter contexts; per-member authorization/token/cost/timeout/retry/weight budgets; failure isolation; structured quorum, dissent, audit, receipt allowlisting, optional calibration metadata, and shared HTTP/subscription adapters. Subscription members are single-attempt and expose hashed transport assurance | API and CLI deployments from one vendor are one trust domain. Native CLI audit receipts/events are excluded from the evidence allowlist. Consensus only admits a candidate to harness validation and cannot confirm it |
| Provider operations | Partial | Claude supports `inference_only`, `read_only`, `workspace_write`, and override-gated `unrestricted`; Codex supports the final three and fails closed for `inference_only` because its installed CLI has no verified no-tools mode. Unrestricted injects Claude `--dangerously-skip-permissions` or Codex `--dangerously-bypass-approvals-and-sandbox`; safer modes contain neither flag. Native customizations are suppressed with the exact supported CLI flags by default, provider API keys are excluded even from blanket inheritance, and no CLI call is automatically retried | Provider-owned sandbox flags are capabilities, not MetisBLACK OS-containment proof. Codex project-instruction discovery is CLI-owned and not claimed isolated. No streaming UX, general worker scheduler, Gemini/Grok adapter, full process-tree kill, native cost parity or broad reasoning controls |
| Browser runtime | Implemented, bounded | Typed portable plans and W3C commands, negotiated capability reporting, artifact hashing/private writes, session cleanup/quarantine, plan-prefix replay, redaction, shared central policy receipts; multi-role execution uses isolated sessions, distinct runtime secret bindings, shared cancellation/budgets, failure isolation and neutral evidence hashes | No CDP/BiDi request interception guarantee, automatic IDOR/authz verdict, distributed browser grid management, CAPTCHA solving, or claim of exhaustive browser observability |
| Cloud runtime | Implemented, bounded | Read-only typed AWS STS/IAM/S3/EC2/Lambda/EKS/RDS, Azure account/role/storage/VM/AKS/KeyVault, and GCP auth/project/IAM/storage/compute/GKE/secrets workflows; normalized IAM observations feed a deterministic, cycle-safe reachability graph whose traversable edges require provider evidence and common receipt lineage | Optional/unsupported CLI capabilities are reported rather than fabricated; graph gaps are not paths; exhaustive effective-permission and organization semantics, credential acquisition and arbitrary provider commands remain out of scope |
| World model | Implemented, simple | Bayesian belief update chooses recon/reproduce/assess/stop and persists decisions; not a learned POMDP or sophisticated planner |
| Playbook library | Implemented, bounded | Strict versioned JSON or JSON-frontmatter Markdown; legacy Markdown import preserves methodology as untrusted text; restricted books are not selected by default and require `playbook_selection` override |
| Vault | Implemented for generated test accounts | AES-256-GCM entries and restrictive local key permissions; typed account creation stores only an opaque secret reference in evidence and adds a cleanup record. No external KMS/keychain integration |
| Checkpoint/resume | Implemented | Canonical absolute run paths, atomic snapshots and a single-writer lock; discovery, open-redirect, API primary/replay and subscription-CLI specialist/panel operations use pre-send intents, exact sealed-receipt recovery and explicit indeterminate outcomes. Subscription recovery does not require the CLI to remain available and cannot repeat the main turn for the same logical binding. Completed runs cannot resume; stale lock recovery is manual. Atomic writes and Unix receipt publication fsync their directory; non-Unix power-loss directory durability is not claimed |
| Reports | Implemented | Markdown, offline HTML, JSON, findings JSON, SARIF, execution plan, receipt manifest, cleanup ledger, and sanitized run-decision/artifact references; API coverage decisions expose contract/source/primary/replay lineage and inconclusive reasons without response values |
| TUI / REPL | Basic | TUI shows polling-based progress with pause/cancel; REPL uses whitespace splitting and is not a full shell parser |
| Integrations | Explicit audited summary publication | GitHub issue comment, GitLab merge-request note, and Jira comment payloads; publication requires run authorization or the `authorization` override and uses an operation ID/idempotency key plus local outcome audit. No automatic publication or receipt upload |
| Test account lifecycle | Creation and ledger only | Typed `create_account` generates a vault-backed password, consumes state/account budgets, and records pending cleanup. No generic target-specific login verification or automatic cleanup request |
| Attack chains | Implemented, opt-in and bounded | Validated typed DAGs, receipt prerequisites/dependencies/integrity, capability/scope/risk/state budgets, independent replay, branching/backtracking, deduplication, atomic resume, rollback ledger, attack-graph artifacts, and 18 inert-until-observed templates across web/auth/API/cloud/source/host/AI | Templates are conservative validation chains, not a comprehensive exploit framework. Cloud templates require a registered typed replay adapter and remain disabled in the shared orchestrator today; model prose cannot invent causal edges |

## Finding-state contract

The reporting and gating distinction is intentional:

| State | Meaning |
| --- | --- |
| `hypothesis` / `candidate` | A claim under consideration; not validated |
| `reproduced` | A supported predicate held during replay but has not completed the normal transition |
| `confirmed` | Harness replay independently satisfied the narrow typed proof |
| `needs_review` | Manual/unsupported proof, insufficient evidence or budget, or replay failure |
| `operator_accepted` | An expert explicitly accepted a claim using the confirmation override; no empirical replay is implied |
| `rejected` | Invalid provenance, contradiction, or explicit rejection |
| `retested_present` | A later harness replay still satisfied the typed proof |
| `retested_fixed` | A later successful replay no longer satisfied the typed proof |

Only `confirmed` and `retested_present` should be treated as empirically
confirmed. Reports and machine-readable artifacts include operator acceptance and
override provenance separately. CI consumers must choose deliberately whether an
operator-accepted result affects policy; default `--fail-on` gates exclude it and
`--include-operator-accepted` opts in. It must never be silently collapsed into
empirical confirmation.

## Verification coverage

The workspace includes unit and integration-style local fixture tests for strict
schemas, policy and override gates, DNS/redirect handling, HTTP capture and
redaction, evidence tamper detection, vault encryption/permissions, source and PR
analysis, native provider envelopes, finding replay, resume, reporting, and
integration payloads. It also covers mock W3C browser workflows and quarantine,
mock end-to-end AWS/Azure/GCP workflows, heterogeneous panel quorum/failure
isolation/fabrication rejection, and typed chain execution/replay/resume/rollback.
The E04 test sources add deterministic discovery contracts/parsing and every
finite-cap fixture, exact receipt-based artifact reconstruction, missing/pending
intent recovery, tamper rejection, secret-seed policy, mid-frontier pause/cancel
resume, canonical path coverage, and real-loopback open-redirect crash/retry and
replay/retest fixtures. E04-S03 additionally covers strict receipt-derived OpenAPI
v2/v3 JSON/YAML contracts, bounded value-free probing, durable primary/replay/retest
recovery, exact tamper rejection and report-visible inconclusive coverage. The
current locked local matrix passes 311 non-ignored tests; the two authenticated
subscription probes are deliberately ignored by the fixture matrix and were run
separately against Claude Code `2.1.283` and Codex CLI `0.147.0`, both passing in
unrestricted mode with their exact dangerous flags. Local formatting, all-target
checking and strict Clippy also pass. `cargo deny` is not installed on this host,
so dependency-policy verification remains a CI gate. GitHub Actions run
[`36273283530`](https://github.com/Ryan-Applied/MetisBLACK/actions/runs/36273283530)
passes E04-S03 acceptance commit `8c146ad`, including the strict quality and
dependency-policy jobs and locked Rust 1.88 tests on Ubuntu, macOS 14 arm64 and
Windows.
CI is configured to run:

```bash
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets --all-features
cargo test --locked --workspace --all-features
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo deny check
```

Tests use local fixtures. The repository does not run security tests against
public targets.

## Release blockers

Before describing this as production-ready, the project still needs at least:

- OS-enforced sandboxing for expert process execution, or a clear decision that
  unsandboxed execution remains an exceptional operator-only facility
- broader end-to-end fixtures for every advertised mode and provider
- a stable configuration schema and migrations across released versions
- authorized live-lab certification of platform-specific runtime behavior beyond
  the cross-platform CI fixtures
- externally managed vault keys and defined evidence retention/deletion controls
- signed releases, provenance/SBOM publication, and dependency-update automation
- user documentation for organization-specific scope authorization and CI policy
- broader authenticated-browser, cloud IAM reachability, AI/workflow, and
  exploit-template coverage beyond the bounded paths above

Any unsupported action must continue to fail closed and appear as an explicit
limitation rather than being represented as a completed assessment.
