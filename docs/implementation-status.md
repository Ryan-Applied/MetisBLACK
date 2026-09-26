# Implementation status

This document describes the code in the `0.1.0` rebuild. “Implemented” means a
bounded path exists and is tested; it does not mean broad technique coverage or
production readiness. The legacy NeuroSploit tree is a read-only reference and
is not modified or invoked by this workspace.

## Mode matrix

| Mode / command | Status | Implemented now | Important limitations |
| --- | --- | --- | --- |
| Black-box HTTP / `run` | Bounded implementation | Scoped HTTP GET, checked and pinned DNS answers, per-hop redirects, response/header/cookie observations, up to three same-scope static links, deterministic hardening candidates and replay; a configured provider can request typed HTTP actions under policy | No browser or JavaScript execution, session/cookie jar, automatic form workflow, broad fuzzing/crawl, exploit modules, screenshots, websocket, or service-worker coverage |
| Browser / `browser` | Live bounded implementation | W3C WebDriver HTTP sessions; navigation; DOM find/wait/click/clear/fill/submit; cookies; local/session storage; screenshots; console/network logs; optional capability-gated JavaScript; environment-resolved secrets; plan checkpoints; timeout/cancel/budget/scope enforcement; isolated authenticated multi-role workflows with role-local secret bindings and hash-only neutral comparison records; hash-verifiable observations sealed into common receipts | Requires an installed/configured WebDriver. Classic WebDriver cannot guarantee pre-request interception, so subresource scope validation from performance logs is post-hoc; role comparison does not itself assert an authorization flaw; websocket/service-worker completeness and target-specific authentication semantics are not claimed |
| White-box / `whitebox` | Bounded implementation | Deterministic UTF-8 inventory, source hashes/chunks, common manifest/config recognition, conservative dependency extraction, seven line-oriented security signals, exact-line receipts; bounded language-aware lexical intra-file source-to-sink paths for common HTTP sources and SQL/command/file/request/eval sinks, with explicit sanitizer and unknown-hop records | Not a compiler, framework-aware SAST engine, inter-procedural or whole-program verifier, SBOM/vulnerability database, or exploitability proof; lexical paths remain needs-review; files over limits, binaries, secrets, dependencies, and generated/vendor trees can be omitted |
| Grey-box / `greybox` | Bounded correlation | Runs source analysis and black-box HTTP, extracts up to five simple `.get(...)`/`route(...)` path literals by default, probes in-scope routes, and links source and HTTP receipts in `greybox-links.json` | No general framework routing model, data-flow correlation, authenticated browser flow, schema extraction, or causal exploit-chain inference |
| Host / `host` | Inventory only | TCP connect to explicit scoped ports and optional small passive banner read; open-port replay | No UDP, protocol negotiation, OS/service fingerprinting, credential use, host agent, exploit reproduction, or vulnerability mapping |
| Cloud / `cloud` | Snapshot review only | Reviews a local exported snapshot, requires `cloud-identity.json`, checks an explicitly scoped account ID, applies source/config signals | No live AWS/Azure/GCP SDK, IAM graph, multi-account discovery, credential acquisition, control-plane replay, or cloud API receipt |
| Live cloud / `cloud-live` | Live read-only implementation | Direct-argv AWS/Azure/GCP CLI discovery and version checks, identity verification before enumeration, strict secret-environment allowlists, typed account/subscription/project scopes, bounded pagination/output/commands, normalized assets/IAM/finding inputs, command audit and common receipts; a deterministic provider-neutral graph records only receipt-linked IAM relationships and preserves unknown or denied relationships as non-traversable gaps | Requires installed provider CLIs and operator-supplied credentials. IAM adapters are conservative and do not yet resolve exhaustive effective permissions, organizations, or all conditional semantics; mutation requires a separate typed expert capability and is not wired into the default orchestrator; no cross-provider exploit replay |
| AI endpoint / `aitest` | Benign observation probes | Scoped HTTP observation followed by two messages-array POSTs within the mode's default state-change budget: a baseline marker and a benign instruction-boundary probe; receipts are preserved for review | Assumes a compatible endpoint envelope; no broad multi-turn corpus, model-output judge, tool-abuse harness, leakage canary, authenticated conversation, or automatic vulnerability verdict |
| Skills/workflows / `skills` | Static review only | Source/config review, a distinct `skills-audit.json` inventory for instruction/plugin/MCP/n8n surfaces, and mode-specific provider playbooks | Does not execute workflows, import platform state, simulate triggers, or verify SaaS workflow behavior |
| Local Git PR / `pr` | Bounded implementation | Resolves commits, computes merge base, exports the head tree without hooks, records added/modified/deleted/renamed/type-changed files and bounded patches, maps signals to changed lines, records `introduced`, emits SARIF | Local repository only; no GitHub/GitLab API, remote fetch, review comment, working-tree review, build, or test execution |
| Retest / `retest` | Narrow implementation | Replays supported missing-header, insecure-cookie, source-rule, and open-port predicates; records present/fixed/review outcome | Manual/provider narratives cannot be automatically retested; no browser or arbitrary exploit replay |
| Operator acceptance / `accept` | Implemented, explicit | Applies a separately acknowledged `confirmation` override to one eligible, receipt-backed finding and records `operator_accepted` | Cannot accept rejected or receipt-less evidence; never produces empirical confirmation and is excluded from default gates |
| Expert typed action / `tool` | Implemented, exceptional | Executes one JSON-encoded `ToolAction` against a saved run with its scope/budgets/overrides; supports HTTP, account, AI, source, DNS, TCP, and override-gated shell actions | Requires a pre-existing run and authorization for active tools; this is not a general plugin API and unsafe shell remains unsandboxed |
| Multi-target | Basic | Sequential target checkpoints with shared budgets and resumable completion tracking | No distributed workers, cross-target causal reasoning, scheduling UI, or fleet coordination |

## Subsystem status

| Area | Status | Notes |
| --- | --- | --- |
| Typed domain contracts | Implemented | Strict Serde schemas, explicit modes/severity/states/proofs, model requests cannot set finding state |
| Central policy | Implemented for current tools | Network, URL, host, port, CIDR, filesystem, sampling, request/state/account budgets, command classes, and expert controls are evaluated in code |
| HTTP runtime | Implemented, bounded | GET plus typed GET/HEAD/OPTIONS/POST/PUT/PATCH/DELETE; state-changing methods consume budgets and generic mutations require overrides; no inherited proxy/cookie jar; checked DNS and redirects |
| Source runtime | Implemented, bounded | Canonical scoped path, symlink and secret-path checks, UTF-8 line capture with source hash; conservative hash-bound lexical flows preserve typed sources, sinks, sanitizers and unknown hops and are linked to source receipts by orchestration |
| DNS and TCP runtime | Implemented, bounded | Explicit host/port scope; TCP only and no application payload |
| Expert shell | Implemented only through overrides | Unsandboxed child process with captured output. It requires explicit capability/sandbox/network/filesystem overrides plus command-risk permission. See `expert-overrides.md` |
| Evidence store | Implemented | Private create-once JSON receipts, run/actor/action/output provenance, metadata and content hashes, override provenance, manifest verification |
| Finding confirmation | Implemented for narrow proofs | Independent replay is required for empirical confirmation. Unsupported narratives stay reviewable; operator acceptance is separate |
| Provider swarm | Implemented, early | Mode- and observation-selected playbooks run in recon, specialist, then meta-review stages; same-stage specialists can run concurrently with fresh contexts and session audit |
| Provider loop | Implemented, early | OpenAI/OpenAI-compatible, Anthropic, Gemini, Ollama, llama.cpp, and deterministic mock envelopes; typed calls and token counts. Remote-provider egress requires run authorization or the `authorization` override; the deterministic mock is local |
| Heterogeneous model panel | Implemented, opt-in | Two-or-more independently identified providers/deployments; fresh candidate/reviewer/refuter contexts; per-member authorization/token/cost/timeout/retry/weight budgets; failure isolation; structured quorum, dissent, audit, receipt allowlisting, and optional calibration metadata | Provider-reported native cost telemetry remains absent, so configured token-price fallback is used. Consensus only admits a candidate to harness validation and cannot confirm it |
| Provider operations | Partial | No streaming, native cost telemetry, or reasoning controls; retry policy is small and fixed |
| Browser runtime | Implemented, bounded | Typed portable plans and W3C commands, negotiated capability reporting, artifact hashing/private writes, session cleanup/quarantine, plan-prefix replay, redaction, shared central policy receipts; multi-role execution uses isolated sessions, distinct runtime secret bindings, shared cancellation/budgets, failure isolation and neutral evidence hashes | No CDP/BiDi request interception guarantee, automatic IDOR/authz verdict, distributed browser grid management, CAPTCHA solving, or claim of exhaustive browser observability |
| Cloud runtime | Implemented, bounded | Read-only typed AWS STS/IAM/S3/EC2/Lambda/EKS/RDS, Azure account/role/storage/VM/AKS/KeyVault, and GCP auth/project/IAM/storage/compute/GKE/secrets workflows; normalized IAM observations feed a deterministic, cycle-safe reachability graph whose traversable edges require provider evidence and common receipt lineage | Optional/unsupported CLI capabilities are reported rather than fabricated; graph gaps are not paths; exhaustive effective-permission and organization semantics, credential acquisition and arbitrary provider commands remain out of scope |
| World model | Implemented, simple | Bayesian belief update chooses recon/reproduce/assess/stop and persists decisions; not a learned POMDP or sophisticated planner |
| Playbook library | Implemented, bounded | Strict versioned JSON or JSON-frontmatter Markdown; legacy Markdown import preserves methodology as untrusted text; restricted books are not selected by default and require `playbook_selection` override |
| Vault | Implemented for generated test accounts | AES-256-GCM entries and restrictive local key permissions; typed account creation stores only an opaque secret reference in evidence and adds a cleanup record. No external KMS/keychain integration |
| Checkpoint/resume | Implemented | Atomic snapshots and a single-writer lock; completed runs cannot resume; stale lock recovery is manual. A replacement override set cannot remove the sole authorization bypass for a network/provider run without a fresh `--authorize` decision |
| Reports | Implemented | Markdown, offline HTML, JSON, findings JSON, SARIF, execution plan, receipt manifest, and cleanup ledger |
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
- platform testing beyond the primary Unix development path
- externally managed vault keys and defined evidence retention/deletion controls
- signed releases, provenance/SBOM publication, and dependency-update automation
- user documentation for organization-specific scope authorization and CI policy
- broader authenticated-browser, cloud IAM reachability, AI/workflow, and
  exploit-template coverage beyond the bounded paths above

Any unsupported action must continue to fail closed and appear as an explicit
limitation rather than being represented as a completed assessment.
