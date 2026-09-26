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
| E07 | P0 | Attack-chain breadth | Verified primitive registry, evidence-backed dynamic DAGs, loot propagation, typed adapters and cleanup | Planned |
| E08 | P1 | Provider and swarm platform | Subscription CLIs, provider breadth, streaming, reasoning controls, native cost telemetry, routing and durable workers | Planned |
| E09 | P1 | SDLC integrations | Remote PR/MR fetch, private clone, reviews, status gates, branch watch, Jira issues and mention automation | Planned |
| E10 | P1 | Operator experience and reports | Natural-language REPL, production TUI, project memory, proxies, targeted retest, PDF/Typst and evidence bundles | Planned |
| E11 | P2 | Runtime and data hardening | OS sandbox, managed keys, evidence retention/deletion, stable configuration migrations and distributed execution | Planned |
| E12 | P2 | Release engineering | Cross-platform CI, live-lab certification, signed artifacts, provenance, SBOMs and dependency automation | In progress |

## Ordering and integration rules

- E01-E03 establish reusable typed observations before expanding E04-E07.
- E04-E07 may add causal edges only from receipts accepted by harness validators.
- E08-E10 consume the service layer and cannot create alternate execution paths.
- E11 controls expert processes before general plugin or subscription-CLI expansion.
- E12 signs and publishes only artifacts produced by the complete verification matrix.
- Each story updates `implementation-status.md`, this table, and `sprint-status.yaml`
  only after code review and its scoped verification pass.

E04 currently has two in-progress foundation stories: receipt-backed bounded
surface discovery (E04-S01) and one observe-only open-redirect validator
(E04-S02). Their implementation does not complete the E04 exit condition: active
schema/API validation, authenticated discovery, additional prioritized web
vulnerability classes, owned-live-lab certification, and broader exploit-chain
coverage remain future receipt-backed stories.

## Current verification baseline

The current repository baseline is 197 passing local tests. This proves the existing
bounded contracts and fixtures, not production parity or live external behavior.
GitHub Actions run
[`36265458472`](https://github.com/Ryan-Applied/MetisBLACK/actions/runs/36265458472)
also passes the locked Rust 1.88 workspace on Ubuntu, macOS 14 arm64 and Windows,
the strict quality lane and dependency policy. This completes story E12-S01 but
not the remaining E12 live-lab, signing, provenance, SBOM or automation work.
The E04-S01/S02 implementation has passed its local gates but is newer than that
remote baseline; neither story is complete until a final-head remote run is added
to the story verification records.
