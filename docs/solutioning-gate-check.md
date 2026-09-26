# Production-parity solutioning gate

Gate date: 2026-09-27. Result: **conditionally ready for incremental delivery**;
the architecture is suitable, but the full parity program is not release-ready.

## Requirements coverage

| Requirement | Architectural owner | Evidence today | Gate |
| --- | --- | --- | --- |
| Central typed execution and policy | domain, policy, tool-runtime | Strict schemas, 32-control matrix and override tests | Pass for existing tools |
| Immutable evidence and truthful states | evidence, storage, orchestrator | Receipt hashes, replay and finding transition tests | Pass for supported predicates |
| Browser automation | browser-runtime | W3C plans, isolation, artifacts, cancellation | Partial: modern network and role workflows |
| Web validation breadth | tool-runtime, orchestrator | Typed HTTP and narrow header/cookie predicates | Missing broad modules |
| Source and grey-box analysis | source-analysis, orchestrator | Inventory, dependencies, route literals and conservative lexical flow traces | Missing robust interprocedural/framework models |
| Host and Active Directory | tool-runtime, orchestrator | TCP inventory | Missing protocol and credentialed adapters |
| Live cloud assessment | cloud-runtime, orchestrator | Identity-verified read-only workflows and evidence-backed IAM reachability | Missing controlled validation breadth and live certification |
| AI/MCP/workflow validation | orchestrator, providers | Two benign endpoint probes and static review | Missing scenario/judge/replay harness |
| Multimodel validation | providers, model-panel | Heterogeneous quorum, dissent and failure isolation | Partial provider/telemetry breadth |
| Attack chains | chain-engine, orchestrator | Typed DAG/replay/rollback and 18 templates | Partial adapter and primitive breadth |
| SDLC integrations | integrations, app | Audited comment publication | Missing remote lifecycle automation |
| Production operations | app, storage, CI | Checkpoints, local vault and verified Linux/macOS/Windows CI | Missing sandbox/KMS/migrations/signing/live-lab certification |

## Architecture decisions

- Preserve the runtime trust boundary: models and imported playbooks propose only.
- Add capability-specific crates or typed adapters instead of a generic arbitrary
  command escape hatch.
- Normalize observations at provider/protocol boundaries, then construct graphs,
  correlations and candidates above them.
- Keep empirical replay independent from candidate generation and model consensus.
- Use one durable run/event model for CLI, TUI, CI, distributed workers and resume.
- Introduce managed secrets and sandbox backends behind traits so local development
  remains deterministic without weakening production capability negotiation.

## Risks requiring continuous gates

1. Breadth can outpace proof predicates and silently turn methodology into claims.
2. Subscription CLIs and plugins can bypass the runtime unless process isolation is
   completed before general enablement.
3. Cloud and identity relationships are conditional; inferred edges must not become
   confirmed paths without provider evidence.
4. Browser logs observed after requests cannot prove pre-request scope enforcement.
5. Cross-platform filesystem and process semantics can invalidate local guarantees.
6. Long-running/distributed work needs idempotency and lease semantics before scale.

## Delivery decision

Proceed by the epics and gates in `parity-roadmap.md`. Do not advertise production
parity until every workstream exit condition has direct code, fixture, live-lab and
release evidence and `implementation-status.md` no longer lists the corresponding
limitation.
