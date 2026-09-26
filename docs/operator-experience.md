# Operator experience specification

The CLI, TUI and future desktop surfaces are views over one service layer. They
must never create a second execution path or weaken policy, evidence or finding
state. This specification defines the production operator workflow; it does not
claim that every interaction is implemented yet.

## Primary operators

- An engagement lead defines authorization, scope, exclusions, budgets, providers,
  evidence retention and CI policy.
- An assessor drives discovery, selects typed validation steps, handles checkpoints
  and reviews unsupported hypotheses.
- A reviewer inspects receipts and replay, resolves dissent and can explicitly
  accept a receipt-backed finding without relabeling it empirical.
- A CI or integration identity runs a pinned non-interactive plan and publishes an
  idempotent summary using least-privilege credentials.

## Engagement flow

1. **Create**: select mode and targets; import or create a versioned plan.
2. **Authorize**: show canonical targets, actor, credentials by opaque reference,
   exclusions, effective controls, requested overrides and the exact unsafe banner.
3. **Preview**: display estimated actions, requests, accounts, state changes, cost,
   provider egress, tools, unsupported capabilities and cleanup obligations.
4. **Execute**: stream typed stage/action state, budgets and evidence identifiers.
   Pause and cancellation must reach every local and remote worker.
5. **Decide**: distinguish hypotheses, reproduced, confirmed, needs-review,
   operator-accepted and rejected states visually and in machine output.
6. **Remediate**: expose cleanup/rollback state and never hide unresolved entries.
7. **Report**: generate consistent Markdown, HTML, JSON, SARIF and PDF/Typst views
   from the same report model, with receipt and artifact links.
8. **Retest**: select a finding, playbook, primitive or changed source range;
   preserve the original evidence and create a new replay lineage.

## CLI contract

- Interactive and non-interactive commands serialize the same strict plan schema.
- `--dry-run` and JSON output expose canonical scope, capability negotiation,
  budgets, overrides and disabled work before execution.
- Natural-language input may populate a draft plan, but the typed preview remains
  authoritative and ambiguous fields require confirmation.
- `--only` accepts stable playbook/capability/finding identifiers, not arbitrary
  prompt fragments.
- Proxy configuration is typed, credentials are opaque environment/vault/keychain
  references, and secret values never appear in arguments or saved history.

## TUI information architecture

- Header: run ID, mode, authorization, unsafe status, elapsed time and lifecycle.
- Targets: canonical scope, identities, roles, accounts and per-target progress.
- Plan: stage DAG, active workers, prerequisites, backtracking and disabled nodes.
- Activity: typed actions with status, duration, budget consumption and receipt ID.
- Findings: state/severity/confidence with dissent, replay and override indicators.
- Evidence: redacted observations, hashes, screenshots and replay comparison.
- Budgets: requests, state changes, accounts, tokens, cost, bytes and time.
- Cleanup: pending/completed/failed rollback and quarantine entries.
- Composer: pause, resume, cancel, annotate, request typed action and navigate; it
  cannot execute an unparsed shell command.

## Review and override interactions

- Every override selection shows the specific disabled control and resulting risk.
- Actor, reason and acknowledgement are collected before activation and recorded
  per action; inherited and replacement override sets remain visible.
- `unsafe_all` has a persistent high-contrast indicator. It cannot bypass schema,
  receipt integrity, causal-edge validation or truthful finding-state semantics.
- Reviewer acceptance is displayed separately from successful empirical replay.

## Failure and recovery

- Partial provider, browser, cloud or worker failures retain completed receipts.
- Resume previews the persisted plan fingerprint and any changed environment or
  override set before continuing.
- Stale workers are never silently rerun; the operator sees retry, skip and abort
  choices where the workflow permits them.
- Cleanup failures remain actionable after report generation.

## Accessibility and platform behavior

- CLI and reports do not rely on color alone. TUI actions have keyboard help and
  a non-interactive equivalent.
- JSON output is stable for screen readers, automation and alternative clients.
- Paths, quoting and terminal behavior are tested on Linux, macOS and Windows.
- Sensitive artifacts default to private permissions where supported and emit an
  explicit limitation where the platform cannot provide equivalent semantics.

## UX acceptance

Each implemented surface must have golden CLI/JSON fixtures, terminal-size tests,
redaction tests, cancellation/resume tests and parity checks proving it calls the
same service methods as the non-interactive path.
