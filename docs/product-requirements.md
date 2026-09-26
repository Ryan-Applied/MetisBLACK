# Product requirements

MetisBLACK is an authorized security-assessment application whose model can
request actions but cannot execute them outside a typed, centrally enforced
runtime. The existing implementation remains a read-only reference.

The primary contract is an auditable chain from scope to action to observation to
receipt to finding to independent reproduction. Models produce hypotheses, never
trusted receipts or confirmation status. API and local providers share that loop.

Modes: black-box HTTP, white-box source, grey-box correlation, host discovery,
cloud configuration, AI endpoint testing, skills/workflows, local Git PR review,
retesting and multi-target engagements. Interfaces share one service layer.

Required quality: stable Rust, deterministic local fixtures, no public-target
tests, restricted secret files, explicit capability reporting, accurate finding
states, reproducible reporting, resumable checkpoints, bounded work and costs.

An authorized expert may deliberately override every operational restriction,
granularly or with `--unsafe-all`. Overrides must never activate implicitly: require
actor, reason and explicit acknowledgement, display the effective plan, and record
history and per-action provenance. Schema/integrity and truthful empirical assurance
remain invariants. Operator acceptance is a separate finding state, excluded from
default CI gates. Unsandboxed expert commands make no containment guarantee.

Acceptance is tracked in `implementation-status.md`. Unsupported operations fail
closed and are reported as limitations; a command existing is not evidence that
every technique described by a legacy playbook has been implemented.
