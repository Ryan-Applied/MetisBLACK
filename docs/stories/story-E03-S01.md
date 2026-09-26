# E03-S01: Provider-neutral IAM reachability graph

## Outcome

Convert existing normalized AWS, Azure and GCP identity observations into an
evidence-backed graph that can answer deterministic reachability questions without
conflating assumptions with confirmed privilege paths.

## Acceptance criteria

- Typed principal, group, role, policy, capability and resource nodes include
  provider and canonical account/subscription/project identity.
- Every confirmed edge references originating command/audit evidence.
- Unknown or assumed relationships remain explicit and cannot satisfy a confirmed
  path query.
- Reachability and shortest-path queries are deterministic and cycle-safe.
- Cross-boundary paths fail closed unless the observed relationship explicitly
  authorizes the boundary.
- Fixtures cover direct, transitive, cyclic, cross-boundary, missing-evidence and
  stable-serialization cases for all three providers.

## Global parity gates

The gates in `docs/parity-roadmap.md` apply. Organization discovery, controlled
validation mutations, rollback and chain-engine integration remain later E03 stories.

## Verification record

Implemented in `cloud-runtime` and integrated into live-cloud orchestration as the
versioned `cloud-iam-graph.json` artifact. Every traversable edge must resolve its
provider audit ID to a common immutable receipt before the artifact is accepted.
Crate tests, orchestrator integration tests, formatting and strict Clippy are the
required local gate; live provider certification remains a later E03 story.
