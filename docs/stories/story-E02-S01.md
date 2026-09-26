# E02-S01: Conservative intra-file flow foundation

## Outcome

Produce deterministic, language-aware source-to-sink paths for simple intra-file
flows while keeping ambiguity explicit and avoiding compiler-grade claims.

## Acceptance criteria

- Typed source, propagation, sanitizer, sink and unknown-hop records preserve exact
  file/line/hash provenance.
- Supported language front ends ignore comments and string-only decoys.
- Simple assignments and call propagation reach SQL, command, file, request and
  evaluation sinks where traceable.
- Effective sanitization breaks a verified path; ambiguity becomes needs-review.
- Tests cover positive flows, sanitizer breaks, reassignment/shadowing, multiline
  bounds, comments/strings and deterministic serialization.
- Current line-signal behavior remains compatible.

## Global parity gates

The gates in `docs/parity-roadmap.md` apply. Framework graphs, inter-procedural
analysis, dependency reachability and grey-box integration remain later E02 stories.

## Verification record

The bounded lexical flow foundation is implemented and integrated into source-mode
orchestration. `source-flow-analysis.json` preserves every analysis and limitation;
candidate paths receive independent source and sink receipts but always use manual
proof and remain `needs_review`. Unit fixtures and orchestrator tests cover the
local contract. Compiler-grade ASTs, framework reachability, inter-procedural flow,
dependency reachability and live grey-box reproduction remain later E02 stories.
