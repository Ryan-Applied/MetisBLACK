# E08-S01: Audited autonomous subscription-CLI providers

## Outcome

Add native Claude Code and Codex subscription transports to the existing provider
loop and heterogeneous model panel. The adapters execute fixed direct argv, use
the operator's existing subscription login, normalize machine-readable output,
and expose autonomous native tooling only through an explicit assurance mode.
Provider narration and native tool activity remain control-plane audit data: they
cannot manufacture MetisBLACK tool receipts, empirical confirmation, or causal
attack-chain facts.

## Acceptance criteria

- A strict versioned configuration selects only a named `claude` or `codex`
  adapter, compatible vendor, model, autonomous mode, bounded output/event/turn
  ceilings, optional absolute executable, optional working directory and a finite
  environment-name allowlist. There is no arbitrary command, argv template or
  shell string.
- Executables are resolved and canonicalized before use. The adapter records the
  canonical path, executable hash, observed version and fixed argv-schema hash.
  Unsupported executables, backend/vendor combinations and malformed versions
  fail closed or require a truthful provider-capability downgrade.
- Every invocation uses `Command::new` with adapter-owned arguments and sends the
  prompt over bounded stdin. The child starts from `env_clear`; only the exact
  adapter/profile names selected by configuration are copied. Assessment, cloud,
  unrelated provider and process-injection variables are not inherited by
  default.
- Claude exposes distinct `inference_only`, `read_only`, `workspace_write` and
  `unrestricted` modes. Codex exposes `read_only`, `workspace_write` and
  `unrestricted`; its `inference_only` selection fails closed until the installed
  CLI provides a verified no-tools mode. Native tools require explicit
  `tool_capabilities`, `sandbox`, `network` and profile-secret acknowledgement.
  Write and unrestricted modes require the additional applicable filesystem,
  state, command, installation, download, destructive, privilege and environment
  overrides. `unsafe_all` remains the deliberate aggregate bypass.
- Unrestricted Claude uses `--dangerously-skip-permissions`; unrestricted Codex
  uses `--dangerously-bypass-approvals-and-sandbox`. No safer mode contains either
  flag. Reports and receipts label unrestricted execution as lower assurance and
  make no containment claim.
- Provider-owned read-only/workspace sandbox flags are reported as provider
  capabilities, not as MetisBLACK OS-sandbox proof. Native commands, edits, web
  requests, MCP calls and files are recorded only as bounded redacted event
  summaries and hashes.
- Stdout, stderr, aggregate events, runtime and turn count are bounded. Timeout,
  cancellation, overflow, invalid UTF-8 where required, malformed/trailing JSON,
  non-zero exit and missing final result fail closed. Dropping an in-flight
  invocation kills at least the direct child; any weaker process-tree guarantee
  is reported explicitly.
- The provider loop and model panel consume the same adapter. Subscription calls
  require engagement authorization, never read an API key, never silently fall
  back to HTTP, never auto-retry a possibly consumed turn, and preserve vendor
  trust-domain rules for heterogeneous quorum.
- A durable pre-spawn intent binds actor/session/step, transcript and tool-schema
  hashes, provider/model, adapter capability, executable, argv, environment names,
  ceilings and overrides. A sealed common receipt binds termination, output
  hashes/counts, normalized reply, telemetry provenance and native-event summary.
  A pending post-spawn intent without an exact receipt is indeterminate and is not
  automatically repeated.
- Reports expose adapter/version/hash, execution mode, sandbox and cancellation
  assurance, native activity, truncation, token/cost provenance and all overrides.
  Native activity cannot become a target observation, finding proof or chain edge.
- Deterministic compiled fake-CLI fixtures cover exact argv, injection text,
  environment isolation, mode gating, danger-flag presence/absence, structured
  output, stream parsing, caps, timeout, cancellation, secret redaction, version
  mismatch, crash/tamper recovery and CLI/API same-vendor quorum. Authorized live
  checks bind the exact installed Claude and Codex versions and executable hashes;
  Gemini and Grok remain unsupported until separate adapters pass the same gate.

## Global parity gates

The controls, evidence, replay, redaction, cleanup, reporting, verification and
truthful-capability gates in `docs/parity-roadmap.md` apply. This story does not
complete E08 or E11: MetisBLACK-managed cross-platform process trees, OS sandbox,
provider-only egress, managed credential brokerage, durable workers, Gemini/Grok
adapters, streaming UX, native cost coverage and broad reasoning controls remain
separate required work.

## Verification record

Status: in progress.

Completed in this slice:

- The locked workspace matrix passes 311 non-ignored tests; two authenticated
  live tests remain ignored by default.
- Formatting, all-target/all-feature checking, strict Clippy and `git diff
  --check` pass. Local `cargo deny` is unavailable and remains a CI gate.
- The hardened unrestricted probes passed against Claude Code `2.1.283`
  (`d8cb1e5c79684cc12a8bfc813e3a2073406921b6245744b3009be3ab5651d21e`)
  and Codex CLI `0.147.0`
  (`134063e133f0b4244fa3b251acf973d4fe4b4aeeacbdc135211bf480f59f1477`).
- Deterministic adversarial fixtures cover exact danger flags, no-tools failure,
  API-key exclusion, prepared executable replacement, typed failure audit,
  descendant-held pipes, panel/specialist crash recovery without a CLI, and
  control-plane evidence exclusion.
- A swarm review identified seven release-significant findings; all seven were
  addressed and the complete matrix was rerun.
- The locked optimized `metisblack 0.1.0` macOS arm64 build completed with
  SHA-256 `8594d65c7f75171bc3c1dac64139bb0b55ba0365c4e6d25af09c53632b9f48d8`.
- Final-head GitHub Actions run
  [`36277987141`](https://github.com/Ryan-Applied/MetisBLACK/actions/runs/36277987141)
  passes the strict quality and dependency-policy jobs plus locked Rust 1.88
  tests on Ubuntu, macOS 14 arm64 and Windows for commit `6f45b98`.

The story remains in progress because the broader E08/E11 items listed above are
not implemented. Unrestricted live prompts remain opt-in and require the exact
audited override bundle or `unsafe_all`.
