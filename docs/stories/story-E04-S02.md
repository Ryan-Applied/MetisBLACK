# E04-S02: Typed observe-only open-redirect validation

## Outcome

Validate a narrow server-side open-redirect predicate using a dedicated typed GET
action and runtime-generated reserved-domain canary, without following or
contacting the redirect destination.

## Acceptance criteria

- The action accepts an in-scope endpoint and constrained query parameter; the
  runtime generates a fresh opaque canary under `https://metisblack.invalid/`.
- The first response is observed without following `Location`. URL, DNS, private
  address, authorization, request, rate, concurrency, timeout, sampling and
  redaction controls still apply through the central runtime.
- Success means the action completed, not that a vulnerability exists. The proof
  recomputes the predicate from a strict typed observation and requires an allowed
  redirect status plus an exact normalized canary `Location` match.
- Initial validation, independent reproduction and retest each use a fresh canary,
  actor, request and receipt. Transport or malformed-response failures are
  inconclusive, never evidence that the issue is fixed.
- Canonical claims remain conservative: confirmation proves server-side arbitrary
  redirect semantics, not phishing success, OAuth theft or account takeover.
- The GET consumes the ordinary request budget and creates no remote state or
  cleanup obligation. No redirect, destination or third-party bypass is required
  because the canary is response data and is never navigated.
- Fixtures cover exact positive replay, same-origin and lookalike negatives,
  malformed/missing locations, scope/authorization/budget denial, timeout,
  receipt tamper rejection, restart and retest present/fixed/inconclusive states.

## Global parity gates

The gates in `docs/parity-roadmap.md` apply. Browser-executed XSS, OAuth redirect
chains and state-changing web exploits remain separate receipt-backed stories.

## Verification record

Status: in progress; local verification passed, final-head CI pending.

The current implementation adds a strict `OpenRedirectObservation`, typed
`OpenRedirectProbe` action and `Proof::OpenRedirect`. Policy validates the
declared endpoint and runtime-built probe URL; the runtime performs one GET with
redirects disabled, records authorization and resolved-address provenance, and
does not resolve or contact the `Location` destination. Harness validation
reparses the strict observation, binds it to the action and proof, and recomputes
the predicate from an allowed redirect status and exact raw canary `Location`.
Independent replay and retest generate fresh canaries; a failed or malformed
retest remains `needs_review` rather than becoming `retested_fixed`.

Each initial probe has a durable pre-send intent. Restart recovers only an exact
actor/action-bound sealed receipt; an unresolved intent becomes indeterminate and
is never automatically repeated. Failed probes create explicit failed-stage and
limitation records. A repeat requires `retry-failed-stages`, consumes a one-shot
audited retry decision, and uses a fresh canary. Positive probe coverage is not
marked complete until the receipt-backed finding has been persisted, closing the
crash window between observation and claim creation.

A real-loopback fixture exercises confirmation with fresh replay canaries,
positive crash recovery, exact intent binding, missing-intent recovery, explicit
failure/retry, and present/fixed/inconclusive retest semantics. Local verification
on 2026-09-27 passed formatting, locked all-target/all-feature check, Clippy with
warnings denied, and all **197** workspace tests. The story remains open until the
final-head GitHub Actions run is recorded.
An owned authorized live lab is still required before broader framework
interoperability is claimed; this is one observe-only vulnerability class, not
broad web exploitation parity.
