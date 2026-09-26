# E04-S01: Receipt-backed bounded web-surface discovery

## Outcome

Replace the inline one-hop regex crawl with a typed, deterministic and resumable
web-surface discovery state machine whose observed resources and declared API
operations retain immutable receipt lineage.

## Acceptance criteria

- Strict versioned plan, checkpoint and artifact contracts reject unknown fields
  and unsupported schema versions.
- Every bound is explicit and finite; `DataSampling` may authorize a larger
  operator-supplied bound but never converts a bound into `usize::MAX`.
- A deterministic breadth-first plan covers same-scope HTML links, scripts and
  form shapes, robots and sitemaps, bounded JavaScript URL hints, and OpenAPI v2/v3
  declarations without executing JavaScript, submitting forms or invoking APIs.
- Observed, declared and omitted surfaces are distinct. Malformed, truncated,
  remote-reference and out-of-scope inputs never become stronger claims.
- Every fetched resource and derived edge or operation retains receipt lineage;
  canonical ordering and hashing are reproducible from verified receipts.
- Atomic checkpoints preserve the finite frontier and completed fetches. Pause,
  cancellation, timeout and restart cannot falsely complete a target or repeat a
  completed request.
- Reporting exposes the artifact path, hash, counts and gaps without creating a
  vulnerability finding or causal chain edge from discovery alone.
- Deterministic real-loopback fixtures cover cycles, duplicates, schemas, scope
  denial, caps, malformed/truncated inputs, cancellation, tamper and restart.

## Global parity gates

The controls, evidence, replay, redaction, reporting, verification and truthful
capability gates in `docs/parity-roadmap.md` apply. Active GraphQL queries, form
submission, fuzzing and exploit payloads require later typed actions and proofs.

## Verification record

Status: done.

The current implementation adds a dedicated `web-discovery` crate and a typed
`WebDiscoveryFetch` action. The pure state machine owns strict versioned plans,
frontier/checkpoint state, canonical artifacts, finite defaults and ceilings,
observed/declared/omitted states, and receipt/body-hash lineage. Orchestration
persists plan/checkpoint/artifact/stage records, checkpoints after every receipt,
persists a pre-send operation intent, recovers an exact sealed receipt even when
the intent or run-manifest reference was not committed, converts an unresolved
pending intent into an explicit indeterminate receipt without repeating the
request, and independently
rebuilds the final artifact from sealed receipts before recording completion.
The runtime fetches exactly one response with redirects disabled and enforces both
central scope and the plan's exact allowed origins. Discovery decisions and
artifact references are report data, not findings.

Local verification on 2026-09-27 passed formatting, locked all-target/all-feature
check, Clippy with warnings denied, and all **197** workspace tests. Fixtures cover
strict contracts, every finite cap, malformed and truncated input, exact lineage,
missing/pending intent recovery, checkpoint/stage tamper, secret-bearing seeds,
mid-frontier pause, cancellation and resume, canonical paths, and deterministic
real-loopback acquisition. Atomic writes sync the file on every supported platform
and additionally fsync the parent directory on Unix; power-loss directory durability
on non-Unix platforms is not claimed.

GitHub Actions run
[`36269877662`](https://github.com/Ryan-Applied/MetisBLACK/actions/runs/36269877662)
passed all five jobs from commit `8a1f693` using the declared Rust 1.88 MSRV:
the strict format/check/test/lint lane, dependency policy, Ubuntu, macOS 14 arm64,
and Windows. Interoperability across real TLS, CDN, compression, proxy and
framework variants still requires an opt-in owned live lab; those variants are
not claimed here.
