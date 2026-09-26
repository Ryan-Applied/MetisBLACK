# E12-S01: Cross-platform locked workspace CI

## Outcome

Run the complete locked all-feature workspace check and test suite on GitHub-hosted
Linux, macOS arm64 and Windows runners without allowing one platform failure to
hide the others.

## Acceptance criteria

- CI has an explicit Linux/macOS/Windows matrix using the declared Rust 1.88 MSRV.
- Each platform runs locked all-target compilation and the all-feature test suite.
- Source checkout does not persist credentials and build caches are platform-keyed.
- The primary quality job still enforces formatting and warning-free Clippy.
- The story remains incomplete until a remote run proves all three runner results.

## Current evidence

The workflow definition is implemented. Local macOS testing is evidence for the
current host only; no remote run is recorded in this story yet.
