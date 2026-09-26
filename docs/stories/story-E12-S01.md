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

Complete. GitHub Actions run
[`36265174263`](https://github.com/Ryan-Applied/MetisBLACK/actions/runs/36265174263)
passed from commit `72676d3` with independent green results for Ubuntu, macOS 14
arm64 and Windows, plus the strict format/check/test/Clippy and dependency-policy
jobs. The Windows lane ran all 148 tests on Rust 1.88; platform-sensitive fixtures
use native legal paths and scheduling assertions measure observed concurrency
instead of relying on wall-clock thresholds.
