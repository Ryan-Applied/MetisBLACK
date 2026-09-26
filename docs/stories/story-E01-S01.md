# E01-S01: Authenticated multi-role browser foundation

## Outcome

Execute named browser plans in isolated sessions with role-specific secret bindings
and produce a deterministic, neutral comparison record for later authorization and
object-access validation.

## Acceptance criteria

- Named role-plan contracts reject duplicate/empty roles and inline credentials.
- Every role receives a distinct WebDriver session and cleanup/quarantine lifecycle.
- Cancellation is shared; one role's ordinary failure is retained without fabricating
  observations for it or erasing completed roles.
- Results contain only redacted observations and artifact hashes, never verdicts.
- Mock-driver tests prove isolation, deterministic ordering, secret redaction,
  cleanup, cancellation and partial failure.
- Existing single-plan API remains compatible.
- Crate documentation and bounded capability claims are updated.

## Global parity gates

The controls, evidence, replay, cleanup, verification and documentation gates in
`docs/parity-roadmap.md` apply. Orchestrator integration is a follow-on story and
this story alone does not complete E01.

## Verification record

The isolated multi-role runtime is implemented and wired into browser mode through
`BrowserRunConfig.workflow` and `metisblack browser --workflow`. The orchestrator
captures every underlying browser observation as a common receipt, persists the
full workflow result, records the neutral comparison hash, and fails the stage only
after partial observations and cleanup outcomes are saved. Mock WebDriver and full
workspace tests are the local gate; authenticated live-lab certification, CDP/BiDi
interception and authorization correlation remain later E01 stories.
