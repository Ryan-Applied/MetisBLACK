# Legacy NeuroSploit platform analysis

Examined README, tutorial, integration guide, releases, Cargo manifests, app
dispatch, harness pipeline/models/credentials/grounding/planner/report code, the
Typst template, and representative recon, code and chain playbooks.

The old two-crate application delegates most work to coding CLIs or chat APIs.
The black-box probe is real HTTP, but API messages have no tool definitions.
CLI paths bypass approval/sandbox controls. Credentials are interpolated into
model context and exported to subprocesses. Finding extraction drops metadata
through `Default`. Grounding accepts keyword patterns; validators vote on prose.
The world model is assembled after assessment and does not drive decisions.

White-box context is a bounded file concatenation with a narrow extension list;
manifests/configuration and Markdown/JSON skills are omitted. PR mode fetches a
head snapshot without calculating a merge-base diff. Report metadata is stale.
Scope, account budgets and package-install permissions are prompt instructions.
Recon/meta/chain catalogs are not uniformly executed. CI examples exist but only
the release workflow is active at the repository root.

Preserve: specialist methodology, CLI workflows, multimodel support, graceful
cancellation, report formats, evidence references, human review states.
Redesign: all execution, evidence, persistence, finding lifecycle, source indexing,
planning and provider capability negotiation.
Reject: unrestricted coding subprocesses, fabricated tool text as evidence,
implicit attack edges, automatic package installation and arbitrary command
execution without an enforceable sandbox.

No legacy run artifacts, vaults or credentials are read or migrated automatically.
