# metisblack-cloud-runtime

Production-oriented AWS, Azure, and GCP inventory workflows implemented over
provider CLIs. The process boundary accepts only typed argv, never shell text.

## Guarantees

- Exact expected caller identity is verified before any enumeration.
- `aws`, `az`, and `gcloud` are discovered explicitly and version-probed.
- Child environments are cleared and repopulated with only noninteractive
  runtime controls and provider-specific credential variables.
- Read-only operations are a closed typed catalogue. The three supported
  mutations require an `ExpertMutationCapability` with actor, reason, and exact
  acknowledgement; their provenance is present in the command audit.
- Commands have wall-clock timeouts, cancellation, output caps, page limits,
  and a workflow-wide command budget.
- Every invocation emits hash-bearing `CommandAudit` metadata. Call
  `CommandAudit::receipt_input` to obtain canonical JSON for sealing by the
  evidence layer.
- Failed optional services become `UnsupportedCapability` records rather than
  aborting the remaining provider workflow.

## Integration

Construct a provider `CloudScope`, a named `CloudCredentials` context for each
account/subscription/project, and a `CloudRuntime<SystemRunner>`. The result
contains verified identities, normalized resources/configuration/IAM,
finding inputs, unsupported capabilities, and command audits.

Production orchestrators should call `run_with_outcome`. Its
`WorkflowOutcome` retains partial identities, observations, unsupported items,
and successful/failed command audits alongside `terminal_error`. The original
`run` API remains available and preserves its fail-fast `Result` behavior.

`MockRunner` accepts an exact ordered sequence of `MockCall` values and exposes
redacted observations of calls. It is intended for deterministic orchestration
and receipt integration tests. The crate never installs or downloads a CLI.

## IAM reachability

`AdapterReport::from_observations` builds a provider-neutral
`IamReachabilityGraph` from the normalized IAM records returned by a workflow.
The graph has typed principal, role, group, resource, policy, and capability
nodes. Confirmed edges retain their provider, authorizing account/subscription/
project, source resources, and source command audit IDs.

`reachable_from` and `shortest_path` are deterministic and cycle-safe. They
traverse only evidence-complete edges. Missing evidence, unobserved group
membership/effective capabilities, and unapproved cross-boundary candidates
are retained as serialized `GraphGap` records and never participate in a path.
The current adapters intentionally do not infer effective permissions from role
names or acquire credentials. An AWS cross-account trust is accepted only when
the observed source policy explicitly names the foreign principal; generic
cross-boundary candidates are denied.
