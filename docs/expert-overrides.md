# Expert overrides

Expert overrides deliberately remove runtime protections for an authorized
operator. They are part of the evidence record, not a hidden “developer mode.”
The default remains enforced, and model/provider content cannot activate an
override.

## Activation contract

An override is valid only when all of the following are supplied:

- one or more named `--override` controls, or `--unsafe-all`
- `--override-actor` with the accountable operator or automation identity
- `--override-reason` with at least eight non-whitespace characters
- `--acknowledge-unsafe`

Example:

```bash
metisblack run https://lab.example.test \
  --authorize \
  --override rate-limit,request-budget \
  --override-actor "operator@example.test" \
  --override-reason "isolated lab performance window" \
  --acknowledge-unsafe \
  --output ./runs/lab-window
```

The same fields can be stored in a version-1 `RunConfig` for noninteractive CI:

```json
{
  "overrides": {
    "controls": ["rate_limit", "request_budget"],
    "unsafe_all": false,
    "reason": "approved isolated CI fixture",
    "actor": "ci:security-fixture",
    "acknowledged": true,
    "timestamp_ms": 0
  }
}
```

The engine replaces the timestamp with the run start time. Keep the configuration
under change control and protect workflow variables that supply the actor and
reason. An active override produces a prominent stderr banner before execution.
It is persisted in the run manifest, reports, SARIF properties, and receipt
provenance so a receipt can be interpreted with the exact controls disabled when
it was captured.

`--authorize` is separately required for every active egress operation unless the
`authorization` control is explicitly disabled. This includes target-facing
network tools, remote model-provider calls, and integration publication. Because
`--unsafe-all` disables every control, it also bypasses all of these application
gates. Neither path creates legal authorization.

## Control reference

CLI values accept hyphens; JSON uses the snake-case names shown below.

| Control | Default protection | What disabling it permits or changes |
| --- | --- | --- |
| `authorization` | Requires `--authorize`, interactive `AUTHORIZE`, or `authorized: true` for active egress: target tools, remote model providers, and integration publication | Bypasses the application's authorization gate. It does not establish legal or organizational authorization |
| `cloud_identity` | Requires a cloud snapshot to contain `cloud-identity.json` bound to an explicitly scoped account | Skips that account-identity binding check; cloud mode remains local snapshot analysis |
| `playbook_selection` | Selects only mode/observation/tool-compatible read-only playbooks and caps the normal panel | Makes every loaded playbook eligible, including state-changing/restricted entries. Tool and runtime policy still apply to requested actions |
| `scope` | Applies declared network and filesystem scope | Broadly bypasses scope checks. Prefer a narrower destination/path/root override whenever possible |
| `destinations` | Requires the host to match an allowed network rule and honors host exclusions | Allows an otherwise undeclared/excluded host through an existing rule's port/path shape; private/CIDR address checks remain enforced |
| `redirects` | Rechecks tool hops, limits chains to five, and disables publication redirects | Removes the tool hop limit, allows redirect-hop destination/path/network scope through the derived redirect policy, and permits integration redirects; the original tool URL is still checked |
| `subdomains` | Only a rule marked for subdomains matches descendants | Allows descendant hosts of a declared rule even when its subdomain flag is off |
| `third_party` | Prevents navigation to undeclared third parties | Bypasses the same host boundary for third parties while retaining port/path and private/CIDR constraints |
| `paths` | Requires normalized URL paths under an allowed prefix and honors exclusions | Allows out-of-prefix/excluded URL paths; path syntax and URL parsing still apply |
| `ports` | Requires an explicitly listed port | Allows other ports on an otherwise applicable host rule |
| `cidrs` | Constrains resolved/IP targets to declared CIDRs where configured | Bypasses CIDR and private-address resolution checks |
| `filesystem_roots` | Requires canonical non-symlink paths beneath declared roots | Allows paths outside roots and is a prerequisite for expert shell; ordinary filesystem/OS errors still apply |
| `command_risk` | Unknown, denial-of-service, and otherwise unclassified commands are blocked; classified commands require their class control | Allows every command class once the shell capability prerequisites are also disabled |
| `package_installation` | Blocks package-manager commands | Allows the package-installation class when `command_risk` remains enforced |
| `external_downloads` | Blocks download commands such as `curl` and `wget` | Allows the external-download class when `command_risk` remains enforced |
| `state_changes` | Blocks generic mutating HTTP and state-changing commands and enforces the state-change budget used by typed AI/account operations | Allows generic mutations/the command class and removes that budget gate; operations are still recorded |
| `destructive_actions` | Blocks HTTP DELETE and destructive command classes | Allows DELETE and commands classified as destructive when the other method/shell prerequisites also pass |
| `privilege_changes` | Blocks privilege/ownership/mode-changing command classes | Allows that class when `command_risk` remains enforced; it does not grant OS privileges |
| `account_budget` | Limits generated test identities and, with `state_changes`, blocks generic mutating HTTP that could create an account | Removes the account count gate and corresponding generic-mutation gate. Typed account creation stores a generated password in the encrypted run vault and records pending cleanup |
| `rate_limit` | Serializes starts to the configured requests-per-second rate and validates its range | Removes runtime pacing and the normal positive/range validation |
| `request_budget` | Caps tool operations, target count, and model steps | Removes the tool-request cap and upper bounds for targets/steps; `max_steps` must still be positive |
| `concurrency` | Applies the configured semaphore and validates 1–64 | Removes the runtime concurrency semaphore and configured range validation |
| `data_sampling` | Caps file, context, provider, subprocess, and HTTP response sizes and source line ranges | Removes those byte/range caps; memory, provider, filesystem, and protocol limits still exist |
| `sandbox` | Refuses arbitrary subprocess execution because no OS sandbox is present | Required to expose the unsandboxed shell path; it does not create a sandbox |
| `network` | Enforces network scope and secure provider/integration endpoint rules | Bypasses network destination checks and permits non-HTTPS provider or publication endpoints; also required for expert shell because a child process can perform its own networking |
| `environment` | Clears child environment; subscription CLIs receive only fixed values plus explicitly named profile variables | Lets an expert subprocess inherit the full MetisBLACK environment. For a subscription CLI, blanket inheritance additionally requires `unrestricted` autonomy and is fully named in the invocation audit |
| `secret_redaction` | Recursively redacts known and pattern-matched secrets from evidence and reports | Stores raw captured values where the tool exposes them, including `Set-Cookie`; this can permanently disclose credentials in run artifacts |
| `secret_exposure` | Blocks secret-bearing URL fields/queries, secret paths, credential commands, and credential-bearing provider/integration endpoints | Allows those sources and fields. This is distinct from redaction: exposed material may still be redacted unless `secret_redaction` is also disabled |
| `provider_capabilities` | Accepts only known HTTP provider kinds and the typed Claude/Codex subscription adapters | Treats an unknown HTTP kind as OpenAI-compatible. It does not create an arbitrary subscription command, argv template, or provider protocol |
| `tool_capabilities` | Exposes only the standard typed methods and tools | Adds the expert `shell` tool, permits otherwise unsupported HTTP methods, and acknowledges that a native subscription CLI may use provider-owned tools outside the harness |
| `confirmation` | Requires supported independent replay for empirical confirmation | Permits the explicit `accept` command for one eligible finding. The result is `operator_accepted`, never empirical `confirmed` |
| `timeouts` | Applies DNS, TCP connect/banner, HTTP connect/request, provider, publication, and whole-tool timeouts | Omits those application timeouts; cancellation, OS/network behavior, remote infrastructure, and upstream libraries can still stop an operation |

Controls are safety gates, not reality-bending switches. They do not bypass strict
JSON/schema parsing, receipt integrity verification, missing files/programs,
unsupported protocols, unavailable credentials, provider behavior, kernel access
control, network reachability, or the requirement for a non-empty target and
positive model-step count.

## Saved-run actions and override history

`resume`, `retest`, and `tool` reuse the overrides already persisted in a run when
no new override flags are supplied. Passing a new override set replaces the
active set; it does not merge with it. The previous set is appended to
`override_history`, the new set receives a fresh timestamp, and subsequent
receipts embed the new exact provenance. Review the full history when a single
run spans multiple operator decisions.

Resume will not let a replacement override set remove the run's sole
`authorization` bypass when its network mode or remote provider still requires
egress. Supply a fresh `--authorize` in that resume invocation; the decision is
then persisted on the run before the replacement is applied. This prevents an
override edit from silently continuing an active run without an authorization
decision.

The `tool` command executes one strict JSON `ToolAction` through the saved run's
policy and evidence store. For example, an unsandboxed command request is encoded
as data, then separately authorized by its required overrides:

```json
{
  "tool": "shell",
  "program": "/usr/bin/id",
  "args": [],
  "working_dir": "/approved/lab"
}
```

```bash
metisblack tool ./runs/lab --request ./id-action.json --authorize \
  --override tool-capabilities,sandbox,network,filesystem-roots,command-risk,state-changes \
  --override-actor "operator@example.test" \
  --override-reason "read-only identity check in isolated lab" \
  --acknowledge-unsafe
```

Typed `create_account` is different from generic mutating HTTP: it generates a
password, stores it in the encrypted run vault, returns only an opaque secret
reference, consumes configured state/account budgets, and adds a pending cleanup
entry. Generic POST/PUT/PATCH requests require both `state_changes` and
`account_budget` overrides because the harness cannot infer their side effects.

## Dependencies between controls

### Unsandboxed shell

The shell tool is intentionally hard to enable. At minimum it requires:

```text
tool_capabilities + sandbox + network + filesystem_roots
```

It then requires either `command_risk` or the matching command-class override.
A read-only command recognized by the classifier does not need an additional
class override. Every shell execution consumes the state-change budget regardless
of classification, so the saved run must have remaining `max_state_changes` or
disable `state_changes`. An unknown command needs `command_risk`. For example, an
unclassified expert command with a default zero state-change budget needs:

```bash
--override tool-capabilities,sandbox,network,filesystem-roots,command-risk,state-changes
```

This execution is **not sandboxed**. The process runs as the MetisBLACK user,
uses the chosen working directory, can access anything that OS identity can
access, and can escape all application-level policy. The runtime captures stdout,
stderr, exit status, and override provenance, but logging cannot undo side
effects. With `environment` disabled, the child also inherits provider keys and
other environment secrets. With `data_sampling` disabled, output is effectively
unbounded until another resource limit intervenes.

Command classification is a guardrail, not a shell parser or security boundary.
Wrappers, interpreters, scripts, aliases, and program behavior can defeat
name-based classification. Use an OS/container/VM boundary for hostile commands.

### Autonomous subscription CLIs

All Claude/Codex subscription modes acknowledge that a provider-owned process can
perform activity outside the typed harness. The baseline bundle is:

```text
tool_capabilities + sandbox + network + secret_exposure
```

`workspace_write` additionally requires `filesystem_roots + state_changes`.
`unrestricted` additionally requires:

```text
filesystem_roots + state_changes + environment + command_risk +
package_installation + external_downloads + destructive_actions + privilege_changes
```

`unsafe_all` satisfies these application gates as the deliberate aggregate
bypass. The runtime, not user-supplied argv, adds
`--dangerously-skip-permissions` for Claude or
`--dangerously-bypass-approvals-and-sandbox` for Codex. Neither flag appears in
`inference_only`, `read_only`, or `workspace_write`. Blanket ambient environment
inheritance requires both `unrestricted` and its environment/secret controls;
provider API-key variables remain excluded so the subscription path cannot
silently switch authentication or billing. Otherwise use named `HOME`, `PATH`,
`USER`, `LOGNAME`, XDG, proxy/certificate, or provider-profile variables. Claude
safe mode disables its native customization surface by default. Codex ignores
user config and exec-policy rules, but project-instruction discovery such as
`AGENTS.md` remains CLI-owned and is not claimed isolated.
`--subscription-load-native-customizations` is an unrestricted-only bypass that
restores the customization sources controlled by the supported CLI flags and
records that lower-determinism choice in the invocation. Codex `inference_only`
fails closed until an installed version exposes a verified no-tools mode;
`read_only` still permits provider-native reads.

These overrides do not create containment. Native commands, edits, downloads,
web requests, MCP calls, and subprocesses run with the operator's OS authority.
MetisBLACK records bounded event summaries, executable/version/hash, argv,
environment names, output hashes, telemetry, overrides, and a durable pre-spawn
intent. A pending post-spawn intent without an exact sealed receipt becomes
indeterminate and is not retried. These control-plane receipts are excluded from
target evidence, panel citation, confirmation, and attack-chain derivation.

### Secret access and persistence

`secret_exposure` permits secret-bearing inputs; `secret_redaction` controls what
is stored. Disabling both is the highest disclosure risk because receipts,
provider-step files, reports, and integration payload preparation may contain raw
material. File permissions do not make those artifacts safe to commit, upload,
back up, or share.

### Destination controls

`scope`, `destinations`, `third_party`, and `network` each bypass broad parts of
host enforcement. `paths`, `ports`, `subdomains`, and `cidrs` are narrower and
should be preferred. `redirects` has special hop-only semantics; it does not make
the initial target valid.

### Confirmation

The `confirmation` override does not fabricate receipts, reproduce an exploit, or
change the meaning of `confirmed`. It permits an accountable operator to accept
one eligible claim in a separate state:

```bash
metisblack accept ./runs/review finding-123 \
  --override confirmation \
  --override-actor "reviewer@example.test" \
  --override-reason "manual reproduction approved in review record 42" \
  --acknowledge-unsafe
```

The command refuses rejected findings, receipt-less candidates, missing receipts,
and a request without the `confirmation` control. Reports, JSON, and SARIF
preserve the distinction. Default `--fail-on` behavior excludes
`operator_accepted`; `--include-operator-accepted` is the explicit opt-in.

## `--unsafe-all`

`--unsafe-all` disables every control in the control inventory. It still requires
actor, reason, and acknowledgement:

```bash
metisblack run https://isolated-lab.example.test \
  --authorize --unsafe-all \
  --override-actor "operator@example.test" \
  --override-reason "disposable isolated lab with external containment" \
  --acknowledge-unsafe
```

Consequences include bypass of the application's authorization and cloud-identity
gates, unrestricted target/file reach, unrestricted playbook selection,
unsandboxed model-requested processes, unpaced/unbounded work, destructive and
privilege-changing command classes, inherited environment secrets, disabled
redaction, and explicit operator acceptance of unproven claims. The blast radius
is the full OS account and every network it can reach. Prefer a disposable VM or
container with independent egress, filesystem, credential, process, and resource
controls.

Even though it bypasses the application's authorization prompt, `--unsafe-all`
does not:

- create legal authorization or waive organizational change control
- elevate the OS account or grant cloud/IAM privileges
- install a browser, SDK, command, or subscription adapter
- make missing credentials or unreachable services available
- turn manual or operator-accepted evidence into empirical replay
- guarantee completion, correctness, or safe cleanup

## Noninteractive CI

Do not generate an override reason automatically from untrusted branch or PR
content. Use a protected, reviewable configuration and a stable automation actor.
Keep unsafe jobs separate from ordinary PR jobs, restrict their runners and
environments, and retain the run manifest and receipt manifest as audit artifacts.

```bash
metisblack --config ./ci/approved-lab-run.json \
  run https://fixture.internal.example \
  --authorize --json --output ./runs/ci-fixture
```

If CLI flags activate overrides, CI must pass all three acknowledgement fields:

```bash
metisblack run "$APPROVED_FIXTURE_URL" --authorize \
  --override data-sampling,timeouts \
  --override-actor "ci:nightly-lab" \
  --override-reason "approved nightly isolated fixture" \
  --acknowledge-unsafe --json --output ./runs/nightly
```

Never interpolate a model response, target response, repository file, issue body,
or pull-request title into override controls, actor, or acknowledgement.

## Audit checklist

Before execution:

- verify written authorization, targets, time window, and cleanup ownership
- use the smallest controls and shortest run bounds possible
- isolate shell and secret-exposure runs outside the operator workstation
- inspect `--dry-run` output and the override banner

After execution:

- confirm `run-manifest.json` records actor, reason, timestamp, and exact controls
- inspect `override_history` when overrides changed during resume, retest,
  acceptance, or expert tool execution
- correlate each receipt's override provenance and run ID before interpreting it
- treat `operator_accepted` separately from empirical states
- inspect account cleanup and limitations
- restrict, retain, or securely dispose of artifacts under the engagement policy
