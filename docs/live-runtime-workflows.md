# Live runtime workflows

MetisBLACK has several opt-in live execution paths. They share the run's
authorization, scope, budget, cancellation, redaction, receipt, and override
policy. None of them turns model output into confirmed evidence.

## Bounded web discovery and open-redirect validation

Black-box and grey-box runs create a finite default discovery plan from the target.
For explicit seeds, allowed origins and bounds, pass the strict versioned example:

```bash
metisblack run http://127.0.0.1:8080/ \
  --discovery-plan examples/web-discovery-plan.json \
  --authorize --output runs/web-discovery
```

Each frontier item is a typed `WebDiscoveryFetch`: central URL/DNS/private-address,
authorization, request/rate/concurrency/timeout and response bounds apply, and the
plan's exact allowed origins are an additional non-bypassable acquisition boundary.
The fetch records one response with redirects disabled. The deterministic parser
can derive same-plan-origin HTML links and scripts, form shapes without values,
robots and sitemap entries, bounded JavaScript URL hints, and OpenAPI v2/v3
declarations. It never executes JavaScript, submits a form, follows a redirect,
resolves a remote schema reference, or invokes a declared API operation.

The run stores `plan.json`, an atomic `checkpoint.json`, `artifact.json` and
`stage.json` under `web-discovery/<plan-hash>/`. Observed, declared and omitted
surfaces are distinct and carry plan or receipt lineage. Before completion the
orchestrator reconstructs the artifact from the sealed receipts and compares the
canonical result. Reports expose the sanitized artifact path/hash/counts/gaps as a
run decision; discovery alone creates no vulnerability finding or chain edge.
Before every request the run stores a durable operation intent. On restart an
exact sealed receipt is recovered without another request; an unresolved pending
intent is recorded as indeterminate and never silently retried.

Bounds above the defaults require the audited `data_sampling` override, but still
cannot exceed the schema's finite ceilings. The example plan points to an owned
loopback fixture; replace both its seeds/origin and the command target together for
an authorized lab.

For discovered URLs that already contain query parameters, the orchestrator can
run a bounded open-redirect check (three parameter probes by default, at most 20
with the sampling override). The typed action replaces one parameter with a fresh
opaque `https://metisblack.invalid/` canary, sends one GET, and captures the first
response without following the redirect or resolving/contacting the destination.
Acquisition success is not a finding. The harness requires an allowed redirect
status and exact canary `Location`, then independently replays with another fresh
canary before confirmation. Retest likewise uses a fresh canary; transport or
malformed-response failures remain inconclusive. This validates only server-side
arbitrary redirect semantics, not phishing, OAuth theft, account takeover, XSS,
SSRF or a broader exploit chain.

An indeterminate probe records a failed stage and makes no negative coverage
claim. Resume fails closed until an operator explicitly selects
`--retry-failed-stages`; that one-shot audited decision permits one fresh-canary
attempt. A positive stage is completed only after the finding is persisted.

## Receipt-backed API response-contract validation

API validation is opt-in and requires the exact discovery plan that supplied the
OpenAPI receipt:

```bash
metisblack run http://127.0.0.1:8080/ \
  --discovery-plan examples/web-discovery-plan.json \
  --api-validation-plan examples/api-validation-plan.json \
  --authorize --output runs/api-contract
```

The API plan binds the discovery-plan fingerprint and exact source URL, method,
path and optional `operationId`. Only concrete, anonymously accessible,
input-free `GET`, `HEAD` and `OPTIONS` declarations are eligible. Authentication,
required parameters or request bodies, server/path variables, mutation methods,
remote references and selected unsupported constructs fail closed; no weaker
request is substituted.

The orchestrator reconstructs the contract from the sealed discovery receipt and
persists an exact action intent before each primary or replay request. The typed
runtime performs one checked-and-pinned DNS request with environment proxies and
redirects disabled and no credentials or cookie jar. Receipts contain no response
scalar values: only the status, normalized media type, sanitized header names,
body-prefix hash and a bounded JSON shape. Transient statuses, undeclared statuses,
malformed/truncated bodies, unsupported schemas and structural truncation are
inconclusive. A low-severity contract finding requires a distinct replay receipt
with the same verified contract, status, media type and canonical structural
violation. It proves response/declaration inconsistency only and is excluded from
attack-chain facts.

The example plan assumes the owned loopback document declares `GET /health` and
`operationId: health`, and is fingerprint-bound to
`examples/web-discovery-plan.json`; change and re-hash the plans together for
another authorized lab. Contract-normalization or probe failures create an
explicit no-coverage failed stage and are never repeated automatically; a resume
with `--retry-failed-stages` authorizes one audited fresh attempt. Standalone API
retests use their own durable exact-action intents and recover a sealed receipt or
record an indeterminate no-repeat outcome after a crash. Authenticated roles, authorization
differentials, GraphQL execution and state-changing CRUD require later typed
stories with credential isolation and verified cleanup.

## Browser automation

Start a W3C WebDriver endpoint (ChromeDriver, GeckoDriver, SafariDriver, or a
compatible grid), then run:

```bash
metisblack browser https://app.example.test \
  --webdriver http://127.0.0.1:9515 \
  --browser chrome --authorize --output runs/browser
```

Without `--plan`, the orchestrator navigates, captures cookies, and takes a
screenshot. A plan adds form, storage, log, wait, and scripted workflows:

```json
{
  "schema_version": 1,
  "name": "authenticated-observation",
  "actor": "browser-plan",
  "session": {
    "browser": "chrome",
    "headless": true,
    "accept_insecure_certificates": false,
    "additional_capabilities": {}
  },
  "steps": [
    {"id":"open","action":{"action":"navigate","url":"https://app.example.test/login"}},
    {"id":"email","action":{"action":"fill","locator":{"strategy":"css","value":"input[name=email]"},"value":{"source":"environment","name":"METIS_TEST_EMAIL"}}},
    {"id":"password","action":{"action":"fill","locator":{"strategy":"css","value":"input[name=password]"},"value":{"source":"environment","name":"METIS_TEST_PASSWORD"}}},
    {"id":"button","action":{"action":"find","locator":{"strategy":"css","value":"button[type=submit]"},"alias":"submit"}},
    {"id":"submit","action":{"action":"click","alias":"submit"}},
    {"id":"evidence","action":{"action":"screenshot"}},
    {"id":"network","action":{"action":"network_logs"}}
  ]
}
```

Pass it with `--plan browser-plan.json`. Environment-backed values are resolved
only during execution. Downloads additionally require `--allow-downloads` and
the `external-downloads` expert override. Raw JavaScript requires
`--allow-raw-javascript`. Classic WebDriver cannot guarantee pre-request
interception; discovered subresource scope escapes are detected from performance
logs and quarantine the session.

For role-separated authorization evidence, pass the versioned workflow in
`examples/browser-authenticated-workflow.json` with `--workflow` instead of
`--plan`. Each role gets a new session and a distinct mapping from logical plan
secret names to runtime resolver keys:

```bash
export METISBLACK_ADMIN_PASSWORD='from-a-secret-store'
export METISBLACK_VIEWER_PASSWORD='from-a-secret-store'
metisblack browser https://app.example.test \
  --webdriver http://127.0.0.1:9515 \
  --workflow examples/browser-authenticated-workflow.json \
  --authorize --output runs/browser-roles \
  --override state_changes \
  --override-actor assessor@example.test \
  --override-reason "authorized role-login workflow" \
  --acknowledge-unsafe
```

An engagement config can set a finite `scope.max_state_changes` instead of using
the explicit override. The saved comparison contains role labels and observation/
artifact hashes only. It is evidence for a later authorization correlator, not an
automatic IDOR or privilege-boundary verdict.

## Live cloud workflows

The cloud runtime invokes installed provider CLIs with direct argv (never a
shell), verifies the active identity before enumeration, and admits only a typed
read-only operation catalogue. This AWS plan shows the shape:

```json
{
  "scope": {
    "provider": "aws",
    "accounts": [{
      "expected": {
        "account_id": "111111111111",
        "arn": "arn:aws:iam::111111111111:role/SecurityAudit",
        "user_id": null
      },
      "credential_context": "prod-audit",
      "profile": "prod-audit",
      "regions": ["ap-southeast-2"]
    }]
  },
  "credentials": {
    "prod-audit": {
      "provider": "aws",
      "variables": {
        "AWS_ACCESS_KEY_ID": "METIS_AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY": "METIS_AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN": "METIS_AWS_SESSION_TOKEN"
      }
    }
  }
}
```

The map values are host environment-variable names, not secrets. Run:

```bash
metisblack cloud-live cloud-plan.json --authorize --output runs/cloud-live
```

Equivalent typed scopes exist for Azure subscriptions and GCP projects. Results
include verified identities, normalized assets/IAM, command audits, unsupported
capabilities, common receipts, review candidates, and `cloud-iam-graph.json`.
Only IAM relationships whose provider audit IDs resolve to immutable common
receipts are traversable. Missing effective permissions, group membership and
unapproved boundary crossings remain explicit non-traversable gaps. Identity
mismatch stops enumeration.

## Heterogeneous model validation

Pass a panel file to any assessment with `--model-panel panel.json`:

```json
{
  "quorum": 2,
  "acceptance_ratio_millis": 600,
  "members": [
    {
      "id": "candidate-openai",
      "role": "candidate",
      "deployment": "primary",
      "provider": {"kind":"openai","model":"MODEL_ID","endpoint":"https://api.openai.com/v1","key_env":"OPENAI_API_KEY","timeout_seconds":60,"max_output_tokens":4096},
      "max_input_tokens": 32000,
      "max_output_tokens": 4096,
      "max_cost_microusd": 250000,
      "input_cost_microusd_per_million_tokens": 5000000,
      "output_cost_microusd_per_million_tokens": 15000000,
      "timeout_seconds": 60,
      "weight_millis": 1000
    },
    {
      "id": "review-anthropic",
      "role": "reviewer",
      "deployment": "independent",
      "provider": {"kind":"anthropic","model":"MODEL_ID","endpoint":"https://api.anthropic.com","key_env":"ANTHROPIC_API_KEY","timeout_seconds":60,"max_output_tokens":4096},
      "max_input_tokens": 32000,
      "max_output_tokens": 4096,
      "max_cost_microusd": 250000,
      "input_cost_microusd_per_million_tokens": 5000000,
      "output_cost_microusd_per_million_tokens": 15000000,
      "timeout_seconds": 60,
      "weight_millis": 1000
    }
  ]
}
```

The panel rejects duplicate provider/model/deployment identities and panels that
only masquerade as heterogeneous. Members get fresh contexts and independent
token, cost, timeout, retry, and authorization budgets. Because native provider
cost telemetry is not yet available, each member must configure at least one
positive micro-USD-per-million-token fallback rate. Fabricated receipt IDs
are rejected. Quorum promotes a candidate only into the ordinary harness
validation path; it never creates empirical confirmation.

## Typed exploit-chain catalogue

Enable the built-in web, auth, API, source, host, AI, and cloud templates with:

```json
{
  "enabled": true,
  "template_ids": [],
  "max_risk": "low",
  "max_steps": 40,
  "max_state_changes": 0
}
```

```bash
metisblack run https://app.example.test --authorize \
  --chains chains.json --output runs/chains
```

Templates are inert until receipt-derived facts, capabilities, scope, and risk
budgets all match. Execution uses explicit DAG edges, pre/postconditions,
receipt dependencies, independent replay, deduplication, atomic checkpoints,
branching/backtracking, and a rollback ledger. `chains/attack-graphs.json` records
the result. Cloud templates currently remain disabled in the shared orchestrator
unless a typed provider-specific replay adapter is registered; live cloud
discovery is not silently treated as exploit authorization.

These paths can be configured in one strict `RunConfig` file. Use `--dry-run`
to inspect the resolved configuration before any target or provider I/O.

Successful cloud and model-panel stages are content-hash checkpointed and are
not repeated on resume. A failed browser, cloud, or panel stage is also latched:
ordinary `resume` fails closed rather than silently repeating external calls or
cost. After reviewing the partial receipts/audit, an operator may deliberately
retry with `resume RUN_DIR --retry-failed-stages`; that decision is recorded and
warns that already completed operations may repeat.
