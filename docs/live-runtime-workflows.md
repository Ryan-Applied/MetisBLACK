# Live runtime workflows

MetisBLACK has four opt-in production-facing execution paths. They share the
run's authorization, scope, budget, cancellation, redaction, receipt, and
override policy. None of them turns model output into confirmed evidence.

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
capabilities, common receipts, and review candidates. Identity mismatch stops
enumeration.

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

All four paths can be configured in one strict `RunConfig` file. Use `--dry-run`
to inspect the resolved configuration before any target or provider I/O.

Successful cloud and model-panel stages are content-hash checkpointed and are
not repeated on resume. A failed browser, cloud, or panel stage is also latched:
ordinary `resume` fails closed rather than silently repeating external calls or
cost. After reviewing the partial receipts/audit, an operator may deliberately
retry with `resume RUN_DIR --retry-failed-stages`; that decision is recorded and
warns that already completed operations may repeat.
