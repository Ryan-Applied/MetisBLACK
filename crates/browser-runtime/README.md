# MetisBLACK browser runtime

This crate is the typed, auditable browser boundary for MetisBLACK. It speaks
the W3C WebDriver HTTP protocol directly; it never builds shell commands.

Supported portable operations include session lifecycle, navigation, element
lookup and interaction, forms, cookies, typed Web Storage operations,
screenshots, waits, and explicitly enabled raw JavaScript evaluation. Chromium
console/performance logs are capability-negotiated extensions.

Security properties:

- every top-level navigation and every URL found in captured network logs is
  checked by `metisblack-policy`;
- redirect escapes cause immediate session quarantine/closure;
- downloads are denied in requested Chrome/Firefox preferences unless both the
  runtime option and the `external_downloads` expert override are active;
- cookie, log, error, and script result data is recursively redacted;
- steps, bytes, timeouts, cancellation, and policy request/state budgets are
  enforced centrally;
- every attempted operation returns a hash-addressed `BrowserObservation`,
  including failures.

## Backend limitation

Classic WebDriver has no portable request interception primitive. A scoped
navigation can initiate subresource requests before performance logs expose
them. MetisBLACK validates all *discovered* requests and quarantines on escape,
but hard pre-request blocking requires a future WebDriver BiDi or CDP backend.
The negotiated capability record makes this limitation machine-readable.

## Serializable workflows

`BrowserPlanExecutor::execute(&BrowserPlan)` runs a validated ordered plan in a
fresh session and always closes it on success or directly quarantines/deletes it
on failure and cancellation. Plans support named element aliases, navigation,
wait/find/forms, cookies, both Web Storage areas, screenshots, logs, and
capability-gated JavaScript. The result contains ordered observations and step
outcomes, artifacts, final URL, negotiated capabilities, and cleanup status.

Use `PlanValue::Environment { name }` and `PlanArgument::Environment { name }`
for credentials. Only the environment variable name is serialized; its value is
resolved at execution time, registered with the redactor, held in zeroizing
memory, and omitted from step results. `PlanValue::Public` is an explicit
attestation that a value is safe to serialize.

For deterministic recovery, `BrowserPlan::checkpoint` authenticates a completed
prefix against the plan fingerprint. `execute_with_checkpoint` replays that
prefix in a new session to reconstruct browser state; stale cookies and element
handles are never trusted across runs.
