# Threat model

Assets: operator secrets, authorized targets, local files, provider credentials,
evidence integrity, findings and CI decisions. Adversaries include target content,
repository authors, malicious model responses and hostile imported playbooks.

Boundaries and controls:

- Model to runtime: typed tool enumeration, deny unknown fields, per-operation
  policy, no arbitrary shell by default, no typed ability to write receipt stores.
- Network: explicit hostname/port/path scopes, exclusion precedence, checked DNS,
  pinned resolutions, disabled environment proxies, checked redirects, bounded
  requests/responses, no inherited cookies or cross-origin credentials.
- Filesystem: canonical-root checks, symlink rejection, no source execution,
  bounded UTF-8 reads, secret-path exclusions, immutable source hashes.
- Evidence: harness-generated identifiers, content hashes, run/actor correlation,
  independent replay and narrow deterministic claim predicates.
- Secrets: opaque references, authenticated encryption, restrictive permissions,
  redaction at capture and report boundaries, no secrets in command arguments.
- Budgets: a shared atomic reservation per operation; account creation and other
  state changes require operator policy and cannot be enabled by model text.
- Integrations: explicit publication and redacted payloads, confirmed-only gates.

Residual risks: redaction is best-effort for unknown secret formats; malicious
targets may include PII in ordinary responses. Keep evidence retention short.
Prompt separation cannot guarantee that a model ignores injected prose; enforce
the resulting action and finding boundaries in code. Hashes detect corruption,
not tampering by an actor who controls the local account and can rewrite both
records and hashes. Local administrators can read process memory and vault keys.
HTTP GET can cause changes on poorly designed servers; authorization must cover
the permitted endpoints. No production-safety claim follows from a read-only verb.

Expert overrides are an explicit second trust tier. Every operational control has
a named override; `--unsafe-all` expands the entire set. Actor, meaningful reason,
acknowledgement, timestamp and disabled controls are preserved in run history,
action audit records and receipts. The CLI displays a prominent warning. Neither
an override nor `--authorize` creates legal authorization. Model arguments cannot
activate either. Integrity/schema constraints (for example authentic receipt IDs)
remain invariants, not policy restrictions to fabricate evidence around.

An expert may explicitly enable unsandboxed arbitrary subprocesses by overriding
tool capabilities, sandbox, network and filesystem-root boundaries, plus command
risk/class controls and the applicable state-change budget. These subprocesses run
with the user's OS authority and can defeat every application-level boundary,
including modifying receipts or vault material accessible to that identity. Output
capture is not containment. Environment inheritance and raw secret capture require
their separate controls. Arbitrary subscription CLI execution may use this route,
but no native subscription adapter or sandbox assurance is claimed. Do not pass
production credentials to an untrusted child or treat unsafe-run evidence as
equivalent assurance to default typed execution.

Explicit finding acceptance yields `OperatorAccepted`, not `Confirmed`. Missing,
foreign or rejected evidence cannot be accepted. Default CI excludes this state;
including it is an additional operator choice. Secret redaction and data budgets
can themselves be disabled, potentially exposing credentials or exhausting local
and remote resources. Provider and integration egress also honors applicable
network, URL-secret, redirection, timeout and redaction controls.

A future
browser must intercept every request, popup, websocket, download and service-worker
request; a navigation-only allowlist is insufficient.
