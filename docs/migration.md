# Migration

Build and run inside `MetisBLACK`. Existing legacy NeuroSploit configuration,
credentials, installed binary, `.neurosploit` state and historical runs are never rewritten.

Use `metisblack agents import ../agents_md --output ./playbooks` to create a
versioned catalog. Import preserves legacy prose as untrusted methodology and
records warnings for malformed legacy documents. IDs are category-qualified.
Use `metisblack agents validate ./playbooks` before enabling that catalog.

The shipped `playbooks/legacy` catalog contains 435 imported playbooks in seven
categories. Its upstream methodology retains the original MIT notice in `LICENSE`.
`meta/role_pentestfull` has a preserved incomplete-heading warning. Passing
`--playbooks playbooks/legacy` loads it alongside nine built-in specialists;
restricted entries remain ineligible unless explicitly overridden.

Create a version-1 JSON policy/config; old ad-hoc credential YAML must be converted
to secret references. Do not copy passwords into the new config. Old findings are
historical claims, not confirmed findings: their tool text cannot be promoted to
runtime receipts. Reassess to obtain verifiable evidence.

New reports use explicit state and severity enums. CI should gate `confirmed` or
`retested_present` findings, and PR gates additionally require `introduced=true`.
Subscription flags and automatic tool installation are deliberately unsupported.

The CI workflows live under this new directory for a standalone repository.
GitHub only discovers root `.github/workflows`; until this directory becomes a
repository root, the existing outer release-only workflow remains unchanged.
