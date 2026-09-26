# ADR 1: The runtime owns evidence and confirmation

Accepted. Providers return typed actions and hypotheses. Only tools create
receipts; only the reproducer changes a candidate to Confirmed. Independent
re-execution is stronger than model voting, although the proof predicate must
still match the claim. Unsupported claims stay NeedsReview. Provider names and
self-reported confidence are never authority to override policy.
