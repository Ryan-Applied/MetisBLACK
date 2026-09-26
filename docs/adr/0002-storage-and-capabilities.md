# ADR 2: Explicit capabilities and atomic record storage

Accepted. Use cached stable dependencies and atomic JSON snapshots plus immutable
content-addressed evidence initially. This preserves inspectability and offline
builds without introducing a database migration surface. SQLite can replace the
index behind the storage API when query volume warrants it; blobs remain files.

AES-256-GCM via ring protects vault entries with random nonces and a protected
local key. This protects accidental artifact disclosure, not a compromised user.
Browser and native subscription execution are unavailable. There is no implicit
fallback. Deliberate expert overrides may expose an unsandboxed subprocess route,
including an installed subscription CLI. This is a distinct lower-assurance tier,
requires explicit actor/reason/acknowledgement, and cannot be represented as scoped
OS sandbox execution. Per-action audit trails explain the exact disabled controls.
Read-only cloud snapshots are supported separately
from live cloud SDK access, which needs account-bound credentials and real fixtures.
