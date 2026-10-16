<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: CC0-1.0
-->

# CloudFront Origin prefix last-known-good source

`scripts/cloudfront-origin-prefix-lkg.py` is the portable, fail-closed source
for the AWS `CLOUDFRONT_ORIGIN_FACING` IPv4 and IPv6 prefix contract required by
PROTECTED Origin network lockdown. Its only source authority is
`https://ip-ranges.amazonaws.com/ip-ranges.json`, retrieved with the Python
standard library's normal HTTPS certificate and hostname verification. Redirects
and oversized, malformed, incomplete, ambiguous, default-route, or empty-family
documents are rejected.

AWS `syncToken` is admitted as a positive Unix publication time and must name
the same UTC instant as `createDate`. A publication up to five minutes ahead of
the local retrieval clock is tolerated; a greater contradiction is rejected.
No maximum source age is imposed. JSON decoding rejects duplicate keys and the
non-standard `NaN` and infinity constants.

The runtime state directory is deliberately outside Git and must be an absolute,
private directory owned by the invoking operator. It contains only non-secret
candidate and accepted prefix documents plus a lock; it contains no provider
credentials, firewall state, customer data, or desired fleet state. An operator
chooses the deployment-specific path, for example a private subdirectory under
the deployment-state authority.

The lifecycle is deliberately separated:

```text
AWS observation → source validation → service normalization → candidate
→ consumer validation → exact digest acknowledgement → atomic accepted LKG
```

`fetch` can replace `candidate.json`, but cannot alter `accepted-lkg.json`.
It is deliberately silent after publication so stdout failure cannot obscure
the persistent commit result; `candidate` is the separate validated readback.
Consumers read and independently validate the candidate with `candidate`, then
acknowledge exactly its `candidate_sha256` using `accept`. A replacement candidate
therefore invalidates an acknowledgement for an older digest. Only `accept`
atomically publishes the accepted LKG. Every fetch, parsing, validation, or
acceptance failure before the publication commit point leaves an existing
accepted LKG untouched; when none exists such a failure does not manufacture an
empty or permissive allowlist.

State operations use an exclusive lock with a two-second monotonic deadline.
State-directory creation is limited to the final component, whose parent entry
is synchronized before publication. An older AWS publication cannot replace an
accepted LKG. The same publication and normalized provider content may be
accepted again (for example after a later retrieval); conflicting content under
the same publication identity is rejected. These version checks and the exact
digest acknowledgement occur inside the same lock.

Atomic rename is the publication commit point. Every failure before that rename
returns exit status `1` and leaves the previous target unchanged. Successful
rename followed by successful directory synchronization returns `0`. If the
rename succeeds but directory durability confirmation fails, the target has
committed in the running system but crash durability is unconfirmed: the command
returns `2`, emits `COMMITTED_DURABILITY_UNCONFIRMED`, and requires authoritative
readback with `candidate` or `accepted`. This outcome is never reported as a
definite pre-commit failure, even if the diagnostic stream is unavailable.

```bash
scripts/cloudfront-origin-prefix-lkg.py --state-dir /private/runtime/state fetch
scripts/cloudfront-origin-prefix-lkg.py --state-dir /private/runtime/state candidate
scripts/cloudfront-origin-prefix-lkg.py --state-dir /private/runtime/state accept \
  --candidate-sha256 <candidate-sha256-validated-by-consumer>
scripts/cloudfront-origin-prefix-lkg.py --state-dir /private/runtime/state accepted
```

This interface has no provider, firewall, nftables, AWS-IAM, or infrastructure
mutation authority. Downstream adapters own any controlled rule validation and
mutation separately.
