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
Consumers read and independently validate the candidate with `candidate`, then
acknowledge exactly its `candidate_sha256` using `accept`. A replacement candidate
therefore invalidates an acknowledgement for an older digest. Only `accept`
atomically publishes the accepted LKG. Failed fetches, parsing, validation, and
acceptance leave an existing accepted LKG untouched; when none exists they do
not manufacture an empty or permissive allowlist.

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
