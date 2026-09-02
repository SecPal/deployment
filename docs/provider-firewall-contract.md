<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: CC0-1.0
-->

# PROTECTED provider-firewall adapter contract

`scripts/provider-firewall-contract.py` is the pure, provider-neutral seam for
the PROTECTED Origin firewall policy. It owns no provider selection, credential,
customer or fleet inventory, firewall identifier, mutable provider state, or
provider API syntax. A later concrete adapter supplies those runtime inputs and
performs provider observation and mutation.

It reuses the portable provider-capability contract from [#169](https://github.com/SecPal/deployment/issues/169): separately supplied `ExecutionAuthority`, opaque provider context and exact `ResourceTarget`, source revision, adapter identity, parameter digest, and provider concurrency identity remain that contract's authority. The firewall target must be the exact authority target, must have a provider-native resource identity, and its current observation must match `ResourceTarget.expected_version` when that authority is exposed. A stale version is an error, never a last-write-wins retry. Providers without a concurrency authority leave it absent; this seam does not invent a universal ETag.

The accepted CloudFront prefix input comes only from [#214](https://github.com/SecPal/deployment/issues/214). The caller reads its `accepted` LKG boundary and supplies that document plus its exact `candidate_sha256` identity. This seam checks the closed #214 representation and identity, `CLOUDFRONT_ORIGIN_FACING` service, source URL, deterministic non-empty IPv4 and IPv6 sets, canonical CIDRs, and rejection of default routes. It does not fetch AWS ranges, inspect candidates, promote an LKG, or create acceptance provenance. The caller's #214 boundary remains responsible for proving that the document came from `accepted`, rather than `candidate`; a stale or substituted identity is rejected here.

## Bounded lifecycle

```text
provider inspect → normalize FirewallObservation → admit accepted input
→ plan exact owned rule → adapter apply with observed revision
→ fresh provider inspect → semantic verification
                         ↘ failure → exact prior-observation rollback → inspect
```

`FirewallInput` accepts only `EdgeMode.PROTECTED`, TCP, and port 443. `DIRECT`
is rejected rather than being translated into a CloudFront-only ingress policy.
The desired owned rule contains precisely the admitted IPv4 and IPv6 source
sets. Both families are mandatory; a missing family cannot create an empty or
broader policy.

`FirewallObservation` is a provider-normalized, exact-target read-back. Its
rules carry an adapter-provided opaque `rule_id` and explicit `ownership_id`.
The plan finds #215-owned rules exclusively by exact `ownership_id`; overlap,
port, description, provider object location, or resemblance are not ownership.
More than one matching owned rule fails closed. All other rules form the exact
unrelated-policy snapshot and are not deletion authority.

The plan has only two outcomes:

- `no-mutation` for the one exact desired owned rule; and
- `replace-owned` for a missing or stale owned rule.

The latter never authorizes a whole-firewall replacement. The concrete adapter
must bind its mutation to `expected_revision`, preserve every unrelated rule,
and retain the complete prior `FirewallObservation`. The adapter may use its
provider's safe update primitive, but must not remove the known-safe owned rule
before a replacement is safely recoverable.

`ApplyOutcome.APPLY_ACCEPTED` proves only that the adapter accepted its request;
it is not verification. `verify` requires fresh observation of the exact owned
TCP/443 dual-stack policy, all preserved unrelated rules, and every declared
operator-access rule identity. Extra unrelated rules or any unrelated-policy
drift fail closed rather than being silently accepted.

On an adapter mutation failure, `admit_apply_result` produces a `RollbackPlan`
whose only action is `restore-prior`. That plan holds the exact prior target,
revision, and complete normalized observation. `verify_rollback` accepts only
an identical fresh observation. The seam cannot synthesize a permissive policy,
flush a firewall, guess unrelated rules, or roll back a different/stale target.
If the adapter cannot represent that exact restore, it must report a bounded
failure diagnostic and stop.

## Adapter obligations and diagnostics

Adapters perform the side effects outside this pure module. They must emit
bounded, non-secret diagnostic codes that distinguish invalid accepted-prefix
input, target mismatch, ownership ambiguity, concurrency conflict, provider
mutation failure, verification mismatch, and rollback failure. Provider API
responses, credentials, account state, customer inventory, and mutable resource
state are not diagnostics and must not enter Git or this contract.

The contract creates no provider registry, plugin framework, provider-specific
rule DSL, schema, evidence format, or lifecycle engine. It is a portable
admission/planning boundary for a later adapter such as #216; it is not that
adapter, host nftables, fleet placement, or a provider mutation implementation.
