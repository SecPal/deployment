<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: CC0-1.0
-->

# PROTECTED provider-firewall adapter contract

`scripts/provider-firewall-contract.py` is the provider-neutral, ownership-scoped
seam for PROTECTED Origin firewall policy. It owns no provider selection,
credential, customer or fleet inventory, live firewall identity, mutable provider
state, provider API syntax, or concrete provider mutation. A later adapter such
as #216 supplies those runtime facts and effects.

## Existing authorities

The seam consumes the accepted CloudFront Origin prefix state only by calling
`read_lkg(state_directory)` from the authoritative
`scripts/cloudfront-origin-prefix-lkg.py` implementation delivered by #214.
Raw dictionaries and caller-computed digests are not prefix authority. #214
continues to own source observation, candidate validation, publication ordering,
explicit acceptance, safe state storage, and accepted-LKG reads. #215 copies
only the resulting IPv4 and IPv6 strings into immutable semantic policy values.

Every provider observation, mutation, result, and rollback reuses #169:

- observation is `Operation.INSPECT`;
- owned-policy reconciliation and rollback are `Operation.REBUILD`;
- `admit_request()` checks the separately supplied `ExecutionAuthority`,
  supported operation, adapter, source revision, exact target, and parameter
  digest; and
- `admit_result()` checks exact request/result correlation before #215 uses
  provider evidence.

The mutation parameter digest binds PROTECTED mode, exact target and observed
revision, accepted #214 identity, TCP/443 desired policy, adapter/source identity,
the authenticated prior owned slice, required operator-access identities, and
the opaque preserved-state identity. A record constructor is data transport, not
authority; public mutation and verification functions always repeat the #169
admission appropriate to their phase.

## Ownership-scoped observation

`FirewallObservation` is one adapter-produced, #169-correlated complete provider
read whose correlated result is explicitly OBSERVED. Failed or unsupported
INSPECT results are never provider-state authority. Provider-supplied identities are
bounded by the #169 UTF-8 identity limit. Its closed ownership scope distinguishes at most one #215-owned Origin
slice from required operator access and all other provider-native state.
Ownership is never caller supplied or inferred from protocol, port, prefixes,
name, description, position, or semantic resemblance. A provider rule cannot be
both #215-owned and operator access.

Issue #215 normalizes only the owned ingress semantics needed by this contract:
protocol, port, and canonical IPv4/IPv6 sources. Provider-native rule identity is
separate and may change across create, update, or rollback. The desired policy is
exactly TCP 443 from the accepted dual-stack #214 prefix set.

The adapter supplies one deterministic SHA-256 identity for the complete
non-owned provider policy, including required operator-access state and any
provider-native rule types #215 does not model. The adapter must compute that
identity from one complete provider read. Missing completeness, ambiguous owned
state, malformed owned semantics, ownership/operator overlap, or non-owned state
identity drift fails closed. This keeps core patch-like and ownership bounded
without inventing a generic provider firewall DSL.

An empty operator-access tuple means the adapter's complete read found no rules
classified as required operator access. It never grants #215 ownership of those
rules. Providers that internally require replacement must retain every
unmodelled provider-native field when implementing the ownership-bounded
operation; an incomplete projection is never a replacement payload.

## Plan, apply, verification, and recovery

`plan()` has two outcomes:

- `NO_MUTATION` when the one authenticated owned slice is semantically equal to
  the desired policy, regardless of its provider-native rule ID; and
- `REPLACE_OWNED` when that slice is absent or semantically stale.

A plan alone authorizes no write. `build_mutation_request()` produces the
correlated #169 REBUILD request only when a separately supplied authority matches
the complete mutation digest and the current observation supplied a non-empty
revision. Missing or stale concurrency authority has no write fallback.

Every mutation result, including APPLIED, ALREADY_SATISFIED, FAILED, UNSUPPORTED,
or an incomplete-cleanup failure, requires a fresh correlated INSPECT. Apply
acceptance is never verification. Verification requires the exact desired owned
semantics, the same non-owned provider-state identity, the same operator-access
identities, exact provider target, adapter, and source revision. A new
provider-native owned rule ID is valid. Each post-mutation inspection parameter
digest binds the exact preceding #169 mutation request; each post-rollback digest
similarly binds its exact rollback request, preventing same-resource replay across
transactions while allowing provider revisions to advance.

Failure or uncertainty never directly creates rollback authority. The fresh
post-mutation read is classified first. For results that guarantee no retained
mutation effect (UNSUPPORTED, ALREADY_SATISFIED, or FAILED with complete cleanup),
only the prior safe semantics may yield PRIOR_VERIFIED; any different state is
concurrent provider drift and fails closed without automatic rollback or invented
causality. For results that can retain mutation effects:

- desired semantics present: desired state is verified;
- prior owned semantics present: recovery is already satisfied;
- changed but representable owned semantics: rollback may be planned; or
- incomplete, ambiguous, wrong-target, non-owned/operator drift, or missing
  revision: fail closed.

A rollback REBUILD request is bound to the fresh post-failure revision and the
prior owned semantics. Its result also requires a fresh INSPECT. Rollback
verification accepts a naturally advanced provider revision and a newly assigned
provider rule ID, while requiring the prior owned semantics, exact target,
operator access, and opaque non-owned state identity to remain intact.

The adapter operation is one ownership-bounded logical operation. A concrete
adapter that needs multiple provider-native writes owns their internal ordering,
partial-state diagnosis, and safe recovery; it must return #169 cleanup semantics
and cannot claim completion until the complete ownership-scoped observation is
available.

The contract adds no provider registry, plugin system, generic policy DSL,
second provider authority, evidence architecture, schema, runtime dependency, or
provider-specific behavior.
