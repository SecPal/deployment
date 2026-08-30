<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: CC0-1.0
-->

# Portable provider capability contract

This document defines the public technical boundary for one explicitly selected
infrastructure-provider adapter. It is subordinate to
[ADR-023](https://github.com/SecPal/.github/blob/main/docs/adr/20260824-public-self-hosting-private-managed-operations-adr023.md),
which remains the single authority for the public capability and private managed
orchestration ownership boundary. The canonical
[evidence architecture contract](https://github.com/SecPal/.github/blob/main/docs/evidence-architecture-contract.md)
continues to own observation, normalization, admission, assembly, invariant
ownership, diagnosability, and anti-loop rules.

The executable surface is the pure
[`provider-capability-contract.py`](../scripts/provider-capability-contract.py)
module. It defines one coherent request/authority/result contract and performs no
provider lookup or operation.

## Capability boundary

The closed portable provisioning operations are:

- `create`: establish the one requested infrastructure primitive;
- `inspect`: read back the one provider-native target;
- `rebuild`: replace or re-establish the one admitted target;
- `delete`: remove the one admitted target and verify exact cleanup.

An adapter may implement only a subset. Its supported operation set is supplied
explicitly to request admission. An unsupported operation fails before dispatch;
it is never guessed, translated to another operation, or inferred from a provider
name.

This operation set is not a universal external-provider interface. Firewalls,
WAF, DNS, certificates, CloudFront Viewer Edge, and other provider capabilities
retain their own contracts and operation vocabulary. They may adopt this
contract's authority, exact-target, correlation, and bounded-diagnostic pattern
without being forced into provisioning CRUD.

## One request, separate authority, bounded result

`CapabilityRequest` binds:

- one caller-generated request identity for idempotency and audit correlation;
- the exact public source revision defining the invocation;
- one explicitly selected adapter;
- one operation;
- one provider context and target; and
- the SHA-256 digest of the adapter-specific runtime parameters.

Adapter parameters remain provider-specific. A machine type, instance product,
image selector, disk class, or similar provider value may be an adapter input or
qualification fixture. It does not become a portable SecPal architecture enum.
The digest binds those inputs without copying one provider's object model into
the generic contract.

`ExecutionAuthority` is a separate runtime input. It binds one authorization
identity, adapter, exact public source revision, provider context, exact target,
allowed operation set, and credential mechanism. The mechanism is a non-secret
description such as an OIDC workload-identity path; the credential, token,
private key, account secret, and payment authority remain outside Git and outside
this contract. Possession of adapter code or a valid request does not grant
execution authority.

Request admission requires exact equality between the request and authority for
adapter, source revision, provider context, and target. It has no lookup path for
customer, fleet, preferred provider, SKU, production target, or placement policy.
The caller must select and authorize those technical inputs before invoking an
adapter.

`CapabilityResult` is correlated back to the exact request. It reports only a
closed outcome, provider-native read-back where applicable, exact cleanup state,
and an adapter-owned bounded diagnostic code. It contains no arbitrary provider
output, stdout/stderr, environment dump, or secret-bearing diagnostic text.

## Target and mutation rules

`ResourceTarget.provider` and `ResourceTarget.scope` name the provider and one
provider-native scope, such as an account/project plus region or zone. Provider
identifiers are structurally bounded but open-ended: there is no provider
registry and reviewed GCP, DigitalOcean, Hetzner, AWS, or future adapters do not
require a central enum.

`ResourceTarget.requested_key` identifies the one desired object within that
scope. It is sufficient to bound `create`, where no provider resource identity
exists yet. It is not destructive authority. `inspect`, `rebuild`, and `delete`
require the stronger provider-native resource identity returned by creation or
read-back. A name, prefix, tag search, account scan, or guessed discovery result
cannot silently broaden those operations.

Where the provider exposes a freshness token, generation, ETag, or resource
version, the adapter records it as `expected_version` and rejects stale read-back
or mutation according to its provider-specific contract. The generic boundary
does not invent a version when the provider has none.

A successful `create`, `inspect`, or `rebuild` must return the exact
provider-native resource identity. It may also return an immutable provider image
identity and resource version. An existing-target read-back that names another
resource is rejected. A successful `delete` returns no replacement observation
and must report `cleanup=complete`.

## Idempotency and failure

`already-satisfied` is the portable idempotent outcome for an authenticated
exact desired state that is safe to retain. It is valid for `create`, `rebuild`,
and `delete`; it still observes the admitted resource for create/rebuild and
still proves complete absence for delete. There is no continuation-token system,
recovery state machine, or generic lifecycle store.

`failed` and `unsupported` require a bounded adapter diagnostic code. An
unsupported result cannot imply observation or mutation. A failed mutating
operation must say whether its exact cleanup was `complete` or `incomplete`;
silence is rejected. `incomplete` remains failure and requires operator-visible
handling. The contract does not authorize account-wide cleanup, tag-prefix
deletion, fleet janitor policy, or retry loops.

For billable ephemeral qualification, technical success remains:

```text
create -> inspect / qualify -> exact delete with cleanup=complete
```

A qualification failure still proceeds to exact delete under the separately
authorized cleanup path. Existing bounded TTL janitors remain specialized
fallbacks; they do not become part of this contract.

## Existing adapter and evidence reuse

The current provider-specific implementations remain the concrete reference
examples. They are not wrapped in a new runtime:

| Existing path                  | Portable seam                                                                                                                                     | Existing provider-specific evidence                                                                  |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `infra/ci-cloud/digitalocean/` | reviewed profile selects DigitalOcean; OpenTofu apply creates; outputs and remote evidence inspect; saved exact state drives destroy              | `ci-cloud-evidence.schema.json`, exact OpenTofu state artifact, provider image and machine read-back |
| `infra/ci-cloud/gcp/`          | reviewed profile selects GCP; OpenTofu apply creates; immutable image/resource outputs inspect; saved exact state drives destroy                  | `ci-cloud-evidence.schema.json`, instance/disk/image outputs, exact OpenTofu state artifact          |
| `infra/ci-cloud/gcp-rocky/`    | WIF provider context and closed profile authorize create; continuation admission and provider read-back inspect; saved exact state drives destroy | Rocky discovery, continuation, preparation, qualification, and failure schemas                       |

These qualification paths do not currently expose a rebuild operation. A
portable invocation against them must therefore treat rebuild as unsupported
rather than approximating it. Their provider products, fixed regions, and machine
profiles remain reviewed qualification inputs and evidence, not portable
architecture vocabulary or production placement policy.

Existing evidence schemas remain authoritative at their actual wire and
persistence boundaries. In particular, Rocky discovery records the immutable
provider image, continuation binds the exact provider resource and target SHA,
and qualification records the admitted result. The portable result may carry the
same resource/image read-back needed for immediate target correlation; it does
not define a new evidence document, taxonomy, or provenance format.

A reviewed adapter is qualified by repository tests for request/authority/result
agreement plus the provider-specific real-system evidence its own promised seams
require. Repository-authored tests prove this portable contract. They do not
replace real provider evidence for an adapter that claims a real provider
outcome.

## Public and private ownership

Public repositories may contain provider API integration, provider-specific
adapters, immutable provider/image/resource evidence, and bounded technical
diagnostics. Provider-specific implementation is not inherently confidential.

The public capability must not contain or retrieve:

- customer identity or inventory;
- fleet desired/observed state;
- provider or SKU selection and placement policy;
- procurement, pricing, margin, or reserve policy;
- rollout waves, commercial lifecycle, or customer lifecycle;
- provider account/payment credentials or mutable confidential production state.

Private managed orchestration may choose a provider and concrete parameters,
obtain separate authority, and invoke a reviewed public adapter. It consumes this
technical boundary; it does not duplicate provider mechanics or make its policy
available to the adapter.

## Simplification accounting

```text
NEW_PERMANENT_CONCEPT: one provider-capability request/authority/result contract
REPLACES: the shared lifecycle safety boundary previously implicit across provider-specific paths
WHY_EXISTING_CONTRACT_CANNOT_ABSORB_IT: existing schemas record qualification-stage evidence but do not authorize or correlate portable adapter execution

NEW_PERMANENT_CONCEPTS: 1
EXISTING_CONCEPTS_GENERALIZED: explicit provider context, target identity, operation, read-back, and exact cleanup
DUPLICATED_CONCEPTS_REMOVED: 0 (existing provider implementations remain provider-specific)
NEW_SCHEMAS: 0
NEW_STATE_MACHINES: 0
NEW_PROVIDER_REGISTRIES: 0
NEW_EVIDENCE_TYPES: 0
```
