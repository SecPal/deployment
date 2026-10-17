<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Portable endpoint switching

Owner: [#170](https://github.com/SecPal/deployment/issues/170). Callable contract:
`scripts/endpoint_switch.py`, version 1. This is a bounded adapter port, not an
installer, provider selector, credential broker or BLUE/GREEN orchestrator.

[ADR-023](https://github.com/SecPal/.github/blob/main/docs/adr/20260824-public-self-hosting-private-managed-operations-adr023.md)
permits reviewed public provider implementations. Provider API integration is
not inherently private. Managed customer/fleet inventory, placement, commercial
selection, rollout policy, credentials and mutable confidential state remain
outside this public repository.

## Data and authority

`Endpoint` reuses the existing `ResourceTarget` provider/context/native-resource
identity and adds Deployment Identity. An exact native resource ID is mandatory.
Its `expected_version` must be null: one observed `RoutingState.generation` owns the
endpoint precondition. Provider names are runtime adapter details.

`RoutingState` contains that independently authenticated endpoint identity, an
opaque non-reusable native generation, one exact routing target, the SHA-256 of
the canonical unchanged exposure projection, and the correlated operation ID
when independently observable. The projection includes every relevant listener,
port, protocol, network/resource attachment, admission rule and other unchanged
provider setting. It excludes only the permitted routing-target change and its
native operation/version metadata. Adapter qualification owns the native mapping;
a requester-supplied digest is not evidence of provider state.

`plan(operation_id, current, target, intent=Intent.SWITCH)` constructs an immutable
`SwitchPlan` without IO or authority. It changes exactly one logical endpoint,
never a fleet, arbitrary resource list or infrastructure command. Its complete
before-state, target and intent must be bound to the operation ID.

Trusted construction supplies these separate ports:

| Port                                    | Responsibility                                                                                                                                                                                                    |
| --------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Observer.observe(endpoint)`            | Fresh authenticated native routing read, independent of mutation responses and recursive DNS caches. Return actual provider scope, never echo the request.                                                        |
| `Adapter.validate(plan)`                | Pure exact-resource/candidate mapping admission; reject unsupported or unbounded mutations.                                                                                                                       |
| `Adapter.compare_and_switch(plan)`      | Atomically compare the complete expected routing state/generation and change only the admitted target. Return `APPLIED`, definite no-mutation `REJECTED`, or `UNKNOWN`.                                           |
| `CutoverAuthority.authorize(plan)`      | Fresh owner admission of the exact deployment, resource, target, operation and intent, including current GREEN/fencing/reversal authority. Raise to deny.                                                         |
| `CutoverAuthority.claim_dispatch(plan)` | Atomically reauthorize and persist the exact dispatch intent in the cutover owner's existing state before any provider mutation. Return true once; false for an already claimed identical plan. Reject rebinding. |

The authority is a trusted in-process integration, never a request callback,
caller readiness flag, cached certificate or reachability assertion. The atomic
claim must survive crashes, concurrent coordinators and authority restoration;
it cannot be an in-memory set or an expiring lock that silently permits replay.
An ambiguous claim causes uncertainty and no provider dispatch.

The #170 contract stores no endpoint database, operation journal or permanent process.
The existing cutover owner supplies its own durable intent/serialization boundary;
this interface neither specifies a new storage format nor grants new authority.
Provider credentials stay with the selected narrowly scoped adapter. A separate
read-only observer credential is preferred where supported.

## Execution and uncertainty

`execute(plan, adapter, observer, authority)` admits the candidate, independently
reads the current endpoint, and rejects stale scope/state before dispatch.
A previously committed exact operation returns `ALREADY_SATISFIED` without another
write. Otherwise, only the first successfully claimed intent can dispatch.
Previously claimed attempts go to read-only reconciliation, even if routing still
looks unchanged. No timeout or lost acknowledgement causes a blind replay.

After the provider call, a fresh authoritative observation must show the exact
endpoint, target, unchanged exposure, a different non-reusable generation and
the same operation identity. Only this read-back can establish `APPLIED`; a
successful API response cannot. A lost success acknowledgement can be recovered
from that independently correlated observation. A malformed acknowledgement
grants no authority; only complete read-back can resolve it.

`assess` is pure result admission. Its bounded outcomes are:

- `APPLIED`: the exact admitted routing change is independently observed.
- `ALREADY_SATISFIED`: that same operation is already independently observed.
- `REJECTED`: admission/preconditions failed or the provider definitively rejected
  mutation. A concurrent winner does not authorize this request.
- `UNCERTAIN`: observation, dispatch claim or provider completion is unavailable.
  An unchanged route does not prove an asynchronous operation cannot commit later.
- `RECOVERY_REQUIRED`: changed exposure, wrong post-apply identity, contradictory
  results or uncorrelated/mismatched routing require the owner's recovery decision.

`reconcile(plan, observer, authority)` never invokes an adapter mutation, resets
an intent or grants retry permission. Results contain fixed diagnostic codes,
not raw provider errors, commands, tokens or logs. Returned routing observations
are private runtime facts and must not be dumped into public evidence.

## Replacement, HA and security ownership

[#130](https://github.com/SecPal/deployment/issues/130) prepares GREEN without
production routing or writer authority. [#131](https://github.com/SecPal/deployment/issues/131)
owns current readiness/RecoverySet validation, BLUE fencing, GREEN promotion,
workload activation and admission of this routing operation, followed by #115
acceptance. [#132](https://github.com/SecPal/deployment/issues/132) owns end-to-end
replacement qualification. HA consumers must supply their corresponding fenced
authority rather than deriving it from endpoint status.

An explicit `PRE_WRITE_REVERSAL` is a new operation against current endpoint
state and requires the cutover owner's fresh proof that reversal is safe. Once
GREEN accepted authoritative writes, stale BLUE is not a generic rollback target
even if a caller relabels the request as a forward switch. The owner must reject
that target/intent or use its accepted forward-fix, reseed/rejoin or RecoverySet
path. This library never automatically restores BLUE on failure.

Routing does not inspect, grant, promote, revoke or prove PostgreSQL writer
authority. #82/#135 topology contracts remain unchanged. #219/#220 own HAProxy
runtime/identity; #209 owns PROTECTED Origin authority; #215/#216 own provider
firewalls; #104 owns host nftables. Switching an endpoint cannot widen any of
those controls or substitute for their acceptance.

## Public adapter mappings

| Mechanism                 | Qualification requirement                                                                                                                                                                                       |
| ------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Load-balancer targets     | Exact listener/service identity, conditional target revision, unchanged listeners/ports/admission and authoritative operation-correlated target read-back.                                                      |
| Floating/reserved address | Exact address resource and old/new attachment identities, conditional reassignment and independent read-back; no other IP, network or host is reassigned.                                                       |
| Authenticated DNS         | Exact zone/record-set authority, conditional authoritative revision, bounded record-value change and independently correlated authoritative read-back. Recursive propagation is separate availability evidence. |

A concrete provider may lack a required atomic precondition, non-reusable
generation, operation correlation or authoritative read consistency. Its adapter
must reject unsupported dispatch or report uncertainty/recovery; it must not
emulate these guarantees with an unlocked read-then-write, a local cache, a
best-effort tag update or an unqualified provider label. Partial operations never
become success merely because one target responds. No provider product, customer
inventory or Managed rollout mechanism is required by the public interface.

## Qualification envelope

`python3 tests/endpoint-switch.py` runs in existing preflight. It exercises the
full port with a disposable test-only SQLite routing register and synthetic
cutover authority. Two independent processes prove native conditional mutation;
durable owner claims prevent redispatch after interruption/restart. Cases cover
wrong scope/resource/target, stale state, exposure/read-back mismatch, lost and
malformed acknowledgements, reversal admission and unchanged writer state.

This is genuine local SQLite persistence/concurrency evidence and synthetic
provider/owner integration. It does not route public traffic, qualify a DNS/IP/LB
product, prove #131 PostgreSQL fencing, or establish replacement/HA acceptance.
Live provider qualification belongs to each concrete adapter's explicitly
authorized evidence envelope. #170's interface acceptance requires no provider
credentials, live resource, selected product or private Managed inventory.
