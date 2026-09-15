<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: CC0-1.0
-->

# PROTECTED CloudFront Viewer Edge lifecycle

This contract implements the CloudFront Multi-Tenant Viewer Edge portion of
[ADR-019](https://github.com/SecPal/.github/blob/main/docs/adr/20260824-production-edge-layered-security-adr019.md).
ADR-019 remains the sole architecture authority. This contract does not define
another Edge mode or make the retired Sandbox PoC an implementation dependency.

The executable surface is the pure
[`cloudfront-viewer-edge.py`](../scripts/cloudfront-viewer-edge.py) module. It
constructs typed lifecycle requests, normalizes reviewed AWS response shapes,
admits exact observations, and plans exact AWS SDK operations. It performs no
network access, credential loading, provider selection, DNS mutation, or AWS
mutation.

## Current AWS capability seam

The contract follows the current official CloudFront APIs and terminology:

- [`CreateDistribution`](https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_CreateDistribution.html)
  creates a distribution with `ConnectionMode=tenant-only`, one required
  `OriginDomain` tenant parameter, and one reviewed default behavior.
- [`CreateConnectionGroup`](https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_CreateConnectionGroup.html)
  creates the explicit custom Viewer-routing prerequisite used for a
  self-contained first-tenant bootstrap. Its exact `RoutingEndpoint` is
  inspected before tenant creation.
- [`CreateDistributionTenant`](https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_CreateDistributionTenant.html)
  creates one enabled tenant with the exact custom connection group, Viewer
  domain, tenant-specific `OriginDomain`, and CloudFront-hosted managed
  certificate request. Current AWS rejects this path when neither a certificate
  nor `ManagedCertificateRequest` is present.
- [`GetManagedCertificateDetails`](https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_GetManagedCertificateDetails.html)
  reports `pending-validation`, `issued`, `inactive`, `expired`,
  `validation-timed-out`, `revoked`, or `failed`. A certificate inspection can
  update the tenant, so a later mutation always obtains a fresh tenant ETag.
- [`UpdateDistributionTenant`](https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_UpdateDistributionTenant.html)
  requires the current ETag for certificate attachment, OriginDomain update,
  and disable operations.
- [`DeleteDistributionTenant`](https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_DeleteDistributionTenant.html)
  requires a disabled tenant and its current ETag. The parent distribution can
  be disabled and deleted only after its tenants are gone.

[`UpdateConnectionGroup`](https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_UpdateConnectionGroup.html)
and [`DeleteConnectionGroup`](https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_DeleteConnectionGroup.html)
require the current custom-group ETag. Deletion is admitted only after the exact
group has no represented tenant association and is disabled and deployed.
Default connection groups remain valid externally supplied prerequisites, but
this contract never plans their mutation or deletion.

These provider semantics preserve ADR-019's distinction between accepting a
tenant create plus certificate request, validation, issuance, attachment, and
observed domain activation. They do not require tenant creation and certificate
request to be separate API mutations or domain activation to have a dedicated
mutation.

## Parent and tenant baseline

The reviewed parent is one CloudFront Multi-Tenant Distribution with:

```text
AWS partition = aws
ConnectionMode = tenant-only
Origin DomainName = {{OriginDomain}}
OriginDomain = required tenant parameter
ViewerProtocolPolicy = https-only
AllowedMethods = GET, HEAD, OPTIONS, PUT, POST, PATCH, DELETE
CachedMethods = GET, HEAD, OPTIONS
CachePolicyId = 4135ea2d-6df8-44a3-9df3-4b5a84be39ad
OriginRequestPolicyId = b689b0a8-53d0-40ab-baf2-68738e2966ac
OriginProtocolPolicy = https-only
OriginSslProtocols = TLSv1.2
additional cache behaviors = none
```

The cache policy ID is AWS-managed `CachingDisabled`. The Origin Request Policy
ID is AWS-managed `AllViewerExceptHostHeader`: it transports Viewer headers,
cookies, and query strings while replacing Viewer `Host` with the configured
Origin host. Using immutable managed-policy IDs avoids mutable-name lookup and a
custom policy lifecycle.

Policy transport grants no trust. Viewer-supplied forwarding headers and
`X-SecPal-*` values remain untrusted input. #211 owns Function/KVS validation
and overwrite, and #217 owns HAProxy validation and canonical reconstruction.
The absence of caching ensures authenticated or session-specific responses
cannot cross Viewer or Tenant boundaries through a CloudFront cache hit.

One SecPal deployment maps to one Distribution Tenant. The caller supplies a
deployment-scoped technical key, Viewer domain, explicit `OriginDomain`, exact
parent ID, and exact admitted connection-group ID. Viewer Host and Origin Host
are separate inputs and must differ. The portable implementation contains no
customer identity, fleet inventory, placement, account-selection, rollout,
SLA, pricing, or commercial policy.

For a fresh-account or self-contained qualification bootstrap, the caller first
creates one exact custom connection group and inspects its provider-assigned ID,
current ETag, `RoutingEndpoint`, status, enabled state, and non-default status.
DNS remains external: before tenant creation, the caller must route the Viewer
domain to that endpoint and verify resolution. Route 53 is not part of this
portable contract. An existing admitted default or custom connection group may
instead be caller-supplied when its routing endpoint is already ready.

## Lifecycle and certificate states

The resource-specific operations are closed and CloudFront-specific:

```text
create/inspect/update/disable/delete distribution
create/inspect/disable/delete custom connection group
create/inspect/update/disable/delete tenant
inspect managed certificate
attach issued certificate
```

They are not translated into #169's generic create/inspect/rebuild/delete
vocabulary. #169's separately supplied authority, provider context, exact
target, source revision, parameter digest, credential mechanism, request/result
correlation, and bounded diagnostic patterns are reused at this boundary.

The one managed Viewer-certificate state model is:

```text
no tenant
→ requested (enabled tenant create + managed certificate request accepted)
→ validation-required (AWS pending-validation)
→ issued
→ attached
→ active

AWS inactive → inactive
AWS expired / validation-timed-out / revoked / failed → failed
```

`active` requires all of the following read back together:

- AWS certificate status `issued`;
- the exact issued certificate ARN attached to the exact tenant;
- the exact Viewer domain status `active`;
- tenant `Enabled=true`; and
- tenant deployment status `Deployed`.

A tenant ID, accepted create-time certificate request, validation token,
issued-but-unattached certificate, or attached certificate with an inactive
Viewer domain cannot satisfy `active`.

`DistributionTenant.Enabled=true` means the tenant can serve traffic; it does
not mean its Viewer domain is active. During CloudFront-hosted validation, the
tenant is enabled while the Viewer domain can remain `inactive` and the managed
certificate remains `pending-validation`. CloudFront's well-known validation
exception belongs to that inactive domain state, not to a disabled tenant.

CloudFront managed certificates expose no private key to this contract. Current
managed-certificate details may contain bounded HTTP validation redirects for a
`self-hosted` request. The typed observation surfaces only domain,
`RedirectFrom`, and `RedirectTo`. DNS, registrar, web-server, Route 53, and other
validation orchestration remain caller-owned and outside this leaf.

## Authority, identity, and concurrency

Every invocation binds:

```text
authorization identity
adapter identity and exact source revision
AWS partition, exact account ID, global CloudFront scope, and ACM certificate region
exact distribution and tenant IDs when assigned
exact connection-group ID when assigned or externally admitted
exact CloudFront-specific operation
SHA-256 parameter digest
non-secret credential mechanism
```

The credential value never enters the contract. Create may begin with a
caller-supplied technical key; after AWS returns native IDs, all reads and
mutations require those IDs. Names, prefixes, tags, account-wide listing, and
guessed discovery do not authorize mutation or cleanup.

Every ETag-bound mutation takes the exact ETag from its admitted current
observation. Missing, stale, or mismatched ETags fail before dispatch. Each
mutation is followed by inspection, and the newly observed ETag replaces the old
one. There is no retry loop, last-write-wins fallback, or interchange with a KVS
Data Plane ETag. A parent update carries the complete admitted current
distribution configuration, as the AWS API requires.

## Safe teardown

Teardown is exact and ordered:

```text
inspect exact tenant
→ disable tenant with current tenant ETag
→ inspect until Deployed and obtain new ETag
→ delete exact tenant with that ETag
→ caller removes the exact Viewer DNS record outside this contract
→ inspect exact qualification-owned custom connection group
→ disable custom group with its current ETag
→ inspect until Deployed and obtain new ETag
→ delete custom group with that ETag
→ inspect exact parent
→ disable parent with complete current config and current parent ETag
→ inspect until Deployed and obtain new ETag
→ delete exact parent with that ETag
```

The implementation never lists an account and deletes by name or tag prefix.
It never deletes a default connection group. An externally admitted existing
group remains caller-owned and outside qualification-owned cleanup.
Cleanup failure remains an explicit bounded failure associated with the exact
created IDs; it does not authorize broader cleanup. CloudFront managed-certificate
inspection is bound to the exact distribution-tenant identifier and therefore
ends when exact tenant deletion is proven. The certificate ARN is not a valid
post-deletion identifier for that CloudFront operation. A separate direct ACM
lifecycle is outside #210; provider-retained non-billable certificate state is
not misrepresented as a retained billable Viewer Edge resource.

## Real-provider qualification

Repository tests use deterministic synthetic representations. They prove this
repository contract only. They are not AWS evidence.

The closed `qualification_operations()` sequence is the interface for an
explicitly authorized ephemeral run. Before dispatch, the caller must supply
separate mutation authority, an exact AWS account context, an ephemeral technical
key and domains, an adapter/source SHA, a parameter digest, and an approved
credential mechanism. The run must prove:

1. create and inspect one exact `tenant-only` parent;
2. create and inspect one exact custom connection group, require
   `IsDefault=false`, and obtain its `RoutingEndpoint` before tenant creation;
3. have the external DNS harness create and verify the exact Viewer CNAME to
   that endpoint; DNS mutation is not a CloudFront lifecycle operation;
4. read back mandatory Viewer `https-only`, `CachingDisabled`, the reviewed
   Origin Request Policy, required `OriginDomain`, and Origin `https-only`;
5. create one enabled tenant with the exact connection-group ID and
   `ManagedCertificateRequest(ValidationTokenHost=cloudfront)`, then prove
   accepted creation/request and `Enabled=true` are not domain activation;
6. surface validation-required details and observe issuance without changing
   DNS through this contract;
7. re-read the tenant ETag, attach the issued ARN, then inspect until the exact
   domain is `active` while the tenant remains enabled and deployed;
8. update `OriginDomain` with the latest ETag and verify the exact read-back;
9. exercise a deliberately stale synthetic/admission ETag without dispatching a
   conflicting provider mutation, while provider qualification records the
   bounded precondition behavior available to the authorized adapter;
10. disable and delete the exact tenant, remove its external Viewer CNAME,
    disable and delete the exact custom group, then disable and delete the exact
    parent in the required order; and
11. verify no retained billable CloudFront, connection-group, tenant, or other
    qualification resource remains. Any cleanup failure records exact non-secret
    resource identities for bounded manual cleanup.

Provider qualification requires explicit authorization to create and mutate AWS
and DNS or validation infrastructure. No such authority is granted by this
repository contract or by its tests.

Authorized qualification established two related create-time defects and
cleaned every exact ephemeral resource:

```text
FIRST_REAL_PROVIDER_QUALIFICATION:
certificate-absent CreateDistributionTenant rejected

ACTION:
ManagedCertificateRequest moved into CreateDistributionTenant

SECOND_REAL_PROVIDER_QUALIFICATION:
disabled tenant remained pending-validation

PREVIOUS_DISPOSITION: INVALID_FINDING
CORRECTED_DISPOSITION: IN_CONTRACT_DEFECT
technically_blocking: true
mechanically_blocking: true

THIRD_REAL_PROVIDER_QUALIFICATION:
disabled tenant validation path returned CloudFront 403

FOURTH_REAL_PROVIDER_QUALIFICATION:
persistent CloudFront 403 reproduced; run interrupted by SSO expiry;
exact cleanup subsequently completed

ROOT_CAUSE:
DistributionTenant.Enabled=false was incorrectly conflated with
Domain.Status=inactive

FIFTH_REAL_PROVIDER_QUALIFICATION:
temporary CloudFront qualification dispatcher defect; exact cleanup completed

CLOUDFRONT_DISPATCHER_PREFLIGHT: PASS

SIXTH_REAL_PROVIDER_QUALIFICATION:
temporary Route 53 qualification helper defect; exact cleanup completed

ROUTE53_HELPER_PREFLIGHT: PASS

SEVENTH_REAL_PROVIDER_QUALIFICATION: PASS
REAL_PROVIDER_LIFECYCLE_QUALIFICATION: PASS
RETAINED_BILLABLE_QUALIFICATION_RESOURCES: 0
```

The successful provider-facing qualification proved the tenant-only parent,
custom non-default connection group, pre-tenant Viewer CNAME, enabled tenant,
CloudFront-hosted validation, certificate issuance, fresh-ETag attachment,
active Viewer domain, `OriginDomain` update, exact teardown, and zero retained
billable qualification resources. Ephemeral domains, resource IDs, ETags,
certificate ARNs, and validation values remain outside tracked documentation.

## Scope and complexity

Function/KVS trust transport, WAF/AMR, Origin certificate issuance, provider or
host firewalling, HAProxy Origin authentication, and end-to-end conformance stay
with #211, #212, #213, #215/#216, #217, and #218 respectively.

```text
NEW_PERMANENT_CONCEPT: one bounded CloudFront Viewer Edge lifecycle contract with one managed-certificate state model
REPLACES: nothing; it implements deployment #210
WHY_EXISTING_CONTRACT_CANNOT_ABSORB_IT: #169 intentionally excludes CloudFront resource semantics, and AWS requires certificate-specific validation, issuance, ETag-bound attachment, observed domain activation, and teardown transitions

NEW_PERMANENT_CONCEPTS: 1
EXISTING_CONCEPTS_REUSED: ADR-019 invariants and #169 authority/exact-target/correlation/diagnostic patterns
NEW_SCHEMAS: 0
NEW_STATE_MACHINES: 1
NEW_PROVIDER_REGISTRIES: 0
NEW_EVIDENCE_TYPES: 0
NEW_RUNTIME_DEPENDENCIES: 0
```
