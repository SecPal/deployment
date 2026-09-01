<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: CC0-1.0
-->

# PROTECTED CloudFront shared WAF contract

This is the portable implementation contract for the shared AWS WAF baseline
owned by [deployment #212](https://github.com/SecPal/deployment/issues/212).
It implements the WAF portion of accepted
[ADR-019](https://github.com/SecPal/.github/blob/main/docs/adr/20260824-production-edge-layered-security-adr019.md).
It does not perform provider operations, select a customer logging destination,
or define retention, DPA/TIA, operational response, fleet, or commercial policy.

The executable pure contract is
[`cloudfront-waf.py`](../scripts/cloudfront-waf.py). It has no credential,
network, filesystem, persistence, AWS, or DNS operation path.

## Permanent contract

PROTECTED has exactly this relevant ordering:

```text
Viewer
→ AWS WAF
→ CloudFront viewer-request Function
→ Origin
```

The shared Web ACL is AWS WAF V2 with `Scope = CLOUDFRONT`, endpoint region
`us-east-1`, and default action `Allow`. It is associated only with the exact
CloudFront multi-tenant Distribution. Each admitted Distribution Tenant must
inherit the shared Web ACL: a `Customizations.WebAcl` action of `override` or
`disable` fails closed. Unrelated `Certificate` and `GeoRestrictions`
customizations remain outside this WAF seam and are accepted.

AWS WAF evaluates before the Function. No WAF rule derives authority from
`X-SecPal-Origin-Token`, `X-SecPal-Viewer-Host`, or
`X-SecPal-Viewer-IP`; viewer-supplied copies are ordinary untrusted request
data. Function/KVS overwrite behavior belongs to #211 and is not implemented
here.

The only managed group is `AWS` / `AWSManagedRulesAntiDDoSRuleSet`. The normal
rule statement omits `Version`, so it follows the AWS provider default. It sets
`ClientSideActionConfig.Challenge.UsageOfAction = DISABLED` and
`SensitivityToBlock = LOW`; it does not invent URI exceptions or browser
challenge policy.

There are exactly two managed-rule modes:

| Mode                  | `OverrideAction` | Accepted production enforcement |
| --------------------- | ---------------- | ------------------------------- |
| `QUALIFICATION_COUNT` | `Count`          | No                              |
| `ENFORCEMENT`         | `None`           | Yes                             |

Count is bounded qualification evidence only. It cannot silently become a
production enforcement result.

Every #212-owned Web ACL and rule visibility configuration disables sampled
requests. Logging redaction is not treated as sampling protection.

## Provider discovery and capacity

Before a real mutation, the caller must provide bounded typed discovery for the
exact vendor/name/scope, default and available static versions, reported
capacity, exact `CheckCapacity` result, current applicable Web ACL capacity
ceiling, current rule/action facts, labels, and required Anti-DDoS configuration
surface. The contract requires a resolved default version, the reviewed
`anti-ddos:ddos-request` label, disabled client-side challenge support, low
block sensitivity support, positive capacity facts, an exact successful capacity
result, and capacity within the current ceiling.

A provider-default change is `REQUALIFICATION_REQUIRED`. The portable baseline
does not pin a static version, maintain pins, or fall back to expired versions.
Temporary pins are a later explicitly authorized qualification/rollback concern.

Current internal rules and their ordering are provider evidence rather than
architecture. Discovery records rule/action observations without making a
permanent rule-name list.

## Privacy-minimized security logging

The logging configuration requires one caller-supplied exact destination ARN.
It accepts the AWS WAF destination families CloudWatch Logs, Amazon S3, and
Amazon Data Firehose without selecting one as SecPal Managed policy. Destination
creation, retention, and destination access policy remain outside this contract.

Logging defaults to `DROP` and has one `KEEP` condition for the fully-qualified
`awswaf:managed:aws:anti-ddos:ddos-request` label. It excludes broad
`event-detected` traffic, which can include legitimate requests throughout an
event, as well as ordinary Allow, challengeable-only, unrelated-rule, and
unrelated-label traffic.

Data protection uses `SUBSTITUTION` for:

- the request body;
- the complete query string; and
- the explicitly reviewed Authorization, Cookie, `X-SecPal-Origin-Token`,
  `X-SecPal-Viewer-Host`, and `X-SecPal-Viewer-IP` header keys.

Current live provider behavior requires non-empty `FieldKeys` for
`SINGLE_HEADER`; the contract therefore enumerates this existing reviewed set.
It does not claim an all-header protection mode. A future sensitive application
header must be added to the reviewed contract or protected at another suitable
layer. Logging redaction independently covers URI path, query string, the same
reviewed headers, and remains distinct from Data Protection and sampling.

AWS currently documents `AWS-WAF-TOKEN` as a provider-owned exception to WAF
data-protection coverage. The contract records that limitation rather than
claiming universal cookie protection. No hashing is used merely to preserve
correlation for credentials or customer content.

Retained event records are not anonymous. AWS may emit timestamp, Web ACL and
resource identifiers, tenant/request correlation identifiers, rule/action and
label information, source IP, country, HTTP method/protocol, TLS/client
fingerprints, and redacted header structure. These are the bounded native
security diagnostics for the retained DDoS event. Final retention duration is
not decided here.

## Concurrency, update, and cleanup

CloudFront association and disassociation use the exact Distribution ID and a
fresh CloudFront ETag. Tenant WAF APIs are inspection-only; the accepted baseline
does not associate a tenant-specific ACL.

Web ACL update and deletion use the exact Web ACL ID/ARN and a fresh AWS WAF
`LockToken`. An ETag and LockToken are distinct, non-interchangeable authorities.
`UpdateWebACL` is replacement-style: the plan requires the complete admitted
current configuration, an exact desired replacement, and the current LockToken.
Rollback uses the prior accepted complete configuration with a fresh current
post-failure LockToken; it has no retry loop or last-write-wins path.

Later qualification cleanup is exact and only authorizes resources marked as
qualification-owned:

```text
DeleteLoggingConfiguration for the exact Web ACL ARN
→ DisassociateDistributionWebACL with a fresh Distribution ETag
→ DeleteWebACL with a fresh WAF LockToken
```

It never discovers or deletes resources by name, prefix, tag, or account-wide
listing, and it cannot delete a pre-existing external Web ACL.

## Current provider observation

The #212 intake observed the AWS default `Version_1.0`, capacity 50 WCU, three
current internal rules, and a current CloudFront Web ACL ceiling of 5000 WCU.
These are mutable provider observations, not permanent SecPal guarantees. The
intake also observed the current Anti-DDoS configuration surface and labels.

Diagnostic run `q212-diag-379c83a077` reproduced a live `CreateWebACL`
`WAFInvalidParameterException`: `SINGLE_HEADER` rejected omitted `FieldKeys` as
null or empty. This observed service requirement conflicts with the generic AWS
API reference that currently describes `FieldKeys` as optional. The live
provider evidence controls this executable request shape without creating a new
architecture concept.

## Later real-provider qualification

Real-provider qualification remains required before Ready/closure. With separate
mutation authority it will create only ephemeral exact resources, re-run provider
discovery and `CheckCapacity`, prove distribution association and tenant
inheritance, exercise Count then enforcement read-back, prove WAF-before-Function
ordering with a qualification fixture, verify forged internal-header
independence, inspect privacy sentinels in retained events, prove stale ETag and
LockToken diagnostics, perform update/rollback, and leave zero billable
qualification resources.

This tracked implementation provides synthetic contract evidence only. It makes
no production DDoS guarantee and does not enable CloudFront standard or
real-time logging.

## Cost and scope boundary

The AWS Anti-DDoS managed group and logging can incur AWS charges. Later
qualification requires explicit mutation authorization, an ephemeral bounded
window, exact cleanup, and a retained-billable-resource report. Budget decisions
do not automatically disable security controls.
