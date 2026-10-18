<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Public findings and notifications

Owner: [#172](https://github.com/SecPal/deployment/issues/172).
The executable contract is `scripts/public_findings.py`, version 1. It uses
Python's standard library; no monitoring daemon, private Operations service,
provider access or notification credentials are required.

[ADR-023](https://github.com/SecPal/.github/blob/main/docs/adr/20260824-public-self-hosting-private-managed-operations-adr023.md)
and [#748](https://github.com/SecPal/.github/issues/748) own the public/private
boundary. This implements that decision without changing it.

## Facts and authority

Observation != Health State != Finding != Incident != Authority != Action.

An owning producer observes the system. Its existing contract decides what its
observations mean. A finding projects a bounded technical condition with an
independently bound evidence identity. It carries neither incident state nor
action authorization. Notification transports that finding; delivery does not
establish human acknowledgment, an incident, service health or action completion.

[#129](https://github.com/SecPal/deployment/issues/129) owns production health
aggregation: Service AVAILABLE / DEGRADED / UNAVAILABLE / UNKNOWN; Capability
HEALTHY / DEGRADED / FAILED / UNKNOWN / NOT_APPLICABLE. There is no competing
health engine or global deployment-healthy flag here. Missing telemetry is
UNKNOWN, not automatically customer-service DOWN. Independent blackbox reachability
and whitebox observations retain their own evidence and scope.

## One finding representation

`accept(raw, source=..., subject_sha256=..., evidence_sha256=..., now=...)`
accepts at most 4096 bytes of JSON and returns immutable canonical JSON bytes.
It rejects duplicate/unknown/missing fields, unsupported versions, invalid time,
wrong provenance and unreviewed condition/reason pairs with bounded
`finding-*` errors. The exact fields are:

| Field                  | Meaning                                                          |
| ---------------------- | ---------------------------------------------------------------- |
| `schema_version`       | Integer `1`                                                      |
| `producer`             | Reviewed technical producer identifier                           |
| `category`             | health, security, update, conformance or integrity               |
| `capability`           | Producer-owned technical dimension; no overall service inference |
| `subject_sha256`       | Opaque digest binding a technical subject                        |
| `evidence_sha256`      | Digest of independently available evidence                       |
| `condition` / `reason` | Exact pair from the producer's reviewed vocabulary               |
| `observed_at`          | UTC Unix seconds or null for unknown observation time            |

The trusted consumer provides a `Source` with producer/category/capability,
a finite condition/reason vocabulary and the owning producer's freshness
interval. This configuration is **not incoming finding data**. It must not be
constructed from untrusted JSON. New producers define their own small vocabulary
in their existing owner; this module is not a producer registry.

Subject and evidence digests must be independently resolved through the
authenticated producer/evidence channel. A matching hash string is not a
signature, authenticated collector or proof of host ownership. Evidence must be
available to verify; opaque digests reduce disclosure, not authority checks.
Do not derive expected bindings from the submitted finding itself.

Known conditions require a non-future observation within the producer's
freshness interval. UNKNOWN may retain missing/stale observation time; it never
becomes HEALTHY. Stale known facts are rejected, not silently rewritten.
This envelope admission does not replace producer-specific freshness or health
semantics. Callers supply an independently observed clock, not a timestamp
chosen by the finding.

There are no free-text messages, URLs, labels, inventories, request bodies,
tokens, cookies, personal records, destinations, commands or authorization
fields. A producer must use reviewed non-secret technical codes and opaque
subject/evidence digests. Do not put secrets into codes or referenced evidence.
The validator cannot discover arbitrary secrets deliberately encoded as valid
identifiers. Authentication, redaction, evidence custody and read-only producer
credentials remain obligations of the owning collector and administrator.

## Existing TLS fact and other consumers

`tls_finding(observation, subject_sha256=..., evidence_sha256=..., now=...)`
calls the **existing** `viewer_tls_contract.health()`. Its condition/reason and
observation time come directly from that function. The evidence digest must
match the observation serialized with sorted keys and compact JSON separators.
It preserves the original fact schema, renewal freshness and certificate
decisions. The full TLS fact remains the evidence; this bounded projection is
not a replacement for it. Envelope admission may reject an old known fact until
a current observation is obtained; it does not alter that producer's result.

| Technical owner                          | Consumption boundary                                                    |
| ---------------------------------------- | ----------------------------------------------------------------------- |
| DIRECT Viewer TLS #103                   | Existing Security fact; executable projection above                     |
| Host/systemd/SELinux, #80 conformance    | Owning host evidence and freshness; no new host observer                |
| Frontend/API, workers/scheduler #94/#129 | Preserve liveness versus readiness and progress facts                   |
| PostgreSQL #81 and future HA owners      | Database observations do not grant promotion or writer authority        |
| Barman #107                              | Backup/WAL and Recovery Chain Lost belong to Barman evidence            |
| Objects #99/#128                         | Integrity, replication and recovery continuity remain separately owned  |
| DIRECT/PROTECTED Edge #90/#209           | Routing, TLS and Origin authentication retain distinct authority        |
| CrowdSec #105 / AppSec #106              | Future accepted Security degradation facts; no Draft code imported      |
| Optional runtime detection #98           | Socketless observation; no detector containment authority inferred      |
| Update/version/EOL and artifact scanners | Owning scan policy, provenance and freshness; unknown scan is not clean |

Except for the TLS projection, this table defines compatibility and ownership,
not newly deployed producers. An absent or unaccepted producer supplies no live
fact. Report its dimension as UNKNOWN under the owning health contract rather
than manufacturing HEALTHY or NOT_APPLICABLE. One Security fact cannot establish
customer availability, backup completeness or recovery correctness.

## Independent Self-Hosted notification

`notify` re-admits the finding and constructs an intended notification:
version 1, an operator-generated opaque `notification_id`, and the finding.
The operator passes a trusted adapter in code, outside the JSON channel.
No submitted value selects a destination, executable, module or credential.

The separate result contains version, notification identity, finding digest
and DELIVERED / FAILED / SILENCED. Only an adapter return value of exactly
`True` acknowledges delivery; exceptions and partial/failed writes produce
FAILED without leaking transport exceptions or destinations. A local stream
acknowledgment promises write/flush only, not persistence or human receipt.
Notification IDs correlate attempts; there is no durable deduplication, queue,
implicit retry or exactly-once delivery claim.

For a minimal Self-Hosted consumer, add the repository's `scripts` directory to
the Python import path and use a reviewed producer configuration:

```python
from public_findings import Source, notify, stream_adapter

# raw, subject, evidence and now come from independently authenticated observation.
source = Source("host-conformance", "conformance", "Security",
                frozenset({("UNKNOWN", "observation-unavailable")}), 60)
result = notify(raw, source=source, subject_sha256=subject,
                evidence_sha256=evidence, now=now, notification_id=attempt,
                send=stream_adapter(operator_selected_binary_stream))
```

The stream adapter is a representative transport, not an email/SaaS platform.
The consumer retains the original finding/evidence independently of delivery.
`silent=True` suppresses the attempt only: validation still runs, the result is
SILENCED and the finding is unchanged. Neither silence nor delivery failure
changes health, incident truth, service readiness or an existing safety control.
Notification destinations and any transport credentials belong in protected
runtime configuration, never findings or Git.

## Separately authorized reactions

There is no action dispatcher in this contract. Detectors, scanners and
notification adapters receive no provider, deployment, secret-rotation,
PostgreSQL promotion, RecoverySet selection, resource-deletion or routing
credentials. Run them with the minimum read/transport authority their owner
requires. Python data validation is not an OS sandbox; the embedding process
must enforce privilege and credential separation. A privileged arbitrary
callback is not made safe by calling it a notification adapter.

An administrator may pass accepted findings as **evidence** to an independently
authorized owning consumer. That consumer still authenticates its own
preconditions, exact scope and execution authority. This permits existing
bounded reversible local self-heal without granting a finding action rights.

[#104](host-firewall.md) alone owns its nftables mutation boundary.
When accepted, #105 can select authenticated decisions and dispatch through
that bounded interface under its separately admitted host-security authority.
No new CAP_NET_ADMIN, sudo rule, firewall table, wrapper or remediation token
is added here. Client-controlled identity remains insufficient to ban a peer.

Private [Operations #15](https://github.com/SecPal/operations/issues/15) may
consume these facts, but owns customer/fleet correlation, severity/SLA thresholds,
routing, on-call/SOC, maintenance/suppression and rollout/remediation policy.
It may initiate gated actions only with independent policy and owning execution
authority. ADR acceptance does not bypass the Operations governance/privilege
gate. Private Operations must not redefine public technical health, safety,
conformance or vulnerability semantics.

## Evidence scope

`python3 tests/public-findings.py` exercises bounded provenance admission,
unknown/stale facts, actual TLS fact projection, independent Self-Hosted stream
delivery, failed/partial delivery, silence and data/authority separation.
Existing TLS and host-firewall suites retain their unchanged owning invariants.
These are executable contract tests, not production credential/OS privilege
proof or a deployed monitoring plane. No provider operation, installation,
customer traffic or real notification send is needed for this source contract.
