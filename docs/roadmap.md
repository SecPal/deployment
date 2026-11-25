<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: CC0-1.0
-->

# Deployment roadmap

This roadmap points to current delivery owners. Native GitHub issues and
relationships own delivery status.

## Current production direction

Fedora CoreOS Stable is the Managed reference host on x86_64 and aarch64.
Rootless Podman/Quadlet and SELinux Enforcing are the baseline. PostgreSQL 18
remains separately governed infrastructure, with qualified container operation
as the Managed reference. Sessions, queues, shared cache and coordination are
PostgreSQL-backed. Self-Hosted retains portable interfaces and can use other
qualified platform adapters. [Accepted Managed FCOS refinement](https://github.com/SecPal/.github/pull/1348)

Production Edge mode is **DIRECT** or **PROTECTED**. DIRECT uses HAProxy as the
Viewer Edge and external Certbot for Viewer certificates. PROTECTED uses
CloudFront Multi-Tenant as Viewer Edge and an authenticated HTTPS HAProxy Origin.
Each selected mode needs end-to-end qualification on FCOS. Portable ownership
stays with the [DIRECT graph](https://github.com/SecPal/deployment/issues/90) or
the [PROTECTED graph](https://github.com/SecPal/deployment/issues/209).
[ADR-019](https://github.com/SecPal/.github/blob/main/docs/adr/20260824-production-edge-layered-security-adr019.md)

The current production owners are the [FCOS/PG18 platform graph](https://github.com/SecPal/deployment/issues/134),
the [state, edge and lifecycle graph](https://github.com/SecPal/deployment/issues/87)
and the [recovery graph](https://github.com/SecPal/deployment/issues/91).
Older Rocky and native PostgreSQL assumptions in existing implementation
issues and historical evidence describe the earlier reference.
The accepted ADRs govern the FCOS implementation of those contracts.

### FCOS lab container coverage

**QUALIFIED** on all three FCOS lab hosts at deployment revision
`8ca49d48c6ee2179bf1fe8eae7575379d425484d`. The same reviewed rootless
stack runs on x86_64 and aarch64. Production acceptance is tracked below.

| Role                                                                               | Maintained runtime and qualification boundary                                                                                                                                                                                                                                                                                      |
| ---------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Frontend, Nginx API HTTP, PHP-FPM                                                  | Existing rootless Quadlet fixture on x86_64 and aarch64. Frontend and API are distinct immutable image families.                                                                                                                                                                                                                   |
| General worker, hash-chain worker, scheduler                                       | One of each per application fixture. Queue, session and cache state use PostgreSQL.                                                                                                                                                                                                                                                |
| PostgreSQL 18 and explicit migration                                               | Existing native images, TLS/SCRAM, persistent storage and separated-role renderer. The qualified three-host stack uses the separated-role renderer and verifies the PostgreSQL server identity.                                                                                                                                    |
| HAProxy                                                                            | Private [fixture profile](fcos-application-poc.md#private-haproxy-gateway) reuses the shared HAProxy routing and DIRECT identity rules. Lab evidence has its own scope.                                                                                                                                                            |
| CrowdSec, AppSec/Coraza, SPOA and CRS                                              | The [private AppSec profile](fcos-application-poc.md#private-crowdsec-and-appsec) couples independently confined Engine and SPOA containers to HAProxy. Host enforcement and production security remain under [#105](https://github.com/SecPal/deployment/issues/105) and [#106](https://github.com/SecPal/deployment/issues/106). |
| Host systemd, SELinux, NetworkManager/WireGuard, nftables, SSH, Zincati and Podman | Host-native. They own service supervision, kernel policy, network configuration, recovery access, OS updates and container execution respectively.                                                                                                                                                                                 |

## FCOS qualification evidence

| Capability              | Bounded real-system evidence                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Host and runtime        | Signed multiarch FCOS install, authenticated SSH, direct IPv4/IPv6 WireGuard, fresh identities after x86_64 rebuild, persistent identities and state after reboot, SELinux Enforcing and rootless Quadlet. The exact published host foundation remains a candidate. [#425](https://github.com/SecPal/deployment/issues/425), [Draft #428](https://github.com/SecPal/deployment/pull/428)                                                                                                                                                   |
| Application and ingress | Digest-pinned application fixture on x86_64 and aarch64. Private HTTPS, browser/API login, CORS/CSRF, deployment-scoped cookies, worker/scheduler and database-backed state on named volumes. Private HAProxy and CrowdSec/AppSec/SPOA with pinned CRS qualify current lab ingress. [Application proof](fcos-application-poc.md), [#429](https://github.com/SecPal/deployment/issues/429)                                                                                                                                                  |
| PostgreSQL              | PostgreSQL 18.6 native OCI artifacts, TLS/SCRAM, separate temporary DDL and restricted runtime authority, and read/write and denial probes. The same isolated SIGKILL procedure on both architectures proved automatic WAL replay, survival of acknowledged commits, absence of uncommitted rows and persisted grants after clean recreation. This is process-crash evidence with the guest kernel and storage available. [#426](https://github.com/SecPal/deployment/issues/426), [qualification and limits](postgresql-qualification.md) |
| Recovery                | Encrypted off-source logical export, isolated cross-host import and authenticated reads of exact synthetic data after container recreation. The proof used an already-qualified destination and lab crypto. Full host-loss recovery from a blank host and independent recovery custody remain open. [Logical restore procedure](fcos-application-poc.md#cross-host-logical-restore), [#429](https://github.com/SecPal/deployment/issues/429)                                                                                               |

Raw host observations and archive/key locations stay private. Issue and PR
references identify the bounded evidence. Reuse it for its reviewed host,
bundle, image, state, and failure-model inputs until a relevant input changes.
Architecture acceptance and source merge are distinct from real-system
qualification and profile-specific production acceptance.

## Managed SINGLE readiness

The existing private synthetic fixture supports application and component
pilots on qualified lab hosts. An end-to-end synthetic **MANAGED_SINGLE**
pilot still needs an executable, resumable path through blank host conformance,
fresh Enrollment, Activation, state and recovery materialization, selected Edge,
acceptance and ACTIVE. The production profile additionally requires the live
authorities and recovery evidence before the first customer write. Use existing
authority contracts for both stages. [ADR-022](https://github.com/SecPal/.github/blob/main/docs/adr/20260824-deployment-topology-high-availability-adr022.md),
[Managed composition owner](https://github.com/SecPal/operations/issues/14)

| Gap and owner                                                                                                                                                                                                                                                      | Missing acceptance and next bounded change                                                                                                                                                                                                                                                                                    | Blocks                                                                                                                      |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| Host foundation [#425](https://github.com/SecPal/deployment/issues/425), [#424](https://github.com/SecPal/deployment/issues/424), [#117](https://github.com/SecPal/deployment/issues/117)                                                                          | Bind the reviewed provisioning/conformance bundle to exact execution and prior evidence. Prove independently protected provider custody and safe credential transition through the existing broker before live acceptance. Preserve independent Rescue and manage Zincati update/reboot policy.                               | Full pilot and production                                                                                                   |
| Activation and crypto [#100](https://github.com/SecPal/deployment/issues/100), [#241](https://github.com/SecPal/deployment/issues/241)                                                                                                                             | Compose fresh, conformant Host Enrollment with expiring purpose-scoped Activation. Prove rotation and that a separate recovery operator can restore required crypto generations without the original host or sole Secret Authority. Start from the existing Activation draft.                                                 | Full pilot for Enrollment/Activation; production for real custody and rotation                                              |
| PostgreSQL platform [#426](https://github.com/SecPal/deployment/issues/426)                                                                                                                                                                                        | Admit the merged container lifecycle against the accepted FCOS foundation and #100 service-secret lifetime with independently issued credentials. Admit the intended update, restart and reboot lifecycle and qualify storage semantics for the claimed failure model.                                                        | Production. Lab containerization is qualified.                                                                              |
| Authoritative Objects [#99](https://github.com/SecPal/deployment/issues/99)                                                                                                                                                                                        | Qualify an off-host backend using immutable encrypted bytes and independent size/hash checks. Exercise PENDING-to-READY publication and prove that a failed write cannot publish a database reference. Start with one synthetic object on the selected adapter.                                                               | Full pilot and production                                                                                                   |
| External backup and decryption [#107](https://github.com/SecPal/deployment/issues/107), [#128](https://github.com/SecPal/deployment/issues/128), [#100](https://github.com/SecPal/deployment/issues/100)                                                           | Restore PG18 base backup plus continuous WAL to an exact target from the independent Backup Plane. Restore canonical encrypted Object bytes into a separate namespace and prove retained history is beyond runtime delete authority. Prove independent decryption without credentials from the failed host or lost authority. | Full pilot needs representative recovery material; production needs independent authority and live chain evidence           |
| Host-loss recovery [#109](https://github.com/SecPal/deployment/issues/109), [#110](https://github.com/SecPal/deployment/issues/110)                                                                                                                                | Publish a failure-class-specific VERIFIED RecoverySet binding DB/WAL, Objects and crypto generations. Drill from a fresh blank Host with fresh Enrollment and bounded Recovery authority. Measure RPO/RTO and authenticated application/Object recovery.                                                                      | Full pilot needs synthetic end-to-end recovery evidence; production needs matching VERIFIED evidence before customer writes |
| Production Edge [#90](https://github.com/SecPal/deployment/issues/90) or [#209](https://github.com/SecPal/deployment/issues/209), [#105](https://github.com/SecPal/deployment/issues/105), [#106](https://github.com/SecPal/deployment/issues/106)                 | Qualify one selected mode's HAProxy placement, TLS lifecycle, trusted client identity and required CrowdSec/AppSec paths. Exercise mode-specific bypass rejection and failure behavior.                                                                                                                                       | Full pilot and production for the selected mode                                                                             |
| Operations and lifecycle [#129](https://github.com/SecPal/deployment/issues/129), [#93](https://github.com/SecPal/deployment/issues/93), [#116](https://github.com/SecPal/deployment/issues/116), [Operations #15](https://github.com/SecPal/operations/issues/15) | Expose fresh read-only Service, Backup, Recovery and Security observations with explicit stale/unknown semantics. Exercise one alert, exact digest update with migration and compatible rollback, then link the owning commands from the operator runbook.                                                                    | Full pilot needs health and update evidence through #115; production also needs alerting and incident procedures            |
| Staged activation and acceptance [#92](https://github.com/SecPal/deployment/issues/92), [#115](https://github.com/SecPal/deployment/issues/115), [Operations #14](https://github.com/SecPal/operations/issues/14)                                                  | Compose one synthetic create-to-ACTIVE with failure/resume before routing. Use read-only acceptance to admit exact runtime/Edge, Object, recovery and crypto evidence, then qualify the live profile through its existing owner.                                                                                              | Full pilot and production                                                                                                   |

The native graph makes #115 and [Operations #13](https://github.com/SecPal/operations/issues/13)
prerequisites for the end-to-end Managed lifecycle. Operations #13 consumes
[Operations #12](https://github.com/SecPal/operations/issues/12). Its first
useful slice is authenticated Desired/Observed generation binding and one
leased, idempotent step with authoritative read-back. A lost response must
resume without a duplicated mutation. These are full-pilot and production
composition requirements. The existing synthetic component pilots can continue
on the qualified lab hosts.

For `MANAGED_HA`, Patroni, quorum DCS, fencing, writer routing and automatic
local failover belong to [the HA graph](https://github.com/SecPal/deployment/issues/84). The
[topology evolution graph](https://github.com/SecPal/deployment/issues/135) also
owns future cross-major upgrade qualification.
`MANAGED_CONTINUITY` adds warm independent-provider recovery and controlled
promotion under ADR-022. Planned same-major replacement has its own
[#82](https://github.com/SecPal/deployment/issues/82) delivery and is distinct
from blank-host recovery after total loss. Single uses the shared backup,
Object, crypto and RecoverySet guarantees from
[ADR-020](https://github.com/SecPal/.github/blob/main/docs/adr/20260824-production-state-recovery-authority-separation-adr020.md).

### Next deliveries

1. Advance **#425 / Draft #428** with exact FCOS candidate-to-evidence binding
   and the existing administrator-owned credential handoff. Apply #425's live
   acceptance before representing the candidate as delivered.
2. Advance **#100 / [Draft #337](https://github.com/SecPal/deployment/pull/337)** through the smallest purpose-scoped Activation
   and independent crypto recovery witness using the completed #241 contract.
3. Complete **#426** against the accepted FCOS and Activation inputs. Reuse
   both process-crash records. Add only the remaining lifecycle, storage and
   authority read-back needed by the intended production claim.

Then qualify off-host Objects and independent backup inputs under #99, #107
and #128, bind them into #109 and prove #110 against the #92 construction path.
Prepare the selected Edge and #129/#116 observations/runbooks independently.
Compose the synthetic Managed lifecycle through #115 and Operations #14 before
a live production activation.
