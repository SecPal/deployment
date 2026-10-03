<!--
SPDX-FileCopyrightText: 2026 SecPal Contributors
SPDX-License-Identifier: MIT
-->

# Rocky instance insertion transport observations

This diagnostic belongs to deployment #300. It adds observability; #299 owns
root-cause diagnosis and correction. It claims no GCP fix or real-provider
success. Local fixtures prove repository behavior only. No GCP dispatch is
part of this delivery. A later #299 diagnostic requires separate current
provider authority and accepted protected-main control.

## Mechanism and design decision

The actual producer remains OpenTofu 1.12.5, hashicorp/google 7.40.0 and
`tofu apply --auto-approve --input=false`. Its arguments, working directory,
environment and standard streams are inherited unchanged. Observation neither
reads nor changes proxy configuration, DNS, TLS trust, HTTP selection, timeout,
retry policy, metadata, project, zone, image, machine type or profile. It makes
no Compute request and never duplicates a producer socket file descriptor.

Evaluate socket counters first: Linux's supported `NETLINK_INET_DIAG` exact
socket query returns `TCP_INFO` without application buffers. This proves TCP
states, directional counters and retransmissions. Sampling alone loses final
counters when a socket disappears. Linux TCP destruction notifications retain
those counters. A classic receive filter admits only previously correlated
socket cookies; it initially rejects everything. The bounded filter inspects
only the kernel diagnostic header's two cookie words. It never inspects network
packets or application bytes. No packet capture, PCAP, TLS secrets, tracing hooks,
provider fork, second client or raw diagnostic file is needed.

The process boundary is the apply observer and its descendant locked Google
provider executable, including children created from any Go OS thread. Linux
process start ticks protect PID identity; owned `/proc/<pid>/fd` socket inodes
are checked before and after exact counter queries. Numeric tuples and kernel
socket cookies distinguish connections, including concurrent connections and
reuse. The provider must share the observer's network namespace. Only remote
port 443 is admitted; provider RPC and unrelated processes are excluded.
The namespace TCP table is used only to locate owned inodes; unrelated rows
are discarded before tuple decoding, counter queries or notification admission.

Kernel UAPI sources are
[inet_diag.h](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/inet_diag.h)
and [tcp.h](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/tcp.h).
The local controlled tests exercise actual Linux query and notification
representations, typed payload exclusion and the receive filter. Unsupported
capabilities fail collector startup; there is no production optional mode.

`ss` uses the same diagnostics but introduces textual process names and another
parser. Duplicating sockets to call `getsockopt` can extend their lifetimes.
Packet capture adds unnecessary payload exposure. Privileged kernel tracing adds
kernel compatibility and privilege requirements. In-process HTTP tracing would
change the pinned producer and can report synthetic `DumpRequestOut` callbacks.
None is required to obtain the useful counter partition this contract promises.

## Proven observations and limits

The window covers one apply, not a separately identified HTTP request. The
closed document names the expected instance and run, but never assigns a TCP
connection to a particular encrypted HTTP operation. Earlier prerequisite
operations, HTTP connection reuse and multiple library attempts may share
connections. A socket is never represented as a request or retry attempt.

| Boundary            | Supported observation                                                              | Limit                                                                                                                      |
| ------------------- | ---------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| Endpoint selection  | Correlated numeric TCP endpoint                                                    | DNS completion is UNKNOWN; no socket observed cannot prove failed DNS.                                                     |
| Connection progress | Observed SYN_SENT or a state implying TCP establishment                            | Missing or short-lived sockets cannot prove that no connection was established.                                            |
| Secure transport    | UNKNOWN                                                                            | Counters cannot prove TLS negotiation, handshake completion or absence of meaningful TLS progress.                         |
| Client transmission | Monotonic TCP bytes-sent counters and sample times                                 | Kernel TCP transmission is not complete HTTP upload or GCP receipt.                                                        |
| Server transmission | Monotonic TCP bytes-received counters and sample times                             | Received transport bytes are not parsed HTTP response headers.                                                             |
| Quiescence          | Equal counters between observations; final counters where destruction was observed | The interval ends at the recorded observation, never an inferred timeout; gaps and missing final counters remain explicit. |
| Close/reset         | FIN-related TCP states; reset origin UNKNOWN                                       | A vanished socket or CLOSE state cannot distinguish a local reset from a peer reset.                                       |
| Loss                | Retransmission counter and increases within the window                             | Zero or missing counters do not prove absence of network loss.                                                             |

First counters may already include traffic on a reused connection. Only changes
between observations belong to the sampled interval. Last activity fields name
**increase samples**, not precise wire-byte timestamps. Maximum sampling gaps
are retained. A missing destruction notification is explicitly represented as
`NO_DESTROY_NOTIFICATION_OBSERVED`; it cannot establish post-transmission
silence through provider termination. Destruction timestamps are notification
receipt times. FIN observations are supported by recorded kernel states;
reset origin remains UNKNOWN even when a controlled fixture knows the cause.

`LAST_CLIENT_BYTE_OBSERVED` would not establish
`FULL_HTTP_REQUEST_BODY_ACCEPTED_BY_GCP`; this mechanism makes neither claim.
A long unchanged client counter with no server counter increase is useful to
partition TCP progress, but cannot identify a TLS or backend root cause.

## Closed evidence ownership and trust

[The canonical evidence architecture](https://github.com/SecPal/.github/blob/main/docs/evidence-architecture-contract.md)
owns pipeline responsibilities. `observe-instance-transport.py` owns kernel and
process observation plus orchestration. `instance_transport_contract.py` owns
pure normalization, admission and assembly through separate public surfaces.
The exported JSON schema derives from that owner; executable agreement checks
reject schema drift. Cloud identity agreement tests consume the existing
`rocky-control.py` and `gcp-rocky-janitor.py` identity owners. Transport never
redefines their reconciliation, ownership or cleanup rules.

One `INSTANCE_INSERT_TRANSPORT_EVIDENCE` document binds repository, protected-main
control SHA, target SHA, run ID/attempt, profile, project, zone, instance name,
producer versions and monotonic window. The maximum document is 128 KiB, with
64 connections, bounded counters and at most a 3600-second observation window.
Only first/last snapshots, bounded state sets, count/activity timestamps and
closed statuses and the failing semantic observation operation persist. Overflow,
malformed input or collection failure cannot
produce successful collection. Unknown fields, identities, counter regressions,
wrong ordering and inconsistent facts fail admission. Duplicate JSON members
and oversized input are rejected before independent admission.

Protected main is freshly authenticated through GitHub before provider
credentials: exact repository, branch, checkout SHA, protected-main head and
GitHub commit verification must agree. Candidate source controls neither the
observer nor its admission. The collector receives no additional cloud
permission. The only credential consumer remains the existing producer.

`SUCCESS` means the producer exited zero. `OTHER` means a nonzero producer exit;
its error subtype is UNKNOWN. The observer does not read stdout/stderr to find
a timeout suffix. `NOT_RUN` means startup failed before apply. These closed
results do not substitute for the existing provider outcome. `COMPLETE` describes
healthy collection, not completeness of socket visibility or provider PASS;
zero correlated sockets yields `UNAVAILABLE`, with UNKNOWN endpoint/progress.

## Failure and cleanup

Observation starts before apply is launched and is finalized before the apply
step exits. Runtime failure never signals, cancels, retries or restarts the
producer. A collector failure fails the apply step even if the producer exited
zero; it cannot authorize qualification continuation. Independent artifact
admission/publication is bounded and uses `continue-on-error`, leaving exact
failed-create reconciliation and mandatory cleanup reachable. Admission or
retention failure also stops preparation and fails provisioning, while provider
success remains a separate prerequisite. No raw capture
exists to retain or delete. Atomic sanitized output uses mode 0600 and removes
its temporary sanitized file even when publication fails.

Accepted #295 reconciliation remains unchanged: ABSENT,
EXACT_RUN_OWNED_INSTANCE_PRESENT, INCOMPATIBLE_OR_AMBIGUOUS_RESOURCE and
UNKNOWN_PROVIDER_STATE remain owned by the exact provider janitor. Ambiguous
creation cannot resume qualification. Cleanup still independently requires
OPEN_TOFU_STATE_EMPTY and fresh PROVIDER_RUN_RESOURCE_SET_ABSENT for instance,
disk, network, subnet, SSH, egress-allow and egress-deny. Transport provides no
delete authority and cannot replace either check. The 10800-second TTL remains
unchanged.

## Local evidence

`python3 tests/ci-cloud-instance-transport.py` exercises real loopback sockets:
connect success, refusal, client bytes followed by silence, server bytes without
parsed headers, peer reset, local FIN/close, unrelated concurrent traffic and
multiple relevant connections. Synthetic secret-shaped payloads remain outside
all typed outputs. Kernel counters, not instrumented HTTP callbacks, own these
observations. Pure admission tests cover UNKNOWN, schema/identity agreement,
bounds, representation errors, inconsistent facts and collector failure.

Repository preflight runs this contract and the existing cloud, metadata,
architecture, reconciliation and cleanup gates. A local PASS is not a real GCP
result or acceptance on protected main.
