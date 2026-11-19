<!-- SPDX-FileCopyrightText: 2026 SecPal Contributors -->
<!-- SPDX-License-Identifier: CC0-1.0 -->

# Closed Hetzner maintenance broker

This portable capability implements inspection, Rescue and power operations for
an administrator-supplied exact server inventory. It never creates or deletes a
server, changes protection, rebuilds through the provider, forwards arbitrary
HTTP, or executes a shell. It is source preparation, not an installed service or
production qualification.

The existing [provider capability contract](provider-capability-contract.md)
owns exact-target, separately supplied authority, correlation and independent
read-back semantics. Its provisioning CRUD enum is deliberately unchanged:
Rescue and power actions retain their provider-specific vocabulary. ADR-023
owns public capability versus private inventory; ADR-024 and the canonical
[evidence architecture](https://github.com/SecPal/.github/blob/main/docs/evidence-architecture-contract.md)
own bounded authorization, evidence and acceptance. No new fleet controller,
scheduler, VPN, provider registry or general workflow engine is introduced.

## Interfaces and responsibilities

`scripts/hetzner_broker.py` contains separate executable-testable boundaries:

- `admit_request`, `Policy.from_dict`: pure closed request and policy admission;
- `HetznerTransport`: fixed TLS origin, exact allowlisted paths, bounded JSON,
  at most two GET attempts, three-second socket timeout and a 30-second dispatch
  budget, without proxy environment, redirects or mutating retries; the
  single-threaded installed service additionally has a 40-second hard request
  timer, including slow/dribbling HTTP responses;
- `normalize_server`, `normalize_action`: pure provider representation;
- `admit_server`, `admit_action`: pure exact-identity, protection and action binding;
- `assemble_reply`: pure closed result projection; and
- `execute`: orchestration of dispatch, normalization, admission and assembly.

The broader Python pure surfaces use the repository-specific closed-dependency
and effect-rejection tests in `tests/hetzner-broker.py`; they are not claims of
admission by the canonical single-return expression subset. Representative
provider observations exercise normalization through admission and wire assembly.
The exact-provider-ID check has executable agreement with
`provider-capability-contract.py::admit_result`; the broker adds the narrower
provider-specific type, architecture and protection checks. The evidence
manifest declares each bounded broker diagnostic stage, with executable
agreement against the implementation's closed stage set.

`serve` owns Unix IPC and custody admission. The final service must run as a
dedicated non-root UID distinct from the sole authorized caller UID.
`SO_PEERCRED` authenticates the connecting UID before request processing.
Administrator-owned code runs with Python isolated mode. Every code/policy
ancestor is checked for ownership, symlinks and unsafe writability. Policy has
no other-user read access; the caller must not belong to its service group.
The credential comes from systemd `LoadCredential`, never argv or an environment
variable. The normal caller cannot supply alternate server paths or credentials
through the socket.

The JSON request has exactly `operation`, plus `server_id` except for
`servers list`, `action_id` for action inspection, and a fresh 32-character
lowercase hexadecimal `request_id` for mutations. IDs are positive integers,
not strings or booleans. The supported operation strings are:

```text
servers list
server inspect
server status
server rescue enable
server rescue disable
server reboot
server power-on
server power-off
server action-status
```

The CLI accepts the same words with IDs following the operation, for example
`server inspect 101` or `server action-status 101 202`. `servers list` reads
only the policy's exact IDs; it never scans and adopts discovered resources.
Mutating CLI requests additionally require `--request-id` with an explicit
32-character lowercase hexadecimal operation identity. Record it before dispatch
and reuse it for a retry of that operation. Missing/malformed IDs fail closed;
the CLI never silently generates a fresh identity after an interrupted reply.
A new ID means a separately authorized new attempt, not a safe retry.
The wire format has no method, URL, route, command, protection or body field.

## Private policy and current non-mutation boundary

Keep actual inventory outside all Git repositories. Its closed shape is:

```json
{
  "version": 2,
  "service_uid": 2001,
  "caller_uid": 2002,
  "expires_at": 4102444800,
  "allowed_mutations": [],
  "servers": {
    "101": { "architecture": "x86", "server_type": "cx23" }
  },
  "excluded_server_ids": [104],
  "rescue_ssh_key_ids": [105]
}
```

These are synthetic examples. The `codex` socket group and caller account in
the installation example are replaceable operator choices, not required broker
identities: policy uses the exact approved caller UID. The administrator resolves actual UIDs and a
bounded execution-window expiry (Unix seconds, at most `4102444800`),
verifies every immutable ID and the existing Rescue public-key
identity, and installs the private policy. Never expand it automatically.
Initial installation requires `allowed_mutations=[]`; no client request can
override it. Later authorization names only the exact approved operation strings
from the closed mutation set; a Rescue-only grant does not enable reboot or
power-off. Version 1 boolean mutation policies are rejected rather than widened.
Excluded-server and Rescue-key lists may be empty when the approved project and
operation scope require none. Rescue enable specifically requires configured
SSH key IDs; an empty list never authorizes password-based bootstrap fallback.
Both provider protection flags must remain true even for reads.
Unexpected identity, architecture, type, protection or policy expiry fails closed.

When separately authorized later, Rescue uses fixed `linux64` and only
administrator-selected existing SSH key IDs. The returned Rescue password is
discarded, never returned or audited. Power-off is a hard provider power-off and
requires explicit future authorization for that operation.

Mutations reserve a durable SQLite idempotency record before POST. Identical
completed replays return the stored observation, not a fresh acceptance claim.
An unfinished record, conflicting reuse or full ledger refuses redispatch.
Retain the ledger through service restarts and deployments; never reset it to
retry an uncertain operation. An administrator must independently inspect the
provider result and authorize a new attempt when appropriate.

Action polling has three bounded reads, without sleep or POST resubmission.
`action.pending` is not acceptance; inspect the returned action ID later.
`applied` means provider action success and fresh server observation. It does
not prove guest boot, SSH, NetBird or workload conformance. A reboot specifically
still needs installation-bound guest boot/boot-ID evidence in a later contract.

Audit emits only broker-generated correlation IDs, admitted operation names,
numeric identities, phases and closed diagnostic codes. Raw requests, tokens,
provider errors and response bodies are excluded. Audit admission failure stops
dispatch. The response stream and journal are not authority to widen targets.

## Administrator installation boundary

No commands in this section have been run against privileged host configuration.
Installation belongs to the established host administrator. Do not grant Codex
sudo, a shared service UID, access to the credential group, or write access to
installed source, units or policy. Review source and its SHA-256 first; install
only from the reviewed revision. Do not run the daemon from a user checkout.
First seal candidate source/units in root-private staging and verify their
reviewed hashes there. Publish only verified bytes to readable installation
paths; checking after a public copy could disclose a root-readable file through
a user-controlled source symlink.

An administrator, in their existing authorized root session, performs:

1. Create the dedicated system account `secpal-hetzner-broker`, with no home and
   `/usr/sbin/nologin`. Confirm Codex is not a member of that account's group.
2. Create `/opt/secpal-hetzner` as root, mode `0755`; install the reviewed
   `scripts/hetzner_broker.py` there, root-owned mode `0644`.
3. Create `/etc/secpal-hetzner`, root-owned with group
   `secpal-hetzner-broker`, mode `0750`. Construct the private policy from the
   approved inventory, set `service_uid` to `id -u secpal-hetzner-broker`,
   `caller_uid` to `id -u codex`, expiry to the approved execution window and
   `allowed_mutations=[]`. Install it as `policy.json`, root-owned with the
   service group and mode `0640`. Do not copy a guessed service UID or expiry.
4. Through Hetzner Console, independently provision a fresh token for the exact
   approved existing project. It must never enter Codex, Git, shell arguments or service
   definitions. Supply it using a protected administrator prompt, for example:

   ```bash
   (
     set -euo pipefail
     umask 077
     temporary_key="$(mktemp /run/secpal-hetzner-key.XXXXXXXX)"
     trap 'rm -f -- "$temporary_key"' EXIT
     systemd-ask-password 'Fresh Hetzner approved-project token' > "$temporary_key"
     test -s "$temporary_key"
     install -o root -g root -m 0600 "$temporary_key" /etc/secpal-hetzner/token
   )
   ```

   Use Bash without tracing. Producer failure aborts before token installation. Read
   permission suffices for initial acceptance; future autonomous Rescue/power
   requires an independently approved Read & Write credential. Never broaden
   the broker's operation allowlist to match the credential's provider powers.
   Project token scope does not replace the broker's exact server allowlist.
   If an excluded development host shares that project, it stays excluded by
   the independently protected broker policy. This procedure neither moves
   resources nor creates a project. Delete protection is defense in depth;
   a provider credential able to remove it is not itself a deletion boundary.

5. Install the supplied `infra/hetzner-broker/secpal-hetzner.socket` and
   `.service` as root-owned `0644` files in `/etc/systemd/system`. Validate with
   `systemd-analyze verify`, reload systemd and start only
   `secpal-hetzner.socket`. No existing application/NetBird unit is changed.
6. Independently, as administrator, verify both protected files exist, are
   non-empty regular files with the prescribed owner/group/modes, and that the
   normal caller is outside the broker group. Inspect metadata only; never
   print contents. As the normal caller, run
   `python3 scripts/hetzner_boundary_check.py` and require
   `boundary.access-checks-complete`. An inaccessible parent can yield EACCES
   even for a missing child; denied reads alone therefore do not establish
   protected-file existence or complete isolation. Missing visible installation
   paths fail the check. Run the client `servers list` and exact-ID inspections
   through the socket; require a working independent service, actual provider
   read-back and both protection flags, with no mutations.
7. Identify integrations using the old token. Complete their independently
   authorized transition, then revoke that token in Hetzner Console. Verify one
   fixed direct GET with the old token returns HTTP `401`, without logging it.
   Other errors, timeouts and broker failure are not proof of revocation.
8. Confirm Codex has no other equivalent unrestricted token, accessible secret
   file, credential-bearing process environment, agent or administration path.
   Only after all administrator metadata, normal-caller access-denial, live
   read-only broker and credential-transition checks pass may isolation be
   recorded as complete. The unprivileged boundary checker cannot certify
   old-token revocation or the absence of equivalent credentials.

After installing the reviewed files, the administrator activates only this new
socket. These commands neither reboot a host nor restart an existing service:

```sh
systemd-analyze verify /etc/systemd/system/secpal-hetzner.service \
  /etc/systemd/system/secpal-hetzner.socket
systemctl daemon-reload
systemctl enable --now secpal-hetzner.socket
systemctl is-active secpal-hetzner.socket
```

Expected result: unit verification exits zero and the socket reports `active`.
The service starts on the first authorized socket request. As the normal
approved caller, from the reviewed source checkout:

```sh
python3 scripts/hetzner_boundary_check.py
python3 scripts/hetzner_broker.py servers list
```

Expected result: `boundary.access-checks-complete` with every access check true,
then `observed` with exactly the administrator-approved server IDs and both
protection flags true. This remains partial custody evidence until the separate
administrator metadata and credential-transition checks above pass. A failed
check does not authorize changing permissions, broadening the policy or using
an unguarded credential as a fallback. Check only this service's journal; audit
entries must contain closed codes and stages, never raw provider responses.

For rollback, the administrator disables this new interface and stops its
credential holder:

```sh
systemctl disable --now secpal-hetzner.socket
systemctl stop secpal-hetzner.service
systemctl is-active secpal-hetzner.socket secpal-hetzner.service
```

Expected result: both units are `inactive`; `is-active` exits nonzero. Preserve
the private policy, source hashes, credential custody and durable request ledger
for diagnosis. Do not erase the ledger, restore an exposed token or automatically
reenable an older integration. No guest, provider resource, application service
or NetBird service is changed by this rollback. Unit/source removal, account
removal and credential revocation are separate administrator decisions, not
automatic cleanup.

The old exposed token is deliberately not revoked by source preparation.
Same-UID mock tests prove behavior, never credential isolation. The dedicated
account, protected provisioning, actual denial checks and old-token revocation
remain mandatory installation acceptance boundaries.

## Validation

Run `python3 tests/hetzner-broker.py` and
`python3 tests/provider-capability-contract.py`. The broker tests use synthetic
provider-shaped observations, real local Unix peer credentials, fake transport
and durable temporary ledgers. Forbidden actions are never tested against the
provider. Live read-only qualification must separately record the source hash,
timestamp, exact admitted identities and count of GET/POST/DELETE operations
outside Git. Public tests and examples contain no live inventory.
