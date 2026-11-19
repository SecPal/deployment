<!-- SPDX-FileCopyrightText: 2026 SecPal Contributors -->
<!-- SPDX-License-Identifier: CC0-1.0 -->

# Reproduce the SecPal FCOS application proof

This fixture exercises the application on an already qualified FCOS lab host.
It composes the maintained [integration Quadlets](quadlet-integration.md)
with private HTTPS and persistent rootless volumes. The fixture is synthetic.
Use the normal Host Enrollment, Workload Activation and recovery contracts
for deployments with customer data.

## Render and stage

Record the exact reviewed Git revision and retain the private inputs and bundle
digest in the restricted qualification record. The renderer writes a fresh
directory outside Git. Its input is a unique fixture instance, a per-deployment
DNS parent, an RFC 1918 bind address and the approved ingress ports.

```bash
python3 scripts/render-fcos-application-poc.py \
  --profile stack --instance labpoc01 --domain lab.example.invalid \
  --bind-ipv4 10.0.0.28 --port 18443 --https-port 443 \
  --output /private/qualification/stack
```

The gateway is the only published role and listens on the supplied private
address. Use the site's existing WireGuard ingress approval for the external
port. Supply the matching TLS chain and key separately. Use native digest and
publisher admission for each existing image pin before staging it into the
runtime user's Podman store. Build the generated gateway Containerfile using
the pinned base, `--pull=never` and `--network=none`. Tag it
`localhost/secpal-integration-gateway-labpoc01:2.10.2` for this instance.

Authenticate the host and admit an empty slot before transferring the bundle.
Stop on any existing fixture unit, container, named volume, network or staging
directory for the selected instance. Put `assets/` under
`/var/lib/secpal-application-poc/labpoc01`, with traversable root-owned
directories and read-only, SELinux container-readable files. Supply the
chain at `tls/fullchain.pem` and the private key at `tls/leaf.key` with read
access for only the mapped gateway identity as needed. Install the generated
units as administrator-owned files in the existing rootless user's Quadlet
directory, with its normal SELinux labels. Keep real TLS material and test
passwords outside the rendered bundle and logs.

## Initialize, verify and restart

Run through the host's admitted runtime user and user manager. The examples
assume the PoC instance and namespace above.

```bash
prefix=secpal-int-labpoc01
systemctl --user daemon-reload
systemctl --user start "$prefix-secrets-init.service"
systemctl --user start "$prefix-postgres.service"
systemctl --user start "$prefix-migrate.service"
systemctl --user start "$prefix-gateway.service" "$prefix-scheduler.service" \
  "$prefix-worker-general.service" "$prefix-worker-hash-chain.service"
```

Only initialize a fresh fixture. The initializer creates disposable local
credentials and PostgreSQL TLS material. It uses the same database role for
runtime and migration as the synthetic integration fixture. The two explicit
one-shots are outside the normal boot dependency chain. The worker, scheduler
and gateway units start through the existing lingering user manager.

Create a random 48-character hexadecimal synthetic account password in a
private file. Run `scripts/seed-fcos-application-poc.php` with PHP inside the
admitted fixture's FPM container, supplying the password on stdin. For example,
on the guest with the reviewed script available to the runtime user:

```bash
podman exec -i "$prefix-php-fpm" php -r "$(tail -n +2 /private/seed-fcos-application-poc.php)" \
  < /private/fixture-password
```

Verify PostgreSQL readiness and TLS/SCRAM, HTTPS with normal certificate
validation, and login and authenticated organization reads with the synthetic
account. Verify the same organization ID in PostgreSQL. For a persistence
check, stop the exact eight running role services, start PostgreSQL, then start
the gateway and background services as above. Check that the database
container was recreated, the cluster identifier and volume stayed the same
and the authenticated record remains. The restart skips both one-shots.

For teardown, verify the fixture instance, container/volume ownership and
database identity. Stop only its services, including both one-shots. Remove
only its named volumes, private networks, added gateway tag, unit files and
staged directory, then reload the user manager. Verify that the fixture is
absent and the pre-existing applications and volumes are healthy.

## Cross-host logical restore

The restore bundle runs only PostgreSQL, API and FPM on a new internal network
and separate volumes. It has no published port, boot activation, frontend,
scheduler or workers. Render it from the same reviewed source:

```bash
python3 scripts/render-fcos-application-poc.py \
  --profile restore --instance labrestore01 --output /private/qualification/restore
```

Select a synthetic record already confirmed through the source API and SQL.
Capture the schema, record and any file dependencies. Stream a consistent
`pg_dump --format=custom` through pinned SSH into encrypted off-source
storage. Keep decryption material separately protected. Verify the archive
digest, table of contents and full decoding before admitting a restore.

Stage the restore bundle on a different authenticated host and start only
`secrets-init` and `postgres`. Check a fresh empty schema, independent cluster
identity and named volume, then stream the authenticated archive to
`pg_restore --single-transaction --exit-on-error --no-owner --no-acl` on that
cluster. Apply the schema from the archive. Compare the schema and exact
synthetic record, start the API and verify unauthenticated rejection and an
authenticated read within its internal network. Use an isolated test token
and revoke it after the read. Recreate the PostgreSQL container and repeat
the checks. Preserve bounded evidence and follow the scoped cleanup above.

This checks logical restoration of the exercised state. It leaves WAL/PITR,
retention, independent recovery-crypto custody, private object recovery,
RecoverySets and production activation to their existing contracts.
