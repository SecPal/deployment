#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail
umask 077
exec 3>&2
exec >/dev/null 2>&1

stage=input
retire=false
finish() {
    local status=$? failure=$stage
    trap - EXIT
    if (( status != 0 )); then
        printf 'fcos-db-roles.%s: failed\n' "$failure" >&3
    fi
    if $retire; then
        stage=disable-migration-login
        sql -c 'ALTER ROLE secpal_poc_migrate NOLOGIN PASSWORD NULL' || report_cleanup_failure
        stage=stop-migrator
        systemctl --user stop "$service" || report_cleanup_failure
        stage=remove-migration-credentials
        remove_migration_credentials || report_cleanup_failure
    fi
    if (( status != 0 )); then exit "$status"; fi
    if $retire; then
        printf '%s\n' 'Explicit migration succeeded. Migration login and credential delivery retired.' >&3
    fi
}

report_cleanup_failure() {
    printf 'fcos-db-roles.%s: failed\n' "$stage" >&3
    status=1
}

trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
if [[ $# != 2 || ! $2 =~ ^[a-z0-9]{8,24}$ || ( $1 != prepare && $1 != migrate ) ]]; then
    printf '%s\n' 'Usage: fcos-poc-db-roles.sh prepare|migrate FIXTURE_INSTANCE' >&3
    exit 64
fi

instance=$2
prefix=secpal-int-$instance
unit=/etc/containers/systemd/users/$(id -u)/$prefix-postgres.container
service=$prefix-migrate.service
stage=rootless-runtime
test "$(podman info --format '{{.Host.Security.Rootless}}')" = true
stage=generated-unit
grep -Fxq 'Label=org.secpal.fcos.database-roles=separated' "$unit"
stage=secret-volume
storage=$(podman volume inspect --format '{{.Mountpoint}}' "$prefix-secrets")
test "$(podman volume inspect --format '{{index .Labels "org.secpal.integration.instance"}}' "$prefix-secrets")" = "$instance"

if [[ $1 == prepare ]]; then
    stage=fresh-container
    if podman container exists "$prefix-postgres"; then exit 1; else test "$?" -eq 1; fi
    stage=prepare-credential-roots
    podman unshare bash -s -- "$storage" <<'PREPARE'
set -euo pipefail
umask 077
storage=$1
test ! -e "$storage/postgresql/bootstrap-password"
test ! -e "$storage/runtime-database"
test ! -e "$storage/migration-database"
for purpose in runtime migration; do
    directory=$storage/$purpose-database
    mkdir -m 0700 "$directory"
    case "$purpose" in
        runtime) printf 'secpal_poc_runtime\n' > "$directory/postgres-username" ;;
        migration) printf 'secpal_poc_migrate\n' > "$directory/postgres-username" ;;
    esac
    openssl rand -hex 32 > "$directory/postgres-password"
    cp -- "$storage/postgresql/server.crt" "$directory/postgres-ca.crt"
    chown 10001:10001 "$directory" "$directory"/*
    chmod 0400 "$directory"/*
done
PREPARE
    stage=install-transport-policy
    podman unshare bash -s -- "$storage" <<'TRANSPORT'
set -euo pipefail
umask 077
storage=$1
install -o 999 -g 999 -m 0400 "$storage/postgres-password" "$storage/postgresql/bootstrap-password"
cat > "$storage/pg_hba.separated" <<'HBA'
local all secpal_fixture_admin trust
local all all reject
hostssl secpal +secpal_runtime,+secpal_migration 0.0.0.0/0 scram-sha-256
hostssl secpal +secpal_runtime,+secpal_migration ::/0 scram-sha-256
host all all 0.0.0.0/0 reject
host all all ::/0 reject
HBA
chown 999:999 "$storage/pg_hba.separated"
chmod 0400 "$storage/pg_hba.separated"
mv -- "$storage/pg_hba.separated" "$storage/postgresql/pg_hba.conf"
TRANSPORT
    printf '%s\n' 'Prepared separate database credential roots and TLS/SCRAM policy.' >&3
    exit 0
fi

sql() {
    podman exec -i "$prefix-postgres" psql -X -q -v ON_ERROR_STOP=1 +        -U secpal_fixture_admin -d secpal "$@"
}

stage=empty-cluster
test "$(sql -At -c "SELECT current_user = 'secpal_fixture_admin' AND
    NOT EXISTS (SELECT FROM pg_roles WHERE rolname LIKE 'secpal_poc_%') AND
    NOT EXISTS (SELECT FROM pg_tables WHERE schemaname = 'public')")" = t

stage=grant-role-contract
sql <<'SQL'
BEGIN;
CREATE ROLE secpal_owner NOLOGIN;
CREATE ROLE secpal_runtime NOLOGIN;
CREATE ROLE secpal_migration NOLOGIN;
CREATE ROLE secpal_poc_runtime NOLOGIN;
CREATE ROLE secpal_poc_migrate NOLOGIN;
GRANT secpal_runtime TO secpal_poc_runtime WITH ADMIN FALSE, INHERIT TRUE, SET FALSE;
GRANT secpal_migration TO secpal_poc_migrate WITH ADMIN FALSE, INHERIT TRUE, SET TRUE;
GRANT secpal_owner TO secpal_migration WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;
ALTER DATABASE secpal OWNER TO secpal_owner;
REVOKE ALL ON DATABASE secpal, postgres, template0, template1 FROM PUBLIC;
GRANT CONNECT ON DATABASE secpal TO secpal_runtime, secpal_migration;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
ALTER SCHEMA public OWNER TO secpal_owner;
GRANT USAGE ON SCHEMA public TO secpal_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE secpal_owner IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO secpal_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE secpal_owner IN SCHEMA public
    GRANT USAGE ON SEQUENCES TO secpal_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE secpal_owner REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
COMMIT;
SQL

remove_migration_credentials() {
    podman unshare bash -c '
        set -eu
        rm -- "$1/postgres-password" "$1/postgres-username" "$1/postgres-ca.crt"
        rmdir -- "$1"
    ' bash "$storage/migration-database"
}
retire=true

password() {
    podman unshare bash -c 'cat -- "$1"; cat -- "$1"' bash "$storage/$1-database/postgres-password" |
        sql -c "\\password $2"
}
stage=set-runtime-password
password runtime secpal_poc_runtime
stage=set-migration-password
password migration secpal_poc_migrate
stage=enable-logins
expires=$(date -u -d '+10 minutes' '+%Y-%m-%d %H:%M:%S+00')
sql -v expires="$expires" <<'SQL'
BEGIN;
ALTER ROLE secpal_poc_runtime LOGIN;
ALTER ROLE secpal_poc_migrate LOGIN VALID UNTIL :'expires';
COMMIT;
SQL
stage=start-migration
systemctl --user start "$service"
stage=migration-result
test "$(systemctl --user show --property=Result --value "$service")" = success
stage=restrict-migration-ledger
sql -c 'REVOKE INSERT, UPDATE, DELETE ON TABLE public.migrations FROM secpal_runtime'
