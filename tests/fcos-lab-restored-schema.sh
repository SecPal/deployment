#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT
set -euo pipefail
umask 077

cd "$(dirname -- "${BASH_SOURCE[0]}")/.."
image=${1:?supply the exact PostgreSQL 18 image digest}
validator=${2:?supply the pinned evidence architecture validator}
[[ $image =~ ^docker\.io/library/postgres@sha256:[a-f0-9]{64}$ ]]
work=$(mktemp -d)
source_id=
restore_id=
cleanup() {
    if [[ -n $restore_id ]]; then podman rm -f -v "$restore_id" >/dev/null; fi
    if [[ -n $source_id ]]; then podman rm -f -v "$source_id" >/dev/null; fi
    local file
    for file in "$work/schema" "$work/counters" "$work/other-version" "$work/pg_hba.conf"; do
        if [[ -e $file ]]; then unlink "$file"; fi
    done
    rmdir -- "$work"
}
trap cleanup EXIT

cat > "$work/pg_hba.conf" <<'HBA'
local all secpal_fixture_admin trust
local all all reject
host all all 0.0.0.0/0 reject
host all all ::/0 reject
HBA
chmod 0444 "$work/pg_hba.conf"

suffix=${work##*.}
enrolled="secpal-enrolled-proof-$suffix"
clone="secpal-update-proof-$suffix"
new_cluster() {
    podman run -d --pull=never --network none --name "$1" \
        --label io.secpal.fcos.schema-rehearsal=true \
        --env POSTGRES_HOST_AUTH_METHOD=trust --env POSTGRES_DB=secpal \
        --env POSTGRES_USER=secpal_fixture_admin \
        --volume "$work/pg_hba.conf:/run/rehearsal-hba.conf:ro,z" \
        "$image" -c listen_addresses= -c hba_file=/run/rehearsal-hba.conf
}
psql_for() {
    local container=$1
    shift
    podman exec -i --user postgres "$container" psql -X -qAt -w -v ON_ERROR_STOP=1 -U secpal_fixture_admin -d secpal "$@"
}
ready() {
    for _ in {1..40}; do
        if [[ $(psql_for "$1" -c "SELECT NOT pg_is_in_recovery() AND (SELECT count(*) FROM pg_stat_activity WHERE backend_type='checkpointer')=1" 2>/dev/null) == t ]] &&
            podman exec "$1" sh -c 'test "$(tr "\000" " " < /proc/1/cmdline | cut -d " " -f1)" = postgres'; then
            return 0
        fi
        sleep 1
    done
    return 1
}

source_id=$(new_cluster "$enrolled")
restore_id=$(new_cluster "$clone")
ready "$enrolled"
ready "$clone"
if podman exec --user postgres "$clone" psql -X -w -U postgres -d secpal -c 'SELECT 1' >/dev/null 2>&1; then
    printf '%s\n' 'The isolated transport unexpectedly allowed an alternate administrator' >&2
    exit 1
fi
for container in "$enrolled" "$clone"; do
    psql_for "$container" -c 'CREATE ROLE secpal_owner NOLOGIN; ALTER SCHEMA public OWNER TO secpal_owner'
done

psql_for "$enrolled" <<'SQL'
CREATE FUNCTION public.allowed_value(val integer) RETURNS boolean LANGUAGE sql IMMUTABLE RETURN val >= 2;
CREATE FUNCTION public.other_value(val integer) RETURNS boolean LANGUAGE sql IMMUTABLE RETURN val >= 2;
CREATE TABLE public.fixture (
    value integer CONSTRAINT range_check CHECK (((value >= 2))),
    state varchar(16) CONSTRAINT state_check CHECK (state::text = ANY ((ARRAY['open'::varchar, 'closed'::varchar])::text[])),
    external_value integer CONSTRAINT function_check CHECK (public.allowed_value(external_value))
);
SQL
podman exec --user postgres "$enrolled" pg_dump --schema-only --no-owner --no-privileges -U secpal_fixture_admin -d secpal > "$work/schema"
psql_for "$enrolled" < scripts/fcos-lab-check-catalog.sql > "$work/counters"
psql_for "$clone" < "$work/schema"
actual=$(scripts/fcos-lab-compare-restored-schema.sh "$validator" "$work/schema" "$work/counters" "$clone")
expected=$(sed -E '/^\\(un)?restrict /d' -- "$work/schema" | sha256sum | cut -d ' ' -f 1)
[[ $actual == "$expected" ]]

jq '.server_version_num += 1' "$work/counters" > "$work/other-version"
if report=$(scripts/fcos-lab-compare-restored-schema.sh "$validator" "$work/schema" "$work/other-version" "$clone" 2>&1); then
    printf '%s\n' 'A PostgreSQL version mismatch was admitted' >&2
    exit 1
fi
[[ $report == *'fcos-schema-rehearsal.restored-catalog: PostgreSQL versions differ'* ]]

rejected() {
    local sql=$1 wanted=$2 report
    psql_for "$clone" -c "$sql"
    if report=$(scripts/fcos-lab-compare-restored-schema.sh "$validator" "$work/schema" "$work/counters" "$clone" 2>&1); then
        printf '%s\n' 'Structurally different restore was admitted' >&2
        return 1
    fi
    [[ $report == *"$wanted"* ]]
}
rejected 'ALTER TABLE public.fixture DROP CONSTRAINT range_check;
          ALTER TABLE public.fixture ADD CONSTRAINT range_check CHECK (value > 2)' 'fcos-schema-rehearsal.restored-schema: enrolled and restored schemas differ'
psql_for "$clone" -c 'ALTER TABLE public.fixture DROP CONSTRAINT range_check;
                      ALTER TABLE public.fixture ADD CONSTRAINT range_check CHECK (value >= 2)'
rejected 'ALTER TABLE public.fixture DROP CONSTRAINT function_check;
          ALTER TABLE public.fixture ADD CONSTRAINT function_check CHECK (public.other_value(external_value))' \
    'fcos-schema-rehearsal.restored-catalog: CHECK properties, types or dependencies differ'
psql_for "$clone" -c 'ALTER TABLE public.fixture DROP CONSTRAINT function_check;
                      ALTER TABLE public.fixture ADD CONSTRAINT function_check CHECK (public.allowed_value(external_value))'
rejected 'ALTER TABLE public.fixture DROP CONSTRAINT range_check;
          ALTER TABLE public.fixture ADD CONSTRAINT range_check CHECK (value >= 2) NOT VALID' \
    'fcos-schema-rehearsal.restored-catalog: CHECK properties, types or dependencies differ'
printf '%s\n' 'Native PostgreSQL admitted the replayed schema and rejected different operators, function references and validation state.'
