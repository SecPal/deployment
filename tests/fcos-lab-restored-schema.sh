#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT
set -euo pipefail
umask 077

cd "$(dirname -- "${BASH_SOURCE[0]}")/.."
image=${1:?supply the exact PostgreSQL 18 image digest}
[[ $image =~ ^docker\.io/library/postgres@sha256:[a-f0-9]{64}$ ]]
work=$(mktemp -d)
source_id=
restore_id=
cleanup() {
    if [[ -n $restore_id ]]; then podman rm -f -v "$restore_id" >/dev/null; fi
    if [[ -n $source_id ]]; then podman rm -f -v "$source_id" >/dev/null; fi
    unlink "$work/schema"
    unlink "$work/counters"
    rmdir -- "$work"
}
trap cleanup EXIT

suffix=${work##*.}
enrolled="secpal-enrolled-proof-$suffix"
clone="secpal-update-proof-$suffix"
new_cluster() {
    podman run -d --pull=never --network none --name "$1" \
        --label io.secpal.fcos.schema-rehearsal=true \
        --env POSTGRES_HOST_AUTH_METHOD=trust --env POSTGRES_DB=secpal \
        "$image" -c listen_addresses=
}
psql_for() {
    local container=$1
    shift
    podman exec -i --user postgres "$container" psql -X -qAt -w -v ON_ERROR_STOP=1 -U postgres -d secpal "$@"
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
podman exec --user postgres "$enrolled" pg_dump --schema-only --no-owner --no-privileges -U postgres -d secpal > "$work/schema"
psql_for "$enrolled" < scripts/fcos-lab-check-catalog.sql > "$work/counters"
psql_for "$clone" < "$work/schema"
actual=$(scripts/fcos-lab-compare-restored-schema.sh "$work/schema" "$work/counters" "$clone")
expected=$(sed -E '/^\\(un)?restrict /d' -- "$work/schema" | sha256sum | cut -d ' ' -f 1)
[[ $actual == "$expected" ]]

rejected() {
    local sql=$1 wanted=$2 report
    psql_for "$clone" -c "$sql"
    if report=$(scripts/fcos-lab-compare-restored-schema.sh "$work/schema" "$work/counters" "$clone" 2>&1); then
        printf '%s\n' 'Structurally different restore was admitted' >&2
        return 1
    fi
    [[ $report == *"$wanted"* ]]
}
rejected 'ALTER TABLE public.fixture DROP CONSTRAINT range_check;
          ALTER TABLE public.fixture ADD CONSTRAINT range_check CHECK (value > 2)' 'schema differs after PostgreSQL replay'
psql_for "$clone" -c 'ALTER TABLE public.fixture DROP CONSTRAINT range_check;
                      ALTER TABLE public.fixture ADD CONSTRAINT range_check CHECK (value >= 2)'
rejected 'ALTER TABLE public.fixture DROP CONSTRAINT function_check;
          ALTER TABLE public.fixture ADD CONSTRAINT function_check CHECK (public.other_value(external_value))' \
    'CHECK properties, types or dependency identities differ'
psql_for "$clone" -c 'ALTER TABLE public.fixture DROP CONSTRAINT function_check;
                      ALTER TABLE public.fixture ADD CONSTRAINT function_check CHECK (public.allowed_value(external_value))'
rejected 'ALTER TABLE public.fixture DROP CONSTRAINT range_check;
          ALTER TABLE public.fixture ADD CONSTRAINT range_check CHECK (value >= 2) NOT VALID' \
    'CHECK properties, types or dependency identities differ'
printf '%s\n' 'Native PostgreSQL admitted the replayed schema and rejected different operators, function references and validation state.'
