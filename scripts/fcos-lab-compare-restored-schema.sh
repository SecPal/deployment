#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

# Compare a native PostgreSQL 18 restore against the enrolled schema.
set -euo pipefail
export LC_ALL=C
umask 077

if [[ $# != 3 ]]; then
    printf '%s\n' 'usage: fcos-lab-compare-restored-schema.sh SOURCE_DUMP SOURCE_CATALOG DISPOSABLE_CONTAINER' >&2
    exit 2
fi

source_dump=$1
source_catalog=$2
container=$3
for file in "$source_dump" "$source_catalog"; do
    [[ -f $file && ! -L $file && -s $file ]] || exit 2
done
[[ $container =~ ^secpal-update-proof-[a-zA-Z0-9]+$ ]] || exit 2
[[ $(podman inspect --format '{{index .Config.Labels "io.secpal.fcos.schema-rehearsal"}} {{.HostConfig.NetworkMode}}' \
    "$container") == 'true none' ]] || exit 2

catalog_sql=$(dirname -- "${BASH_SOURCE[0]}")/fcos-lab-check-catalog.sql
[[ -f $catalog_sql && ! -L $catalog_sql ]] || exit 2
scratch=$(mktemp -d)
replay=secpal_schema_replay
created=false
pg() {
    podman exec -i --user postgres "$container" "$@"
}
cleanup() {
    if [[ $created == true ]]; then
        pg dropdb -w -U postgres "$replay" || return 1
    fi
    unlink "$scratch/restored-catalog" 2>/dev/null || :
    unlink "$scratch/source-checks" 2>/dev/null || :
    unlink "$scratch/restored-checks" 2>/dev/null || :
    unlink "$scratch/replayed-schema" 2>/dev/null || :
    unlink "$scratch/restored-schema" 2>/dev/null || :
    rmdir -- "$scratch"
}
trap cleanup EXIT
normalize_dump() {
    sed -E '/^\\(un)?restrict /d' -- "$1"
}
cluster() {
    jq -er -s '
        select(length == 1) | .[0]
        | select(type == "object" and (.server_version_num | type == "number")
            and .server_version_num >= 180000 and .server_version_num < 190000
            and (.checks | type == "array"))
        | .cluster | select(type == "string" and test("^[0-9]+$"))
    ' "$1"
}

pg psql -X -w -qAt -v ON_ERROR_STOP=1 -U postgres -d secpal < "$catalog_sql" > "$scratch/restored-catalog"
enrolled_cluster=$(cluster "$source_catalog")
restored_cluster=$(cluster "$scratch/restored-catalog")
[[ $enrolled_cluster != "$restored_cluster" ]]
jq -cS 'del(.cluster)' "$source_catalog" > "$scratch/source-checks"
jq -cS 'del(.cluster)' "$scratch/restored-catalog" > "$scratch/restored-checks"
if ! cmp -s "$scratch/source-checks" "$scratch/restored-checks"; then
    printf '%s\n' 'Restored CHECK properties, types or dependency identities differ' >&2
    exit 1
fi

pg createdb -w -U postgres -O secpal_owner -T template0 "$replay"
created=true
pg psql -X -w -q -v ON_ERROR_STOP=1 -U postgres -d "$replay" \
    -c 'ALTER SCHEMA public OWNER TO secpal_owner' >/dev/null
pg psql -X -w -q -v ON_ERROR_STOP=1 -U postgres -d "$replay" \
    -c 'SET ROLE secpal_owner' -f - < "$source_dump" >/dev/null
pg pg_dump --schema-only --no-owner --no-privileges -U postgres -d "$replay" |
    normalize_dump /dev/stdin > "$scratch/replayed-schema"
pg pg_dump --schema-only --no-owner --no-privileges -U postgres -d secpal |
    normalize_dump /dev/stdin > "$scratch/restored-schema"
if ! cmp -s "$scratch/replayed-schema" "$scratch/restored-schema"; then
    printf '%s\n' 'Restored schema differs after PostgreSQL replay of the enrolled DDL' >&2
    exit 1
fi

# The activation guard still uses the exact enrolled schema.
normalize_dump "$source_dump" | sha256sum | cut -d ' ' -f 1
