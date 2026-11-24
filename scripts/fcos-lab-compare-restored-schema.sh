#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

# Compare a native PostgreSQL 18 restore against the enrolled schema.
set -euo pipefail
export LC_ALL=C
umask 077

exec 3>&2 2>/dev/null
stage=input
trap 'printf "fcos-schema-rehearsal.%s: failed\n" "$stage" >&3' ERR
if [[ $# != 4 ]]; then
    printf '%s\n' 'usage: fcos-lab-compare-restored-schema.sh VALIDATOR SOURCE_DUMP SOURCE_CATALOG DISPOSABLE_CONTAINER' >&3
    exit 2
fi

validator=$1
source_dump=$2
source_catalog=$3
container=$4
for file in "$source_dump" "$source_catalog"; do
    [[ -f $file && ! -L $file && -s $file ]] || { printf "fcos-schema-rehearsal.%s: failed\n" "$stage" >&3; exit 2; }
done
[[ $container =~ ^secpal-update-proof-[a-zA-Z0-9]+$ ]] || { printf "fcos-schema-rehearsal.%s: failed\n" "$stage" >&3; exit 2; }
script_dir=$(dirname -- "${BASH_SOURCE[0]}")
stage=admission
python3 -I -S -c '
from pathlib import Path
import runpy
import sys

renderer = runpy.run_path(sys.argv[1])
renderer["admit_database_dispatch"](Path(sys.argv[2]), schema_rehearsal=True)
' "$script_dir/render-fcos-application-poc.py" "$validator"

stage=isolated-container
[[ $(podman inspect --format '{{index .Config.Labels "io.secpal.fcos.schema-rehearsal"}} {{.HostConfig.NetworkMode}}' \
    "$container") == 'true none' ]] || { printf "fcos-schema-rehearsal.%s: failed\n" "$stage" >&3; exit 2; }

catalog_sql=$script_dir/fcos-lab-check-catalog.sql
[[ -f $catalog_sql && ! -L $catalog_sql ]] || { printf "fcos-schema-rehearsal.%s: failed\n" "$stage" >&3; exit 2; }
scratch=$(mktemp -d)
replay=secpal_schema_replay
created=false
pg() {
    podman exec -i --user postgres "$container" "$@"
}
cleanup() {
    if [[ $created == true ]] && ! pg dropdb -w -U secpal_fixture_admin "$replay"; then
        stage=cleanup
        printf "fcos-schema-rehearsal.%s: failed\n" "$stage" >&3
        return 1
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

stage=restored-catalog
pg psql -X -w -qAt -v ON_ERROR_STOP=1 -U secpal_fixture_admin -d secpal < "$catalog_sql" > "$scratch/restored-catalog"
enrolled_cluster=$(cluster "$source_catalog")
restored_cluster=$(cluster "$scratch/restored-catalog")
[[ $enrolled_cluster != "$restored_cluster" ]]
jq -cS 'del(.cluster)' "$source_catalog" > "$scratch/source-checks"
jq -cS 'del(.cluster)' "$scratch/restored-catalog" > "$scratch/restored-checks"
if ! cmp -s "$scratch/source-checks" "$scratch/restored-checks"; then
    printf '%s\n' 'fcos-schema-rehearsal.restored-catalog: CHECK properties, types or dependencies differ' >&3
    exit 1
fi

stage=native-replay
pg createdb -w -U secpal_fixture_admin -O secpal_owner -T template0 "$replay"
created=true
pg psql -X -w -q -v ON_ERROR_STOP=1 -U secpal_fixture_admin -d "$replay" \
    -c 'ALTER SCHEMA public OWNER TO secpal_owner' >/dev/null
pg psql -X -w -q -v ON_ERROR_STOP=1 -U secpal_fixture_admin -d "$replay" \
    -c 'SET ROLE secpal_owner' -f - < "$source_dump" >/dev/null
stage=restored-schema
pg pg_dump --schema-only --no-owner --no-privileges -U secpal_fixture_admin -d "$replay" |
    normalize_dump /dev/stdin > "$scratch/replayed-schema"
pg pg_dump --schema-only --no-owner --no-privileges -U secpal_fixture_admin -d secpal |
    normalize_dump /dev/stdin > "$scratch/restored-schema"
if ! cmp -s "$scratch/replayed-schema" "$scratch/restored-schema"; then
    printf '%s\n' 'fcos-schema-rehearsal.restored-schema: enrolled and restored schemas differ' >&3
    exit 1
fi

# The activation guard still uses the exact enrolled schema.
stage=enrolled-fingerprint
normalize_dump "$source_dump" | sha256sum | cut -d ' ' -f 1
