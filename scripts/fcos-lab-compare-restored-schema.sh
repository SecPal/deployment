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
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

root = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(root / "scripts"))
from fcos_lab_rollout_adapter import verify_dispatch_authority

validator = Path(sys.argv[2]).absolute()
if validator.is_symlink():
    raise ValueError("schema rehearsal validator must be a regular file")
verify_dispatch_authority(validator, (root / "scripts/render-fcos-application-poc.py").read_bytes())
declaration = json.loads((root / ".secpal/evidence-architecture.json").read_bytes())
helper = Path(sys.argv[3]).read_text()
stages = re.findall(r"^\s*stage=([a-z][a-z-]+)$", helper, flags=re.MULTILINE)
required = {"input", "admission", "isolated-container", "cleanup", "restored-catalog",
            "native-replay", "restored-schema", "enrolled-fingerprint"}
prefix = "fcos-schema-rehearsal."
operations = declaration["external_operations"]
if len(stages) != len(required) or set(stages) != required or any(
    operation["id"].startswith(prefix) for operation in operations
):
    raise ValueError("schema rehearsal diagnostics differ from the closed operation set")
for stage in sorted(required):
    identity = prefix + stage
    operations.append({"id": identity, "reachable": True, "fallible": True, "trusted": True,
                       "diagnostic_identity": {"id": identity, "kind": "semantic"}})
with tempfile.TemporaryDirectory(prefix="fcos-schema-admission-") as directory:
    snapshot = Path(directory)
    (snapshot / "AGENTS.md").write_bytes((root / "AGENTS.md").read_bytes())
    (snapshot / ".secpal").mkdir()
    (snapshot / ".secpal/evidence-architecture.json").write_text(json.dumps(declaration))
    subprocess.run([sys.executable, "-I", "-S", validator, "--repository-root", snapshot,
                    "--repository", "SecPal/deployment", "--dispatch"],
                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   check=True, timeout=60)
' "$script_dir/.." "$validator" "${BASH_SOURCE[0]}"

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
if [[ $(jq -er '.server_version_num' "$source_catalog") != "$(jq -er '.server_version_num' "$scratch/restored-catalog")" ]]; then
    printf '%s\n' 'fcos-schema-rehearsal.restored-catalog: PostgreSQL versions differ' >&3
    exit 1
fi
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
