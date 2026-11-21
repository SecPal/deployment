#!/usr/bin/bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

# Installed as an administrator-owned executable on the three FCOS guests.
set -euo pipefail
export PATH=/usr/bin:/usr/sbin LC_ALL=C
umask 077

store=/var/lib/secpal-fcos-lab-rollout
policy=/etc/secpal-fcos-lab-rollout/guest.json
peer=/usr/local/libexec/secpal-fcos-lab-rollout
slot=secpal-int-haproxy01
units=/etc/containers/systemd/users/20000
security_units=/etc/containers/systemd/users/20001
assets=/var/lib/secpal-application-poc/haproxy01
frontend=$slot-frontend
dropin_dir=$units/$frontend.container.d
dropin=$dropin_dir/90-rollout.conf
image=ghcr.io/secpal/frontend
origin=https://github.com/SecPal/deployment.git
branch=refs/remotes/release/main
contract=scripts/integration_runtime_contract.py
digest='sha256:[a-f0-9]{64}'
sha='[a-f0-9]{40}'
hash='[a-f0-9]{64}'
roles=(api php-fpm frontend worker-general worker-hash-chain scheduler postgres gateway crowdsec spoa)
backend_roles=(api php-fpm worker-general worker-hash-chain scheduler)
api_image=ghcr.io/secpal/api

deny() { printf '%s\n' 'FCOS lab guest rejected the operation' >&2; exit 1; }

as_user() {
    local name=$1 uid=$2
    shift 2
    runuser -u "$name" -- env -i PATH=/usr/bin:/usr/sbin \
        HOME="/var/home/$name" XDG_RUNTIME_DIR="/run/user/$uid" \
        DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" "$@"
}

runtime() { as_user secpal-runtime 20000 "$@"; }
security() { as_user secpal-lab-sec01 20001 "$@"; }

git_object() {
    env -i PATH=/usr/bin:/usr/sbin HOME=/ GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
        GIT_ALLOW_PROTOCOL=https GIT_TERMINAL_PROMPT=0 timeout 180 git -C "$store/release.git" "$@"
}

refresh() { git_object fetch -q --no-tags "$origin" "refs/heads/main:$branch"; }

fingerprint() {
    git_object ls-tree -r -z --full-tree "$1" -- "${inputs[@]}" | sha256sum | cut -d ' ' -f 1
}

admitted() {
    git_object merge-base --is-ancestor "$1" "$branch" &&
        [[ $(fingerprint "$1") == "$2" ]]
}

frontend_field() {
    local source rows prefix=''
    source=$(git_object show "$1:$contract") || return 1
    if grep -Eq '^LAB_FRONTEND_(DIGEST|SOURCE_COMMIT)[[:blank:]]*=' <<< "$source"; then
        prefix=LAB_
    fi
    rows=$(sed -nE "s/^${prefix}$2 = \"($3)\"$/\1/p" <<< "$source") || return 1
    [[ $rows =~ ^$3$ ]] || return 1
    printf '%s\n' "$rows"
}

without_lab_pins() {
    git_object show "$1:$contract" |
        sed -E '/^LAB_(FRONTEND|API|PHP_FPM|API_PAIR)_DIGEST = "sha256:[a-f0-9]{64}"$/d;
                /^LAB_(FRONTEND|API)_SOURCE_COMMIT = "[a-f0-9]{40}"$/d;
                /^LAB_API_VEX_EXPIRES_AT = "[0-9T:Z-]+"$/d'
}

lab_pins_only() {
    git_object diff --quiet --no-ext-diff "$foundation" "$1" -- "${frozen_sources[@]}" &&
        [[ $(without_lab_pins "$foundation") == "$(without_lab_pins "$1")" ]] &&
        frontend_field "$1" FRONTEND_DIGEST "$digest" >/dev/null &&
        frontend_field "$1" FRONTEND_SOURCE_COMMIT "$sha" >/dev/null
}

backend_field() {
    local source rows prefix=''
    source=$(git_object show "$1:$contract") || return 1
    if grep -Eq '^LAB_(API_(DIGEST|PAIR_DIGEST|SOURCE_COMMIT|VEX_EXPIRES_AT)|PHP_FPM_DIGEST)[[:blank:]]*=' <<< "$source"; then
        prefix=LAB_
    fi
    rows=$(sed -nE "s/^${prefix}$2 = \"($3)\"$/\1/p" <<< "$source") || return 1
    [[ $rows =~ ^$3$ ]] || return 1
    printf '%s\n' "$rows"
}

backend_pins() {
    backend_field "$1" API_SOURCE_COMMIT "$sha" &&
        backend_field "$1" API_PAIR_DIGEST "$digest" &&
        backend_field "$1" API_DIGEST "$digest" &&
        backend_field "$1" PHP_FPM_DIGEST "$digest" &&
        backend_field "$1" API_VEX_EXPIRES_AT '[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]{8}Z'
}

parse_request() {
    local file=$1 line
    local -a fields
    IFS= read -r line < "$file" || return 1
    [[ $(stat -c %s -- "$file") == $(("${#line}" + 1)) ]] || return 1
    read -r -a fields <<< "$line"
    [[ ${#fields[@]} == 8 && ${fields[*]} == "$line" ]] || return 1
    operation=${fields[0]}
    [[ ${fields[1]} == "$host" && ${fields[2]} == "$platform" ]] || return 1
    revision=${fields[3]} wanted=${fields[4]} previous=${fields[5]} prior=${fields[6]} child=${fields[7]}
    [[ $revision =~ ^$sha$ && $previous =~ ^$sha$ && $wanted =~ ^$hash$ && $prior =~ ^$hash$ ]] || return 1
    case "$operation" in
        prepare) [[ $child =~ ^$digest$ ]];;
        observe|activate|accept|rollback) [[ $child == - ]];;
        *) return 1;;
    esac
}

trusted_directory() {
    [[ -d $1 && ! -L $1 && $(stat -c '%u %g %a' -- "$1") == "$2" ]]
}

frozen_layout() {
    exact_rollout_dropin || return 1
    local role directory
    for role in "${backend_roles[@]}"; do
        directory=$units/$slot-$role.container.d
        if [[ -e $directory || -L $directory ]]; then
            trusted_directory "$directory" '0 0 755' &&
                [[ -z $(find "$directory" -mindepth 1 -maxdepth 1 ! -name '90-rollout.conf' -print -quit) ]] || return 1
        fi
    done
    # These fixture inputs contain configuration and code. The private
    # runtime, data, certificate and credential directories are outside them.
    local -a paths=("$units"/"$slot"-*.* "$security_units"/"$slot"-*.*)
    local path
    for path in "${paths[@]}"; do
        [[ $path == "$dropin_dir" ]] && continue
        for role in "${backend_roles[@]}"; do
            [[ $path != "$units/$slot-$role.container.d" ]] || continue 2
        done
        [[ -f $path && ! -L $path ]] || return 1
        sha256sum -- "$path" || return 1
    done
    sha256sum -- "/etc/systemd/user/$slot-gateway.socket" "$assets/edge/haproxy.cfg" \
        "$assets/edge/spoe.cfg" "$assets/assets/phase-b-runtime-probe.php" || return 1
    find "$assets/security/config" -type f -print0 | sort -z | xargs -0 sha256sum
}

exact_rollout_dropin() {
    local extra
    extra=$(find "$dropin_dir" -mindepth 1 -maxdepth 1 ! -name '90-rollout.conf' -print -quit) &&
        [[ -z $extra ]]
}

normalize_image() {
    local config=${1#sha256:}
    [[ $config =~ ^$hash$ ]] || return 1
    printf '%s\n' "$config"
}

inspect_role() {
    local role=$1 account=runtime directory=$units path raw ref indexed config running privileged read_only
    case "$role" in crowdsec|spoa) account=security; directory=$security_units;; esac
    "$account" systemctl --user is-active --quiet "$slot-$role.service" || return 1
    path=$("$account" systemctl --user show --value -p SourcePath "$slot-$role.service") || return 1
    [[ $path == "$directory/$slot-$role.container" ]] || return 1
    raw=$("$account" podman container inspect --format \
        '{{.ImageName}} {{.ImageDigest}} {{.Image}} {{.State.Running}} {{.HostConfig.Privileged}} {{.HostConfig.ReadonlyRootfs}}' \
        "$slot-$role") || return 1
    read -r ref indexed config running privileged read_only <<< "$raw"
    config=$(normalize_image "$config") || return 1
    printf '%s\n' "$ref $indexed $config $running $privileged $read_only"
}

unchanged_roles() {
    local role directory configured observed
    for role in "${roles[@]}"; do
        [[ $role == frontend ]] && continue
        if [[ ${1:-} == fixed ]] && backend_role "$role"; then
            continue
        fi
        directory=$units
        case "$role" in crowdsec|spoa) directory=$security_units;; esac
        configured=$(sed -n 's/^Image=//p' "$directory/$slot-$role.container") || return 1
        observed=$(inspect_role "$role") || return 1
        [[ $configured =~ ^[a-z0-9./_-]+@$digest$ &&
            $observed =~ ^"$configured"\ "${configured##*@}"\ $hash\ true\ false\ true$ ]] || return 1
        printf '%s %s\n' "$role" "$observed"
    done
}

backend_role() {
    case "$1" in api|php-fpm|worker-general|worker-hash-chain|scheduler) return 0;; esac
    return 1
}

render_dropin() { printf '[Container]\nImage=%s\n' "$1"; }

backend_matches() {
    local record=$1 role override component ref config expected actual
    for role in "${backend_roles[@]}"; do
        override=$units/$slot-$role.container.d/90-rollout.conf
        component=fpm
        [[ $role != api ]] || component=nginx
        if jq -e 'has("backend")' <<< "$record" >/dev/null; then
            ref=$(jq -er --arg role "$component" '.backend[$role].ref' <<< "$record") &&
                config=$(jq -er --arg role "$component" '.backend[$role].config' <<< "$record") || return 1
            [[ $ref =~ ^"$api_image@"$digest$ && $config =~ ^$hash$ &&
                -f $override && ! -L $override ]] && cmp -s "$override" <(render_dropin "$ref") || return 1
            expected="$ref ${ref##*@} $config true false true"
        else
            [[ ! -e $override && ! -L $override ]] || return 1
            expected=$(sed -n "s/^$role //p" "$store/roles") || return 1
        fi
        actual=$(inspect_role "$role") || return 1
        [[ $actual == "$expected" ]] || return 1
    done
}

matches() {
    local record=$1 ref config kind observed
    ref=$(jq -er .ref <<< "$record") && config=$(jq -er .config <<< "$record") &&
        kind=$(jq -er .kind <<< "$record") || return 1
    if [[ $kind == base ]]; then
        [[ ! -e $dropin && ! -L $dropin ]] || return 1
    else
        [[ -f $dropin && ! -L $dropin ]] && cmp -s "$dropin" <(render_dropin "$ref") || return 1
    fi
    observed=$(inspect_role frontend) || return 1
    [[ $observed == "$ref ${ref##*@} $config true false true" ]] && backend_matches "$record"
}

record() {
    jq -cn --arg revision "$1" --arg fingerprint "$2" --arg ref "$3" \
        --arg config "$4" --arg kind "$5" --arg index "$6" \
        '$ARGS.named'
}

save() {
    printf '%s\n' "$2" > "$store/.next" &&
        sync -f "$store/.next" &&
        mv -T -- "$store/.next" "$store/$1" &&
        sync -f "$store"
}

check_installed() {
    frozen_layout > "$scratch/layout" && cmp -s "$scratch/layout" "$store/layout" &&
        unchanged_roles fixed > "$scratch/roles" &&
        cmp -s "$scratch/roles" <(grep -vE '^(api|php-fpm|worker-general|worker-hash-chain|scheduler) ' "$store/roles")
}

validate_quadlet() {
    local ref=$1
    mkdir -p "$scratch/quadlets/$frontend.container.d" || return 1
    cp -- "$units/$frontend.container" "$units/$slot-edge.network" "$scratch/quadlets/" || return 1
    render_dropin "$ref" > "$scratch/quadlets/$frontend.container.d/90-rollout.conf" || return 1
    # The generator receives only non-secret Quadlet definitions.
    chmod 0755 "$scratch" "$scratch/quadlets" "$scratch/quadlets/$frontend.container.d" || return 1
    chmod 0644 "$scratch/quadlets/$frontend.container" "$scratch/quadlets/$slot-edge.network" \
        "$scratch/quadlets/$frontend.container.d/90-rollout.conf" || return 1
    runtime env QUADLET_UNIT_DIRS="$scratch/quadlets" \
        /usr/lib/systemd/system-generators/podman-system-generator --user --dryrun > "$scratch/generated" &&
        grep -Fq -- "$ref" "$scratch/generated"
}

restart_frontend() {
    local gateway
    runtime systemctl --user is-active --quiet "$slot-edge-network.service" &&
        gateway=$(runtime podman container inspect --format '{{.Id}} {{.State.StartedAt}}' "$slot-gateway") &&
        [[ -n $gateway ]] || return 1
    # Keep ordering dependencies while avoiding restart propagation through
    # the running gateway's Requires= relationship to the frontend.
    timeout 160 runuser -u secpal-runtime -- env -i PATH=/usr/bin:/usr/sbin HOME=/var/home/secpal-runtime \
        XDG_RUNTIME_DIR=/run/user/20000 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/20000/bus \
        systemctl --user --job-mode=ignore-requirements restart "$frontend.service" &&
        [[ $(runtime podman container inspect --format '{{.Id}} {{.State.StartedAt}}' "$slot-gateway") == "$gateway" ]]
}

switch_image() {
    local record=$1 ref kind
    ref=$(jq -er .ref <<< "$record") && kind=$(jq -er .kind <<< "$record") || return 1
    runtime podman image exists "$ref" || return 1
    if [[ $kind == base ]]; then
        rm -f -- "$dropin" || return 1
    else
        render_dropin "$ref" > "$dropin_dir/.next" &&
            chmod 0644 "$dropin_dir/.next" &&
            mv -T -- "$dropin_dir/.next" "$dropin" || return 1
    fi
    sync -f "$dropin_dir" &&
        runtime systemctl --user daemon-reload &&
        restart_frontend &&
        matches "$record" && check_installed
}

sql() {
    runtime podman exec "$slot-postgres" psql -X -At -v ON_ERROR_STOP=1 -U secpal_fixture_admin -d secpal -c "$1"
}

singleton_roles() {
    local observed expected
    observed=$(runtime podman ps --format '{{.Names}}' |
        grep -E '^secpal-int-.*-(scheduler|worker-general|worker-hash-chain)$' | sort) || return 1
    expected=$(printf '%s\n' "$slot-scheduler" "$slot-worker-general" "$slot-worker-hash-chain")
    [[ $observed == "$expected" ]]
}

worker_hostname() {
    local name
    name=$(runtime podman container inspect --format '{{.Config.Hostname}}' "$slot-worker-$1") || return 1
    [[ $name =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]{0,63}$ ]] || return 1
    printf '%s\n' "$name"
}

health() {
    local expected=$1 queue worker key reply i seed receipt
    local general hash_chain
    [[ $(getenforce) == Enforcing ]] &&
        [[ $(runtime podman info --format '{{.Host.Security.Rootless}}') == true ]] &&
        [[ $(security podman info --format '{{.Host.Security.Rootless}}') == true ]] &&
        [[ $(inspect_role frontend) == *' true false true' ]] &&
        runtime systemctl --user is-active --quiet "$slot-gateway.socket" &&
        ! runtime systemctl --user is-active --quiet "$slot-migrate.service" &&
        [[ $(sql 'SELECT system_identifier FROM pg_control_system()') == "$(cat "$store/cluster-id")" ]] &&
        [[ $(sql "SELECT count(*) FROM organizational_units WHERE id='$witness' AND name='FCOS lab rollout witness'") == 1 ]] &&
        [[ $(sql 'SHOW ssl; SHOW password_encryption;') == $'on\nscram-sha-256' ]] || return 1
    singleton_roles || return 1
    general=$(worker_hostname general) && hash_chain=$(worker_hostname hash-chain) &&
        [[ $general != "$hash_chain" ]] || return 1
    seed=$(jq -er .fingerprint <<< "$expected") || return 1
    for queue in default activity-hash-chain; do
        case "$queue" in
            default) worker=general; receipt=$general;;
            activity-hash-chain) worker="hash-chain"; receipt=$hash_chain;;
        esac
        key="integration-queue-$worker-${seed:0:24}"
        runtime podman exec "$slot-php-fpm" php /run/secpal/phase-b-runtime-probe.php \
            cache-forget "$key" || return 1
        runtime podman exec "$slot-php-fpm" php /run/secpal/phase-b-runtime-probe.php \
            queue-dispatch "$key" "$queue" || return 1
        for ((i=0; i<30; i++)); do
            reply=$(runtime podman exec "$slot-php-fpm" php /run/secpal/phase-b-runtime-probe.php cache-get "$key") || return 1
            [[ $reply == "$receipt" ]] && break
            sleep 1
        done
        [[ $reply == "$receipt" ]] || return 1
    done
}

persist_accepted() {
    local accepted=$1
    matches "$accepted" && check_installed && singleton_roles &&
        save accepted.json "$accepted"
}

decode_publisher_evidence() {
    local file=$1
    local -a rows
    mapfile -t rows < "$file"
    [[ ${#rows[@]} == 2 && ${rows[0]} =~ ^[A-Za-z0-9+/]+={0,2}$ && ${rows[1]} =~ ^[A-Za-z0-9+/]+={0,2}$ ]] || return 1
    [[ $(stat -c %s -- "$file") == $(("${#rows[0]}" + "${#rows[1]}" + 2)) ]] || return 1
    printf '%s' "${rows[0]}" | base64 --decode > "$scratch/index.json" &&
        printf '%s' "${rows[1]}" | base64 --decode > "$scratch/bundle.json"
}

verify_publisher() {
    local index=$1 publisher=$2
    decode_publisher_evidence "$scratch/proof" || return 1
    [[ $(sha256sum < "$scratch/index.json") == "${index#sha256:}  -" ]] || return 1
    verify_signature "$scratch/index.json" "$scratch/bundle.json" "$publisher" frontend
}

verify_signature() {
    local subject=$1 bundle=$2 publisher=$3 product=$4 version expected_hash
    expected_hash=$(awk -v platform="$platform" '$1 == platform { print $2 }' "$peer/gh-binary-sha256.txt") || return 1
    [[ $expected_hash =~ ^$hash$ && $(sha256sum < "$peer/gh") == "$expected_hash  -" ]] || return 1
    version=$("$peer/gh" --version) || return 1
    [[ $version == 'gh version 2.97.0 '* ]] || return 1
    env -i PATH=/usr/bin:/bin HOME="$scratch" GH_CONFIG_DIR="$scratch" GH_PROMPT_DISABLED=1 \
        GH_NO_UPDATE_NOTIFIER=1 GH_NO_EXTENSION_UPDATE_NOTIFIER=1 GH_TELEMETRY=false timeout 120 \
        "$peer/gh" attestation verify "$subject" --bundle "$bundle" \
        --repo "SecPal/$product" --signer-workflow "SecPal/$product/.github/workflows/publish-container.yml" \
        --source-ref refs/heads/main --source-digest "$publisher" --signer-digest "$publisher" \
        --deny-self-hosted-runners --hostname github.com > /dev/null 2>&1
}

verify_backend() {
    local publisher=$1 pair=$2 nginx=$3 fpm=$4 role index native descriptor
    local -a rows names=(pair pair.bundle.json document fpm fpm.bundle.json nginx nginx.bundle.json)
    mapfile -t rows < "$scratch/proof"
    ((${#rows[@]} == ${#names[@]})) || return 1
    local i size=0
    for i in "${!names[@]}"; do
        [[ ${rows[i]} =~ ^[A-Za-z0-9+/]+={0,2}$ ]] || return 1
        size=$((size + ${#rows[i]} + 1))
        printf '%s' "${rows[i]}" | base64 --decode > "$scratch/${names[i]}" || return 1
    done
    [[ $size == "$(stat -c %s -- "$scratch/proof")" &&
        $(sha256sum < "$scratch/pair") == "${pair#sha256:}  -" ]] || return 1
    verify_signature "$scratch/pair" "$scratch/pair.bundle.json" "$publisher" api || return 1
    descriptor=$(jq -er '
        select(.schemaVersion == 2 and .mediaType == "application/vnd.oci.image.manifest.v1+json"
            and .artifactType == "application/vnd.secpal-build-evidence.v1+json")
        | [.layers[] | select(.annotations["org.opencontainers.image.title"] == "runtime-pair.json")]
        | select(length == 1) | .[0] | select(.mediaType == "application/json") | .digest' "$scratch/pair") || return 1
    [[ $descriptor =~ ^$digest$ && $(sha256sum < "$scratch/document") == "${descriptor#sha256:}  -" ]] || return 1
    jq -e --arg source "$publisher" '
        .schema_version == "1.0.0" and .source == {repository:"https://github.com/SecPal/api",commit:$source}
        and (.images | keys) == ["nginx","php-fpm"]' "$scratch/document" >/dev/null || return 1
    for role in fpm nginx; do
        index=$nginx
        local component=nginx
        if [[ $role == fpm ]]; then index=$fpm; component=php-fpm; fi
        [[ $(sha256sum < "$scratch/$role") == "${index#sha256:}  -" ]] &&
            verify_signature "$scratch/$role" "$scratch/$role.bundle.json" "$publisher" api || return 1
        native=$(jq -er --slurpfile pair "$scratch/document" --arg component "$component" \
            --arg image "$api_image@$index" --arg platform "$platform" '
            select(.schemaVersion == 2 and .mediaType == "application/vnd.oci.image.index.v1+json")
            | [.manifests[] | select(.mediaType == "application/vnd.oci.image.manifest.v1+json")
               | {platform:(.platform.os + "/" + .platform.architecture),digest}] | sort_by(.platform)
            | select(map(.platform) == ["linux/amd64","linux/arm64"] and (map(.digest)|unique|length) == 2)
            | select(all(.[]; .digest | test("^sha256:[0-9a-f]{64}$")))
            | select($pair[0].images[$component].reference == $image)
            | select(. == ($pair[0].images[$component].platforms
               | map({platform,digest:.manifest_digest}) | sort_by(.platform)))
            | .[] | select(.platform == $platform) | .digest' "$scratch/$role") || return 1
        printf '%s\n' "$native" > "$scratch/$role.child" || return 1
    done
}

backend_database() {
    local version cluster ledger schema
    version=$(sql 'SHOW server_version_num') &&
        [[ $version =~ ^18[0-9]{4}$ ]] &&
        cluster=$(sql 'SELECT system_identifier FROM pg_control_system()') &&
        [[ $cluster == "$(cat "$store/cluster-id")" ]] &&
        ledger=$(sql "SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY id), '[]'::jsonb) FROM public.migrations AS m") &&
        [[ $ledger == \[* && $ledger != '[]' ]] &&
        schema=$(runtime podman exec "$slot-postgres" pg_dump --schema-only -U secpal_fixture_admin -d secpal |
            sed -E '/^\\(un)?restrict /d' | sha256sum) || return 1
    printf '%s\n' "$version" "$cluster" "$ledger" "$schema" | sha256sum | cut -d ' ' -f 1
}

same_backend_database() {
    if [[ ! $1 =~ ^$hash$ || $(backend_database) != "$1" ]]; then
        printf '%s\n' 'Backend compatibility rejected: PostgreSQL identity, schema or migration ledger differs' >&2
        return 1
    fi
}

run_staged() {
    local image=$1 executable=$2
    shift 2
    runtime podman --default-mounts-file=/dev/null run --rm --pull=never --network=none \
        --cap-drop=all --security-opt=no-new-privileges --read-only --http-proxy=false \
        --tmpfs /tmp:rw,noexec,nosuid,nodev,size=32m --user 10001:10001 --entrypoint "$executable" "$image" "$@"
}

fpm_payload() {
    # shellcheck disable=SC2016 # PHP receives a literal program.
    run_staged "$1" /usr/local/bin/php -r '
        $modules = get_loaded_extensions();
        sort($modules, SORT_STRING);
        if (!in_array("pdo_pgsql", $modules, true)) exit(1);
        $files = [];
        foreach (["/app", "/usr/local/etc/php", "/usr/local/etc/php-fpm.d"] as $root) {
            $tree = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
            foreach ($tree as $entry) {
                if ($entry->isLink()) {
                    $target = $entry->getRealPath();
                    if ($target === false || !str_starts_with($target, $root . "/")) exit(1);
                    $files[$entry->getPathname()] = ["link", readlink($entry->getPathname())];
                    continue;
                }
                $hash = $entry->isFile() ? hash_file("sha256", $entry->getPathname()) : false;
                if ($hash === false) exit(1);
                $files[$entry->getPathname()] = $hash;
            }
        }
        ksort($files, SORT_STRING);
        echo hash("sha256", json_encode([PHP_MAJOR_VERSION, PHP_MINOR_VERSION, $modules, $files], JSON_THROW_ON_ERROR)), "\n";
    '
}

backend_role_ref() {
    local record=$1 component=fpm
    [[ $2 != api ]] || component=nginx
    if jq -e 'has("backend")' <<< "$record" >/dev/null; then
        jq -er --arg component "$component" '.backend[$component].ref' <<< "$record"
    else
        sed -n "s/^Image=//p" "$units/$slot-$2.container"
    fi
}

validate_backend_quadlets() {
    local record=$1 role path ref
    mkdir "$scratch/quadlets" || return 1
    chmod 0755 "$scratch" "$scratch/quadlets" || return 1
    for path in "$units"/"$slot"-*.{container,network,volume}; do
        [[ -f $path ]] || continue
        install -m 0644 "$path" "$scratch/quadlets/" || return 1
    done
    for role in "${backend_roles[@]}"; do
        path=$scratch/quadlets/$slot-$role.container.d
        ref=$(backend_role_ref "$record" "$role") &&
            mkdir -m 0755 "$path" &&
            render_dropin "$ref" > "$path/90-rollout.conf" && chmod 0644 "$path/90-rollout.conf" || return 1
    done
    runtime env QUADLET_UNIT_DIRS="$scratch/quadlets" \
        /usr/lib/systemd/system-generators/podman-system-generator --user --dryrun > "$scratch/generated" || return 1
    for role in api php-fpm; do
        ref=$(backend_role_ref "$record" "$role") &&
            grep -Fq -- "$ref" "$scratch/generated" || return 1
    done
}

prepare_backend() {
    local installed=$1 pins=$2 old_pins=$3 publisher pair nginx fpm expires snapshot component ref config old before after
    local -a values previous_values
    mapfile -t values <<< "$pins"
    mapfile -t previous_values <<< "$old_pins"
    [[ ${#values[@]} == 5 && ${#previous_values[@]} == 5 ]] || return 1
    publisher=${values[0]} pair=${values[1]} nginx=${values[2]} fpm=${values[3]} expires=${values[4]}
    [[ $child == "$pair" && $nginx != "$fpm" && $pair != "$nginx" && $pair != "$fpm" &&
        $pair != "${previous_values[1]}" && ( $nginx != "${previous_values[2]}" || $fpm != "${previous_values[3]}" ) &&
        $(frontend_field "$revision" FRONTEND_DIGEST "$digest") == "$(frontend_field "$previous" FRONTEND_DIGEST "$digest")" &&
        $(frontend_field "$revision" FRONTEND_SOURCE_COMMIT "$sha") == "$(frontend_field "$previous" FRONTEND_SOURCE_COMMIT "$sha")" ]] || return 1
    backend_expiry "$expires" && verify_backend "$publisher" "$pair" "$nginx" "$fpm" || return 1
    local images='{}' native raw user digest_seen architecture
    for component in fpm nginx; do
        native=$(cat "$scratch/$component.child") || return 1
        ref="$api_image@$native"
        runtime env DOCKER_CONFIG="$scratch" podman pull --quiet --authfile "$scratch/auth.json" --platform "$platform" "$ref" >/dev/null || return 1
        raw=$(runtime podman image inspect --format '{{.Id}} {{.Digest}} {{.Architecture}} {{.Config.User}}' "$ref") || return 1
        read -r config digest_seen architecture user <<< "$raw"
        [[ $digest_seen == "$native" && $architecture == "${platform#linux/}" &&
            $user =~ ^(10001(:10001)?|secpal)$ ]] || return 1
        config=$(normalize_image "$config") &&
            images=$(jq -c --arg key "$component" --arg ref "$ref" --arg config "$config" \
                '.[$key]={ref:$ref,config:$config}' <<< "$images") || return 1
    done
    old=$(backend_role_ref "$installed" php-fpm) &&
        ref=$(jq -er .fpm.ref <<< "$images") &&
        before=$(fpm_payload "$old") && after=$(fpm_payload "$ref") || return 1
    if [[ ! $before =~ ^$hash$ || $before != "$after" ]]; then
        printf '%s\n' 'Backend compatibility rejected: application payload or PHP contract differs' >&2
        return 1
    fi
    run_staged "$ref" /usr/local/sbin/php-fpm -t >/dev/null 2>&1 || return 1
    ref=$(jq -er .nginx.ref <<< "$images") &&
        run_staged "$ref" /usr/sbin/nginx -t >/dev/null 2>&1 || return 1
    singleton_roles && snapshot=$(backend_database) || return 1
    local candidate
    candidate=$(jq -c --arg revision "$revision" --arg fingerprint "$wanted" --arg pair "$pair" \
        --arg expires "$expires" --argjson images "$images" \
        '.revision=$revision | .fingerprint=$fingerprint | .backend=($images+{pair:$pair,expires:$expires})' <<< "$installed") &&
        validate_backend_quadlets "$candidate" || return 1
    save prepared.json "$(jq -cn --argjson before "$installed" --argjson next "$candidate" --arg database "$snapshot" \
        '{before:$before,next:$next,database:$database}')"
}

backend_expiry() {
    local expires now
    expires=$(date -u -d "$1" +%s) && now=$(date -u +%s) && ((now < expires))
}

untouched_instances() {
    local role account identity
    for role in frontend postgres gateway crowdsec spoa; do
        account=runtime
        case "$role" in crowdsec|spoa) account=security;; esac
        identity=$("$account" podman container inspect --format '{{.Id}} {{.State.StartedAt}}' "$slot-$role") || return 1
        [[ -n $identity ]] || return 1
        printf '%s %s\n' "$role" "$identity"
    done
}

switch_backend() {
    local record=$1 role ref override service untouched
    local -a services=()
    for role in "${backend_roles[@]}"; do
        services+=("$slot-$role.service")
        ref=$(backend_role_ref "$record" "$role") &&
            [[ $ref =~ ^"$api_image@"$digest$ ]] &&
            runtime podman image exists "$ref" || return 1
    done
    untouched=$(untouched_instances) &&
        runtime systemctl --user --job-mode=ignore-requirements stop "$slot-api.service" &&
        runtime systemctl --user --job-mode=ignore-requirements stop "${services[@]:1}" || return 1
    for service in "${services[@]}"; do
        [[ $(runtime systemctl --user show --value -p ActiveState "$service") == inactive ]] || return 1
    done
    for role in "${backend_roles[@]}"; do
        override=$units/$slot-$role.container.d
        if jq -e 'has("backend")' <<< "$record" >/dev/null; then
            if [[ ! -e $override ]]; then mkdir -m 0755 "$override" || return 1; fi
            trusted_directory "$override" '0 0 755' || return 1
            ref=$(backend_role_ref "$record" "$role") &&
                render_dropin "$ref" > "$override/.next" &&
                chmod 0644 "$override/.next" &&
                mv -T -- "$override/.next" "$override/90-rollout.conf" || return 1
        else
            rm -f -- "$override/90-rollout.conf" "$override/.next" || return 1
        fi
        if [[ -d $override ]]; then sync -f "$override" || return 1; fi
    done
    runtime systemctl --user daemon-reload &&
        runtime systemctl --user start "$slot-php-fpm.service" &&
        runtime systemctl --user start "$slot-api.service" &&
        runtime systemctl --user start "${services[@]:2}" &&
        matches "$record" && singleton_roles && check_installed &&
        [[ $(untouched_instances) == "$untouched" ]]
}

prepare() {
    local installed=$1 pin_ref publisher native ref config candidate new_backend old_backend
    [[ $(jq -r .fingerprint <<< "$installed") == "$prior" && $(jq -r .revision <<< "$installed") == "$previous" ]] &&
        matches "$installed" && refresh && admitted "$revision" "$wanted" && admitted "$previous" "$prior" &&
        git_object merge-base --is-ancestor "$previous" "$revision" &&
        lab_pins_only "$revision" && lab_pins_only "$previous" || return 1
    new_backend=$(backend_pins "$revision") && old_backend=$(backend_pins "$previous") || return 1
    printf '{"auths":{}}\n' > "$scratch/auth.json" || return 1
    chmod 0711 "$scratch" && chmod 0644 "$scratch/auth.json" || return 1
    if [[ $new_backend != "$old_backend" ]]; then
        prepare_backend "$installed" "$new_backend" "$old_backend"
        return
    fi
    pin_ref=$(frontend_field "$revision" FRONTEND_DIGEST "$digest") || return 1
    publisher=$(frontend_field "$revision" FRONTEND_SOURCE_COMMIT "$sha") || return 1
    [[ $pin_ref != "$(frontend_field "$previous" FRONTEND_DIGEST "$digest")" ]] || return 1
    verify_publisher "$pin_ref" "$publisher" || return 1
    native=$(jq -er --arg arch "${platform#linux/}" \
        '.manifests | map(select(.platform.os == "linux" and .platform.architecture == $arch))
         | select(length == 1) | .[0].digest' "$scratch/index.json") || return 1
    [[ $native =~ ^$digest$ && $native == "$child" ]] || return 1
    ref="$image@$child"
    runtime env DOCKER_CONFIG="$scratch" podman pull --quiet --authfile "$scratch/auth.json" --platform "$platform" "$ref" >/dev/null || return 1
    config=$(runtime podman image inspect --format '{{.Id}} {{.Digest}} {{.Architecture}} {{.Config.User}}' "$ref") || return 1
    [[ $config =~ ^([^[:space:]]+)\ "$child"\ "${platform#linux/}"\ 101:101$ ]] || return 1
    config=$(normalize_image "${BASH_REMATCH[1]}") || return 1
    validate_quadlet "$ref" || return 1
    candidate=$(record "$revision" "$wanted" "$ref" "$config" update "$pin_ref") || return 1
    candidate=$(jq -c --argjson previous "$installed" '
        if $previous|has("backend") then .backend=$previous.backend else . end' <<< "$candidate") || return 1
    save prepared.json "$(jq -cn --argjson before "$installed" --argjson next "$candidate" '{before:$before,next:$next}')"
}

main() {
    if [[ $# == 1 && $1 == --ssh-entry ]]; then
        [[ $EUID != 0 && -z ${SSH_ORIGINAL_COMMAND:-} ]] || deny
        exec /usr/bin/sudo -n -- "$peer/guest"
    fi
    [[ $EUID == 0 ]] || deny
    cd /
    [[ $# == 0 || ( $# == 1 && $1 == --enroll ) ]] || deny
    trusted_directory "$store" '0 0 700' || deny
    trusted_directory "$dropin_dir" '0 0 755' || deny
    [[ -f $policy && ! -L $policy && $(stat -c '%u %g %a' -- "$policy") == '0 0 600' ]] || deny
    jq -e 'keys == ["foundation","host","machine_id","witness"]' "$policy" >/dev/null || deny
    host=$(jq -er .host "$policy") foundation=$(jq -er .foundation "$policy") witness=$(jq -er .witness "$policy")
    [[ $foundation =~ ^$sha$ && $witness =~ ^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$ &&
        $(cat /etc/machine-id) == "$(jq -er '.machine_id | select(test("^[a-f0-9]{32}$"))' "$policy")" ]] || deny
    case "$host:$(uname -m)" in
        cx23:x86_64|cx33:x86_64) platform=linux/amd64;;
        cax21:aarch64) platform=linux/arm64;;
        *) deny;;
    esac
    mapfile -t inputs < <(grep -vE '^(#|$)' "$peer/release-paths.txt")
    frozen_sources=()
    for path in "${inputs[@]}"; do
        [[ $path == "$contract" ]] || frozen_sources+=("$path")
    done
    exec 9>"$store/lock"
    flock -n 9 || deny
    local installed prepared before next database
    scratch=$(mktemp -d /var/tmp/secpal-fcos-rollout.XXXXXXXX)
    trap 'rm -rf -- "$scratch"' EXIT

    if [[ $# == 1 ]]; then
        [[ ! -e $store/accepted.json && ! -e $dropin ]] || deny
        [[ -d $store/release.git ]] || git init -q --bare "$store/release.git"
        refresh
        git_object merge-base --is-ancestor "$foundation" "$branch"
        local base_ref startup identity
        base_ref="$image@$(frontend_field "$foundation" FRONTEND_DIGEST "$digest")"
        startup=$(inspect_role frontend)
        [[ $startup =~ ^"$base_ref"\ "${base_ref##*@}"\ ($hash)\ true\ false\ true$ ]] || deny
        identity=${BASH_REMATCH[1]}
        installed=$(record "$foundation" "$(fingerprint "$foundation")" "$base_ref" "$identity" base "${base_ref##*@}")
        frozen_layout > "$store/layout"
        unchanged_roles > "$store/roles"
        sql 'SELECT system_identifier FROM pg_control_system()' > "$store/cluster-id"
        matches "$installed" || deny
        health "$installed" || deny
        persist_accepted "$installed" || deny
        return
    fi

    timeout 8 head -c 2097153 > "$scratch/wire" || deny
    [[ $(stat -c %s -- "$scratch/wire") -le 2097152 ]] || deny
    head -n 1 "$scratch/wire" > "$scratch/request"
    parse_request "$scratch/request" || deny
    tail -n +2 "$scratch/wire" > "$scratch/proof"
    [[ $operation == prepare || ! -s $scratch/proof ]] || deny
    check_installed || deny
    installed=$(cat "$store/accepted.json")
    if [[ $operation == prepare ]]; then
        prepare "$installed" || deny
        return
    fi
    prepared='{}'
    [[ ! -f $store/prepared.json ]] || prepared=$(cat "$store/prepared.json")
    if [[ $operation == observe ]]; then
        for candidate in "$(jq -c '.next // empty' <<< "$prepared")" "$installed" "$(jq -c '.before // empty' <<< "$prepared")"; do
            [[ -n $candidate ]] || continue
            local identity_pair
            identity_pair=$(jq -er '[.revision,.fingerprint]|join(" ")' <<< "$candidate") || deny
            if [[ $identity_pair == "$revision $wanted" || $identity_pair == "$previous $prior" ]] && matches "$candidate"; then
                jq -er .fingerprint <<< "$candidate"
                return
            fi
        done
        deny
    fi
    before=$(jq -ec '.before' <<< "$prepared") || deny
    next=$(jq -ec '.next' <<< "$prepared") || deny
    [[ $(jq -r '[.revision,.fingerprint]|join(" ")' <<< "$before") == "$previous $prior" &&
        $(jq -r '[.revision,.fingerprint]|join(" ")' <<< "$next") == "$revision $wanted" ]] || deny
    database=$(jq -er '.database // ""' <<< "$prepared") || deny
    if [[ -n $database ]]; then
        same_backend_database "$database" || deny
        case "$operation" in
            activate)
                backend_expiry "$(jq -er .backend.expires <<< "$next")" || deny
                if ! matches "$next"; then
                    matches "$before" || deny
                    singleton_roles || deny
                    if ! switch_backend "$next"; then
                        same_backend_database "$database" || deny
                        switch_backend "$before" || deny
                        deny
                    fi
                fi
                same_backend_database "$database" || deny
                ;;
            accept)
                matches "$next" || deny
                backend_expiry "$(jq -er .backend.expires <<< "$next")" || deny
                health "$next" || exit 10
                same_backend_database "$database" || deny
                persist_accepted "$next" || deny
                ;;
            rollback)
                [[ $installed == "$before" ]] || deny
                if ! matches "$before"; then
                    matches "$next" || deny
                    switch_backend "$before" || deny
                fi
                health "$before" || deny
                same_backend_database "$database" || deny
                persist_accepted "$before" || deny
                ;;
        esac
        return
    fi
    case "$operation" in
        activate)
            if ! matches "$next"; then
                matches "$before" || deny
                if ! switch_image "$next"; then
                    switch_image "$before" || deny
                    deny
                fi
            fi
            ;;
        accept)
            matches "$next" || deny
            health "$next" || exit 10
            persist_accepted "$next" || deny
            ;;
        rollback)
            [[ $installed == "$before" ]] || deny
            if ! matches "$before"; then
                matches "$next" || deny
                switch_image "$before" || deny
            fi
            health "$before" || deny
            persist_accepted "$before" || deny
            ;;
    esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
fi
