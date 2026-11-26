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
source_offer=$assets/assets/source-offer.json
fpm_pool=$assets/assets/zz-fpm-session.conf
# Frontend #1788 records the exact OpenAPI source used for these deployments.
contracts_source=f8771b74d887b84b84dcc94e2405df7b47222466
dropin_dir=$units/$frontend.container.d
dropin=$dropin_dir/90-rollout.conf
image=ghcr.io/secpal/frontend
origin=https://github.com/SecPal/deployment.git
branch=refs/remotes/release/main
contract=scripts/integration_runtime_contract.py
compatibility_path=config/quadlet/fcos-lab-rollout/backend-compatibility.json
digest='sha256:[a-f0-9]{64}'
sha='[a-f0-9]{40}'
hash='[a-f0-9]{64}'
roles=(api php-fpm frontend worker-general worker-hash-chain scheduler postgres gateway crowdsec spoa)
backend_roles=(api php-fpm worker-general worker-hash-chain scheduler)
api_image=ghcr.io/secpal/api
request_transport=registry
archive_max=150000000

deny() { printf '%s\n' 'FCOS lab guest rejected the operation' >&2; exit 1; }

backend_step() {
    local stage=$1
    shift
    if "$@" 2>/dev/null; then
        return 0
    fi
    printf 'FCOS lab backend operation failed: fcos-lab-backend.%s\n' "$stage" >&2
    return 1
}

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
                /^LAB_API_VEX_EXPIRES_AT = "[0-9T:Z-]+"$/d;
                /^LAB_API_COMPATIBILITY_SHA256 = "[a-f0-9]{64}"$/d;
                /^LAB_(API|FRONTEND)_TRANSPORT = "oci-archive-v1"$/d'
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

render_frontend_dropin() {
    render_dropin "$1"
    printf 'Mount=type=bind,source=%s,target=/usr/share/nginx/html/source-offer.json,ro=true\n' "$source_offer"
}

render_source_offer() {
    [[ $1 =~ ^$sha$ ]] || return 1
    jq -cn --arg frontend "https://codeload.github.com/SecPal/frontend/tar.gz/$1" \
        --arg contracts "https://codeload.github.com/SecPal/contracts/tar.gz/$contracts_source" \
        '{version:1,repositories:{frontend:{sourceUrl:$frontend},contracts:{sourceUrl:$contracts}}}'
}

render_api_release() {
    local pool=$1 source=$2
    [[ $source =~ ^$sha$ && $(grep -c '^\[' "$pool") == 1 && $(grep -cx '\[secpal\]' "$pool") == 1 ]] || return 1
    sed -E '/^env\[BOOTSTRAP_API_RELEASE_(VERSION|SOURCE_URL)\][[:blank:]]*=/d' "$pool" || return 1
    printf 'env[BOOTSTRAP_API_RELEASE_VERSION]=git.%s\nenv[BOOTSTRAP_API_RELEASE_SOURCE_URL]=https://codeload.github.com/SecPal/api/tar.gz/%s\n' \
        "$source" "$source"
}

release_asset() {
    [[ -f $1 && ! -L $1 && $(stat -c '%u:%g:%a' "$1") == "0:0:644" ]]
}

write_release_asset() {
    local path=$1 temp
    shift
    [[ ! -e $path && ! -L $path ]] || release_asset "$path" || return 1
    trusted_directory "${path%/*}" '0 0 755' && release_asset "$fpm_pool" || return 1
    temp=$(mktemp --tmpdir="${path%/*}" .release-metadata.XXXXXXXX) || return 1
    if ! "$@" > "$temp" || ! chmod 0644 "$temp" || ! chcon --reference="$fpm_pool" "$temp" ||
            ! sync -f "$temp" || ! mv -T -- "$temp" "$path"; then
        rm -f -- "$temp"
        return 1
    fi
    sync -f "${path%/*}"
}

backend_release_matches() {
    local source
    release_asset "$fpm_pool" &&
        source=$(backend_step native-image backend_image_source "$1") &&
        cmp -s "$fpm_pool" <(render_api_release "$fpm_pool" "$source")
}

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
            if [[ $role == php-fpm ]]; then
                backend_release_matches "$ref" || return 1
            fi
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
    local record=$1 ref config kind observed selected source
    ref=$(jq -er .ref <<< "$record") && config=$(jq -er .config <<< "$record") &&
        kind=$(jq -er .kind <<< "$record") || return 1
    if [[ $kind == base ]]; then
        [[ ! -e $dropin && ! -L $dropin ]] || return 1
    else
        release_asset "$dropin" || return 1
        if ! cmp -s "$dropin" <(render_dropin "$ref"); then
            cmp -s "$dropin" <(render_frontend_dropin "$ref") && release_asset "$source_offer" || return 1
            selected=$(jq -er .revision <<< "$record") &&
                source=$(frontend_field "$selected" FRONTEND_SOURCE_COMMIT "$sha") &&
                cmp -s "$source_offer" <(render_source_offer "$source") || return 1
        fi
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
    render_frontend_dropin "$ref" > "$scratch/quadlets/$frontend.container.d/90-rollout.conf" || return 1
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
    local record=$1 ref kind selected source
    ref=$(jq -er .ref <<< "$record") && kind=$(jq -er .kind <<< "$record") || return 1
    runtime podman image exists "$ref" || return 1
    if [[ $kind == base ]]; then
        rm -f -- "$dropin" || return 1
    else
        selected=$(jq -er .revision <<< "$record") &&
            source=$(frontend_field "$selected" FRONTEND_SOURCE_COMMIT "$sha") &&
            write_release_asset "$source_offer" render_source_offer "$source" &&
            render_frontend_dropin "$ref" > "$dropin_dir/.next" &&
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

verify_archived_frontend() {
    local index=$1 publisher=$2 prepared_digest observed_index
    decode_backend_evidence receipt bundle.json prepared.json index.json &&
        verify_signature "$scratch/receipt" "$scratch/bundle.json" "$publisher" frontend || return 1
    prepared_digest=$(jq -er '.candidate_sha256' "$scratch/receipt") &&
        [[ $prepared_digest =~ ^$digest$ && $(sha256sum < "$scratch/prepared.json") == "${prepared_digest#sha256:}  -" ]] &&
        observed_index=$(jq -er '.index_digest' "$scratch/prepared.json") &&
        [[ $observed_index == "$index" && $(sha256sum < "$scratch/index.json") == "${index#sha256:}  -" ]]
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

decode_backend_evidence() {
    local -a rows names=("$@")
    mapfile -t rows < "$scratch/proof"
    ((${#rows[@]} == ${#names[@]})) || return 1
    local i size=0
    for i in "${!names[@]}"; do
        [[ ${rows[i]} =~ ^[A-Za-z0-9+/]+={0,2}$ ]] || return 1
        size=$((size + ${#rows[i]} + 1))
        printf '%s' "${rows[i]}" | base64 --decode > "$scratch/${names[i]}" || return 1
    done
    [[ $size == "$(stat -c %s -- "$scratch/proof")" ]]
}

verify_backend() {
    local publisher=$1 pair=$2 nginx=$3 fpm=$4 role index native descriptor
    decode_backend_evidence pair pair.bundle.json document fpm fpm.bundle.json nginx nginx.bundle.json &&
        [[ $(sha256sum < "$scratch/pair") == "${pair#sha256:}  -" ]] || return 1
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

verify_archived_backend() {
    local publisher=$1 pair=$2 nginx=$3 fpm=$4 expires=$5 role component index native
    local start deadline now
    decode_backend_evidence receipt bundle.jsonl source-security.json &&
        [[ $(sha256sum < "$scratch/receipt") == "${pair#sha256:}  -" ]] &&
        verify_signature "$scratch/receipt" "$scratch/bundle.jsonl" "$publisher" api &&
        verify_signature "$scratch/source-security.json" "$scratch/bundle.jsonl" "$publisher" api || return 1
    jq -e --arg source "$publisher" '
        .schema_version == "1.0.0" and .published == false and .qualification == "SUCCEEDED"
        and .source.repository == "https://github.com/SecPal/api"
        and .source.commit == $source and (.images | keys) == ["nginx","php-fpm"]
    ' "$scratch/receipt" >/dev/null || return 1
    jq -e --arg source "$publisher" '
        .schema_version == "secpal-trivy-repository-scan-v5"
        and .subject == {repository:"SecPal/api",commit:$source}
        and .gate_state == "CLEAN" and .database.status == "FRESH"
        and .operation == {name:"TRIVY_REPOSITORY_SCAN",status:"SUCCEEDED"}
    ' "$scratch/source-security.json" >/dev/null || return 1
    start=$(date -u -d "$(jq -er .database.updated_at "$scratch/source-security.json")" +%s) &&
        deadline=$(date -u -d "$(jq -er .database.next_update "$scratch/source-security.json")" +%s) &&
        now=$(date -u +%s) && expires=$(date -u -d "$expires" +%s) &&
        ((start <= now && now < expires && expires <= deadline)) || return 1

    for role in nginx fpm; do
        component=nginx index=$nginx
        if [[ $role == fpm ]]; then component=php-fpm index=$fpm; fi
        native=$(jq -er --arg component "$component" --arg index "$index" --arg platform "$platform" '
            .images[$component] | select(.candidate_index_digest == $index) | .platforms
            | map(.subject) | sort_by(.platform)
            | select(map(.platform) == ["linux/amd64","linux/arm64"]
                 and all(.[]; .manifest_digest | test("^sha256:[0-9a-f]{64}$"))
                 and ([.[].manifest_digest] | unique | length) == 2)
            | .[] | select(.platform == $platform) | .manifest_digest
        ' "$scratch/receipt") || return 1
        printf '%s\n' "$native" > "$scratch/$role.child" || return 1
    done
}

receive_archived_image() {
    local role=$1 size=$2
    timeout 340 head -c "$size" > "$scratch/$role.tar" &&
        [[ $(stat -c %s -- "$scratch/$role.tar") == "$size" ]]
}

finish_archive_request() {
    timeout 10 head -c 1 > "$scratch/remainder" && [[ ! -s $scratch/remainder ]]
}

receive_archived_backend() {
    receive_archived_image nginx "$archive_nginx_size" &&
        receive_archived_image fpm "$archive_fpm_size" && finish_archive_request
}

pull_archived_child() {
    local role=$1 repository=$2 loaded
    chown root:20000 "$scratch/$role.tar" && chmod 0440 "$scratch/$role.tar" &&
        loaded=$(runtime podman pull --quiet "oci-archive:$scratch/$role.tar") &&
        runtime podman tag "$loaded" "$repository:candidate-${revision:0:12}-$role"
}

pull_backend_child() {
    local role=$1 ref=$2
    if [[ $request_transport == oci-archive-v1 ]]; then
        pull_archived_child "$role" "$api_image"
    else
        runtime env DOCKER_CONFIG="$scratch" podman pull --quiet \
            --authfile "$scratch/auth.json" --platform "$platform" "$ref" >/dev/null
    fi
}

migrations_idle() {
    [[ $(runtime systemctl --user show --value -p ActiveState "$slot-migrate.service") == inactive ]]
}

backend_ledger() {
    local ledger
    ledger=$(sql "SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY id), '[]'::jsonb) FROM public.migrations AS m") &&
        [[ $ledger == \[* && $ledger != '[]' ]] || return 1
    printf '%s\n' "$ledger"
}

backend_ledger_hash() { backend_ledger | sha256sum | cut -d ' ' -f 1; }

backend_schema() {
    runtime podman exec "$slot-postgres" pg_dump --schema-only -U secpal_fixture_admin -d secpal "$@" |
        sed -E '/^\\(un)?restrict /d' | sha256sum | cut -d ' ' -f 1
}

backend_postgres_identity() {
    local version cluster container
    version=$(sql 'SHOW server_version_num') &&
        [[ $version =~ ^18[0-9]{4}$ ]] &&
        cluster=$(sql 'SELECT system_identifier FROM pg_control_system()') &&
        [[ $cluster == "$(cat "$store/cluster-id")" ]] &&
        container=$(runtime podman container inspect --format '{{.Id}} {{.State.StartedAt}}' "$slot-postgres") &&
        [[ $container == *' '* ]] || return 1
    printf '%s\n' "$version" "$cluster" "$container" | sha256sum | cut -d ' ' -f 1
}

same_migrated_database() {
    local proof=$1 schema ledger identity
    migrations_idle &&
        [[ $(sql "SELECT NOT rolcanlogin FROM pg_roles WHERE rolname='secpal_poc_migrate'") == t ]] &&
        identity=$(backend_postgres_identity) &&
        [[ $identity == "$(jq -er .postgres <<< "$proof")" ]] &&
        schema=$(backend_schema --no-owner --no-privileges) &&
        ledger=$(backend_ledger_hash) &&
        [[ $schema == "$(jq -er .migration.schema <<< "$proof")" &&
           $ledger == "$(jq -er .migration.ledger <<< "$proof")" ]]
}

backend_database() {
    local version cluster ledger schema
    migrations_idle &&
        version=$(sql 'SHOW server_version_num') &&
        [[ $version =~ ^18[0-9]{4}$ ]] &&
        cluster=$(sql 'SELECT system_identifier FROM pg_control_system()') &&
        [[ $cluster == "$(cat "$store/cluster-id")" ]] &&
        ledger=$(backend_ledger) &&
        schema=$(backend_schema) || return 1
    printf '%s\n' "$version" "$cluster" "$ledger" "$schema" | sha256sum | cut -d ' ' -f 1
}

same_backend_database() {
    if [[ ! $1 =~ ^$hash$ || $(backend_step database-snapshot backend_database) != "$1" ]]; then
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

fpm_migrations() {
    # shellcheck disable=SC2016 # PHP receives a literal program.
    run_staged "$1" /usr/local/bin/php -r '
        if (!extension_loaded("pdo_pgsql")) exit(1);
        require "/app/vendor/autoload.php";
        $app = require "/app/bootstrap/app.php";
        $app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
        $migrator = $app->make("migrator");
        $paths = array_unique([$app->databasePath("migrations"), ...$migrator->paths()]);
        $files = [];
        foreach ($paths as $path) {
            foreach ($migrator->getMigrationFiles([$path]) as $name => $file) {
                $resolved = realpath($file);
                if (isset($files[$name]) || $resolved === false || !str_starts_with($resolved, "/app/") || is_link($file)) exit(1);
                $files[$name] = hash_file("sha256", $resolved);
                if ($files[$name] === false) exit(1);
            }
        }
        if ($files === []) exit(1);
        ksort($files, SORT_STRING);
        $schemas = [];
        $schemaPath = $app->databasePath("schema");
        if (is_link($schemaPath) || (file_exists($schemaPath) && !is_dir($schemaPath))) exit(1);
        $schemaFiles = is_dir($schemaPath) ? glob($schemaPath . "/*", GLOB_ERR) : [];
        if ($schemaFiles === false) exit(1);
        foreach ($schemaFiles as $file) {
            if (!is_file($file) || is_link($file)) exit(1);
            $schemas[basename($file)] = hash_file("sha256", $file);
            if ($schemas[basename($file)] === false) exit(1);
        }
        $definition = json_encode([$files, $schemas], JSON_THROW_ON_ERROR);
        echo ($argv[1] === "manifest" ? $definition : hash("sha256", $definition)), "\n";
    ' "${2:-hash}"
}

additive_migrations() {
    jq -e --argjson before "$1" --argjson after "$2" -n '
        ($before | type == "array" and length == 2 and (.[0] | type == "object")) and
        ($after | type == "array" and length == 2 and (.[0] | type == "object")) and
        $before[1] == $after[1] and ($after[0] | length) > ($before[0] | length) and
        all($before[0] | to_entries[]; $after[0][.key] == .value)
    ' >/dev/null
}

validate_backend_compatibility() {
    jq --exit-status --compact-output --raw-output --slurp --arg previous "$2" --arg candidate "$3" --arg schema "$4" --arg ledger "$5" '
        def evidence:
            type == "object" and keys == ["linux/amd64","linux/arm64"]
            and all(.[]; type == "string" and test("^sha256:[a-f0-9]{64}$"));
        def database_hash: type == "string" and test("^[a-f0-9]{64}$");
        select(length == 1) | .[0]
        | select(type == "object")
        | select(.previous_pair == $previous and .candidate_pair == $candidate
            and (.schema | database_hash) and (.ledger | database_hash) and (.forward | evidence)
            and ([.forward[]] | unique | length) == 2)
        | select(.rollback == null or ((.rollback | evidence)
            and ([.forward[], .rollback[]] | length == (unique | length))))
        | if .schema_version == 1 and .schema == $schema and .ledger == $ledger and keys ==
            ["candidate_pair","forward","ledger","previous_pair","rollback","schema","schema_version"]
          then (.rollback != null | tostring)
          elif .schema_version == 2 and keys ==
            ["candidate_pair","forward","ledger","migration","previous_pair","rollback","schema","schema_version"]
            and .rollback != null and (.migration | type == "object" and keys == ["ledger","schema"]
            and all(.[]; database_hash)) and .migration.ledger != .ledger
            and ((.schema == $schema and .ledger == $ledger) or
                 (.migration.schema == $schema and .migration.ledger == $ledger))
          then {rollback:true,migration:.migration}
          else empty end
    ' "$1"
}

backend_compatibility() {
    local pin size schema ledger evidence="$scratch/compatibility.json"
    pin=$(backend_field "$revision" API_COMPATIBILITY_SHA256 "$hash") &&
        size=$(git_object cat-file -s "$revision:$compatibility_path") &&
        [[ $size =~ ^[1-9][0-9]{0,4}$ && $size -le 16384 ]] &&
        git_object show "$revision:$compatibility_path" > "$evidence" &&
        [[ $(sha256sum < "$evidence") == "$pin  -" ]] &&
        schema=$(backend_schema --no-owner --no-privileges) &&
        ledger=$(backend_ledger_hash) &&
        [[ $schema =~ ^$hash$ && $ledger =~ ^$hash$ ]] &&
        validate_backend_compatibility "$evidence" "$1" "$2" "$schema" "$ledger"
}

backend_rollback_admitted() {
    local expires
    jq -e '.rollback == true' <<< "$1" >/dev/null &&
        expires=$(backend_field "$2" API_VEX_EXPIRES_AT '[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]{8}Z') &&
        backend_expiry "$expires"
}

qualified_backend_database() {
    local proof=$1 snapshot=$2
    if jq -e 'has("migration")' <<< "$proof" >/dev/null; then
        same_migrated_database "$proof"
    else
        same_backend_database "$snapshot"
    fi
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
    local installed=$1 pins=$2 old_pins=$3 publisher pair nginx fpm expires snapshot component ref config old before after helper rollback
    local migration=null postgres=null
    local -a values previous_values
    mapfile -t values <<< "$pins"
    mapfile -t previous_values <<< "$old_pins"
    [[ ${#values[@]} == 5 && ${#previous_values[@]} == 5 ]] || return 1
    publisher=${values[0]} pair=${values[1]} nginx=${values[2]} fpm=${values[3]} expires=${values[4]}
    [[ $child == "$pair" && $nginx != "$fpm" && $pair != "$nginx" && $pair != "$fpm" &&
        $pair != "${previous_values[1]}" && ( $nginx != "${previous_values[2]}" || $fpm != "${previous_values[3]}" ) &&
        $(frontend_field "$revision" FRONTEND_DIGEST "$digest") == "$(frontend_field "$previous" FRONTEND_DIGEST "$digest")" &&
        $(frontend_field "$revision" FRONTEND_SOURCE_COMMIT "$sha") == "$(frontend_field "$previous" FRONTEND_SOURCE_COMMIT "$sha")" ]] || return 1
    helper=$(backend_step helper-identity backend_helper_hash) &&
        backend_expiry "$expires" &&
        singleton_roles && snapshot=$(backend_step database-snapshot backend_database) &&
        rollback=$(backend_step compatibility-evidence backend_compatibility "${previous_values[1]}" "$pair") || return 1
    if [[ $rollback == '{'* ]]; then
        migration=$(jq -ec '.migration' <<< "$rollback") &&
            postgres=$(backend_step database-snapshot backend_postgres_identity) || return 1
        rollback=true
    fi
    if [[ $request_transport == oci-archive-v1 ]]; then
        [[ $(backend_field "$revision" API_TRANSPORT 'oci-archive-v1') == "$request_transport" ]] &&
            backend_step pair-proof verify_archived_backend "$publisher" "$pair" "$nginx" "$fpm" "$expires" &&
            backend_step native-image receive_archived_backend || return 1
    else
        if backend_field "$revision" API_TRANSPORT 'oci-archive-v1' >/dev/null; then return 1; fi
        backend_step pair-proof verify_backend "$publisher" "$pair" "$nginx" "$fpm" || return 1
    fi
    local images='{}' native raw user digest_seen architecture
    for component in fpm nginx; do
        native=$(cat "$scratch/$component.child") || return 1
        ref="$api_image@$native"
        backend_step native-image pull_backend_child "$component" "$ref" || return 1
        raw=$(backend_step native-image runtime podman image inspect \
            --format '{{.Id}} {{.Digest}} {{.Architecture}} {{.Config.User}}' "$ref") || return 1
        read -r config digest_seen architecture user <<< "$raw"
        [[ $digest_seen == "$native" && $architecture == "${platform#linux/}" &&
            $user =~ ^(10001(:10001)?|secpal)$ ]] || return 1
        config=$(normalize_image "$config") &&
            images=$(jq -c --arg key "$component" --arg ref "$ref" --arg config "$config" \
                '.[$key]={ref:$ref,config:$config}' <<< "$images") || return 1
    done
    old=$(backend_role_ref "$installed" php-fpm) && ref=$(jq -er .fpm.ref <<< "$images") || return 1
    if [[ $migration != null ]]; then
        before=$(backend_step fpm-migrations fpm_migrations "$old" manifest) &&
            after=$(backend_step fpm-migrations fpm_migrations "$ref" manifest) &&
            backend_step fpm-migrations additive_migrations "$before" "$after" || return 1
    elif ! before=$(backend_step fpm-migrations fpm_migrations "$old") ||
         ! after=$(backend_step fpm-migrations fpm_migrations "$ref") ||
         [[ ! $before =~ ^$hash$ || $before != "$after" ]]; then
        printf '%s\n' 'Backend compatibility rejected: migration files or schema dumps differ' >&2
        return 1
    fi
    backend_step fpm-config run_staged "$ref" /usr/local/sbin/php-fpm -t >/dev/null || return 1
    ref=$(jq -er .nginx.ref <<< "$images") &&
        backend_step nginx-config run_staged "$ref" /usr/sbin/nginx -t >/dev/null || return 1
    local candidate
    candidate=$(jq -c --arg revision "$revision" --arg fingerprint "$wanted" --arg pair "$pair" \
        --arg expires "$expires" --argjson images "$images" \
        '.revision=$revision | .fingerprint=$fingerprint | .backend=($images+{pair:$pair,expires:$expires})' <<< "$installed") &&
        backend_step quadlet-validation validate_backend_quadlets "$candidate" &&
        same_backend_database "$snapshot" || return 1
    save prepared.json "$(jq -cn --argjson before "$installed" --argjson next "$candidate" \
        --arg database "$snapshot" --arg helper "$helper" --argjson rollback "$rollback" \
        --argjson migration "$migration" --arg postgres "$postgres" \
        '{before:$before,next:$next,database:$database,helper:$helper,rollback:$rollback}
         + (if $migration == null then {} else {migration:$migration,postgres:$postgres} end)')"
}

backend_helper_hash() {
    local expected actual
    [[ -f $peer/guest && ! -L $peer/guest && $(stat -c '%u %g %a' -- "$peer/guest") == '0 0 755' ]] || return 1
    expected=$(git_object show "$revision:scripts/fcos-lab-rollout-guest.sh" | sha256sum) &&
        actual=$(sha256sum < "$peer/guest") || return 1
    [[ $expected == "$actual" && $actual == *'  -' && ${actual%% *} =~ ^$hash$ ]] || return 1
    printf '%s\n' "${actual%% *}"
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

install_backend_refs() {
    local record=$1 role ref override
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
            if [[ -d $override ]]; then
                rmdir -- "$override" && sync -f "$units" || return 1
            fi
        fi
        if [[ -d $override ]]; then sync -f "$override" || return 1; fi
    done
}

backend_running() {
    matches "$1" && singleton_roles && check_installed && [[ $(untouched_instances) == "$2" ]]
}

backend_image_source() {
    local source
    source=$(runtime podman image inspect --format '{{index .Labels "org.opencontainers.image.revision"}}' "$1") &&
        [[ $source =~ ^$sha$ ]] || return 1
    printf '%s\n' "$source"
}

run_backend_migration() (
    local ref=$1 helper="$assets/assets/fcos-poc-db-roles.sh" status=0
    local override="$units/$slot-migrate.container.d"
    [[ $ref =~ ^"$api_image@"$digest$ && -f $helper && ! -L $helper ]] &&
        [[ $(stat -c '%u:%g:%a' "$helper") =~ ^0:0:(644|755)$ ]] &&
        [[ $(sha256sum < "$helper") == "$(git_object show "$revision:scripts/fcos-poc-db-roles.sh" | sha256sum)" ]] &&
        [[ $(sql "SELECT NOT rolcanlogin FROM pg_roles WHERE rolname='secpal_poc_migrate'") == t ]] &&
        migrations_idle && mkdir -m 0755 "$override" || return 1
    trap 'status=$?; rm -f -- "$override/90-rollout.conf" && rmdir -- "$override" &&
        runtime systemctl --user daemon-reload || status=1; exit "$status"' EXIT
    render_dropin "$ref" > "$override/90-rollout.conf" &&
        chmod 0644 "$override/90-rollout.conf" &&
        restorecon -R "$override" &&
        runtime systemctl --user daemon-reload &&
        runtime systemctl --user show --property=ExecStart --value "$slot-migrate.service" |
            grep -F -- "$ref" >/dev/null || return 1
    runtime bash "$helper" migrate-existing haproxy01
)

switch_backend() {
    local record=$1 migration_proof=${2:-} role ref service untouched expires fpm_ref source
    local -a services=()
    if jq -e 'has("backend")' <<< "$record" >/dev/null; then
        expires=$(jq -er .backend.expires <<< "$record") && backend_expiry "$expires" || return 1
    fi
    for role in "${backend_roles[@]}"; do
        services+=("$slot-$role.service")
        ref=$(backend_role_ref "$record" "$role") &&
            [[ $ref =~ ^"$api_image@"$digest$ ]] &&
            backend_step native-image runtime podman image exists "$ref" || return 1
    done
    fpm_ref=$(backend_step native-image backend_role_ref "$record" php-fpm) &&
        source=$(backend_step native-image backend_image_source "$fpm_ref") || return 1
    backend_step database-snapshot migrations_idle || return 1
    untouched=$(backend_step running-identities untouched_instances) &&
        backend_step stop-http runtime systemctl --user --job-mode=ignore-requirements stop "$slot-api.service" &&
        backend_step stop-backend runtime systemctl --user --job-mode=ignore-requirements stop "${services[@]:1}" || return 1
    for service in "${services[@]}"; do
        [[ $(runtime systemctl --user show --value -p ActiveState "$service") == inactive ]] || return 1
    done
    if [[ -n $migration_proof ]]; then
        same_backend_database "$(jq -er .database <<< "$migration_proof")" &&
            backend_step migration run_backend_migration "$fpm_ref" &&
            backend_step migration same_migrated_database "$migration_proof" || return 1
    fi
    backend_step install-images install_backend_refs "$record" &&
        backend_step install-images write_release_asset "$fpm_pool" render_api_release "$fpm_pool" "$source" &&
        backend_step reload-units runtime systemctl --user daemon-reload &&
        backend_step start-fpm runtime systemctl --user --job-mode=ignore-dependencies start "$slot-php-fpm.service" &&
        backend_step start-http runtime systemctl --user --job-mode=ignore-dependencies start "$slot-api.service" &&
        backend_step start-background runtime systemctl --user --job-mode=ignore-dependencies start "${services[@]:2}" &&
        backend_step database-snapshot migrations_idle &&
        backend_step running-identities backend_running "$record" "$untouched"
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
    local selected_transport=registry
    if frontend_field "$revision" FRONTEND_TRANSPORT 'oci-archive-v1' >/dev/null; then
        selected_transport='oci-archive-v1 frontend'
    fi
    [[ $request_transport == "$selected_transport" ]] || return 1
    if [[ $request_transport == registry ]]; then
        verify_publisher "$pin_ref" "$publisher" || return 1
    else
        verify_archived_frontend "$pin_ref" "$publisher" || return 1
    fi
    native=$(jq -er --arg arch "${platform#linux/}" \
        '.manifests | map(select(.platform.os == "linux" and .platform.architecture == $arch))
         | select(length == 1) | .[0].digest' "$scratch/index.json") || return 1
    [[ $native =~ ^$digest$ && $native == "$child" ]] || return 1
    ref="$image@$child"
    if [[ $request_transport == registry ]]; then
        runtime env DOCKER_CONFIG="$scratch" podman pull --quiet \
            --authfile "$scratch/auth.json" --platform "$platform" "$ref" >/dev/null || return 1
    else
        receive_archived_image frontend "$archive_nginx_size" &&
            finish_archive_request && pull_archived_child frontend "$image" || return 1
    fi
    config=$(runtime podman image inspect --format '{{.Id}} {{.Digest}} {{.Architecture}} {{.Config.User}}' "$ref") || return 1
    [[ $config =~ ^([^[:space:]]+)\ "$child"\ "${platform#linux/}"\ 101:101$ ]] || return 1
    config=$(normalize_image "${BASH_REMATCH[1]}") || return 1
    validate_quadlet "$ref" || return 1
    candidate=$(record "$revision" "$wanted" "$ref" "$config" update "$pin_ref") || return 1
    candidate=$(jq -c --argjson previous "$installed" '
        if $previous|has("backend") then .backend=$previous.backend else . end' <<< "$candidate") || return 1
    save prepared.json "$(jq -cn --argjson before "$installed" --argjson next "$candidate" '{before:$before,next:$next}')"
}

read_request() {
    local first line
    IFS= read -r -n 1025 -t 8 first && ((${#first} <= 1024)) || return 1
    if [[ $first == oci-archive-v1 || $first == "oci-archive-v1 frontend" ]]; then
        request_transport=$first
        IFS= read -r -n 1025 -t 8 first && ((${#first} <= 1024)) || return 1
    fi
    printf '%s\n' "$first" > "$scratch/request" && parse_request "$scratch/request" || return 1
    if [[ $request_transport != registry ]]; then
        [[ $operation == prepare ]] || return 1
        local i consumed=0 row_count=3
        if [[ $request_transport == "oci-archive-v1 frontend" ]]; then row_count=4; fi
        for ((i=0; i<row_count; i++)); do
            IFS= read -r -n 2097153 -t 8 line || return 1
            consumed=$((consumed + ${#line} + 1))
            ((consumed <= 2097152)) || return 1
            printf '%s\n' "$line" >> "$scratch/proof" || return 1
        done
        IFS=' ' read -r -n 64 -t 8 archive_nginx_size archive_fpm_size || return 1
        [[ $archive_nginx_size =~ ^[1-9][0-9]{0,8}$ ]] &&
            ((archive_nginx_size <= archive_max)) || return 1
        if [[ $request_transport == oci-archive-v1 ]]; then
            [[ $archive_fpm_size =~ ^[1-9][0-9]{0,8}$ ]] && ((archive_fpm_size <= archive_max))
        else
            [[ -z $archive_fpm_size ]]
        fi
    else
        timeout 8 head -c 2097153 > "$scratch/proof" &&
            ((${#first} + 1 + $(stat -c %s -- "$scratch/proof") <= 2097152)) &&
            [[ $operation == prepare || ! -s $scratch/proof ]]
    fi
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
    local installed prepared before next database migration_proof
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

    read_request || deny
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
        [[ $(backend_step helper-identity backend_helper_hash) == "$(jq -er .helper <<< "$prepared")" ]] || deny
        migration_proof=
        if [[ $(jq -r 'has("migration")' <<< "$prepared") == true ]]; then
            if same_migrated_database "$prepared"; then
                :
            else
                same_backend_database "$database" || deny
                migration_proof=$prepared
            fi
        else
            same_backend_database "$database" || deny
        fi
        case "$operation" in
            activate)
                backend_expiry "$(jq -er .backend.expires <<< "$next")" || deny
                if ! matches "$next"; then
                    matches "$before" || deny
                    singleton_roles || deny
                    if ! switch_backend "$next" "$migration_proof"; then
                        qualified_backend_database "$prepared" "$database" ||
                            same_backend_database "$database" || deny
                        backend_step rollback-compatibility backend_rollback_admitted "$prepared" "$previous" || deny
                        [[ $(sql "SELECT NOT rolcanlogin FROM pg_roles WHERE rolname='secpal_poc_migrate'") == t ]] || deny
                        switch_backend "$before" || deny
                        deny
                    fi
                fi
                qualified_backend_database "$prepared" "$database" || deny
                ;;
            accept)
                matches "$next" || deny
                backend_expiry "$(jq -er .backend.expires <<< "$next")" || deny
                backend_step guest-health health "$next" || exit 10
                qualified_backend_database "$prepared" "$database" || deny
                persist_accepted "$next" || deny
                ;;
            rollback)
                [[ $installed == "$before" ]] || deny
                if ! matches "$before"; then
                    backend_step rollback-compatibility backend_rollback_admitted "$prepared" "$previous" || deny
                    matches "$next" || deny
                    switch_backend "$before" || deny
                fi
                backend_step guest-health health "$before" || deny
                qualified_backend_database "$prepared" "$database" ||
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
