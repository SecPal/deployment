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

without_frontend_pin() {
    git_object show "$1:$contract" |
        sed -E '/^LAB_FRONTEND_DIGEST = "sha256:[a-f0-9]{64}"$/d; /^LAB_FRONTEND_SOURCE_COMMIT = "[a-f0-9]{40}"$/d'
}

frontend_only() {
    git_object diff --quiet --no-ext-diff "$foundation" "$1" -- "${frozen_sources[@]}" &&
        [[ $(without_frontend_pin "$foundation") == "$(without_frontend_pin "$1")" ]] &&
        frontend_field "$1" FRONTEND_DIGEST "$digest" >/dev/null &&
        frontend_field "$1" FRONTEND_SOURCE_COMMIT "$sha" >/dev/null
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
    # These fixture inputs contain configuration and code. The private
    # runtime, data, certificate and credential directories are outside them.
    local -a paths=("$units"/"$slot"-*.* "$security_units"/"$slot"-*.*)
    local path
    for path in "${paths[@]}"; do
        [[ $path == "$dropin_dir" ]] && continue
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
        directory=$units
        case "$role" in crowdsec|spoa) directory=$security_units;; esac
        configured=$(sed -n 's/^Image=//p' "$directory/$slot-$role.container") || return 1
        observed=$(inspect_role "$role") || return 1
        [[ $configured =~ ^[a-z0-9./_-]+@$digest$ &&
            $observed =~ ^"$configured"\ "${configured##*@}"\ $hash\ true\ false\ true$ ]] || return 1
        printf '%s %s\n' "$role" "$observed"
    done
}

render_dropin() { printf '[Container]\nImage=%s\n' "$1"; }

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
    [[ $observed == "$ref ${ref##*@} $config true false true" ]]
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
        unchanged_roles > "$scratch/roles" && cmp -s "$scratch/roles" "$store/roles"
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
        timeout 160 runuser -u secpal-runtime -- env -i PATH=/usr/bin:/usr/sbin HOME=/var/home/secpal-runtime \
            XDG_RUNTIME_DIR=/run/user/20000 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/20000/bus \
            systemctl --user restart "$frontend.service" &&
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
    local index=$1 publisher=$2 version expected_hash
    decode_publisher_evidence "$scratch/proof" || return 1
    [[ $(sha256sum < "$scratch/index.json") == "${index#sha256:}  -" ]] || return 1
    expected_hash=$(awk -v platform="$platform" '$1 == platform { print $2 }' "$peer/gh-binary-sha256.txt") || return 1
    [[ $expected_hash =~ ^$hash$ && $(sha256sum < "$peer/gh") == "$expected_hash  -" ]] || return 1
    version=$("$peer/gh" --version) || return 1
    [[ $version == 'gh version 2.97.0 '* ]] || return 1
    env -i PATH=/usr/bin:/bin HOME="$scratch" GH_CONFIG_DIR="$scratch" GH_PROMPT_DISABLED=1 \
        GH_NO_UPDATE_NOTIFIER=1 GH_NO_EXTENSION_UPDATE_NOTIFIER=1 GH_TELEMETRY=false timeout 120 \
        "$peer/gh" attestation verify "$scratch/index.json" --bundle "$scratch/bundle.json" \
        --repo SecPal/frontend --signer-workflow SecPal/frontend/.github/workflows/publish-container.yml \
        --source-ref refs/heads/main --source-digest "$publisher" --signer-digest "$publisher" \
        --deny-self-hosted-runners --hostname github.com > /dev/null 2>&1
}

prepare() {
    local installed=$1 pin_ref publisher native ref config candidate
    [[ $(jq -r .fingerprint <<< "$installed") == "$prior" && $(jq -r .revision <<< "$installed") == "$previous" ]] &&
        matches "$installed" && refresh && admitted "$revision" "$wanted" && admitted "$previous" "$prior" &&
        git_object merge-base --is-ancestor "$previous" "$revision" &&
        frontend_only "$revision" && frontend_only "$previous" || return 1
    pin_ref=$(frontend_field "$revision" FRONTEND_DIGEST "$digest") || return 1
    publisher=$(frontend_field "$revision" FRONTEND_SOURCE_COMMIT "$sha") || return 1
    [[ $pin_ref != "$(frontend_field "$previous" FRONTEND_DIGEST "$digest")" ]] || return 1
    verify_publisher "$pin_ref" "$publisher" || return 1
    printf '{"auths":{}}\n' > "$scratch/auth.json"
    chmod 0711 "$scratch"
    chmod 0644 "$scratch/auth.json"
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
    local installed prepared before next
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
