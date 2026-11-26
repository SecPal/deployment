#!/usr/bin/bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT
# The installed guest supplies the functions and state variables used here.
# shellcheck disable=SC1091,SC2034,SC2154

# Attended enrollment for the already-active address-contract cutover.
set -Eeuo pipefail
umask 077
[[ $EUID == 0 && $# == 4 ]] || exit 64
target=$1 stage=$2 revision=$3 payload_sha=$4
case "$target" in
    cx23) cluster=7710251108046708761 ;;
    cx33) cluster=7710259205002502169 ;;
    cax21) cluster=7710253390870708249 ;;
    *) exit 64 ;;
esac
[[ $stage =~ ^/var/tmp/secpal-address-3114\.[[:alnum:]]{8}$ ]]
[[ $(stat -c '%u %g %a' -- "$stage") == '0 0 711' && ! -L $stage ]]
[[ $(stat -c '%u %g %a' -- "$stage/new") == '0 0 700' && ! -L $stage/new ]]
[[ $revision =~ ^[0-9a-f]{40}$ && $payload_sha =~ ^[0-9a-f]{64}$ ]]
test -f "$stage/activated"
guest=/usr/local/libexec/secpal-fcos-lab-rollout/guest
[[ $(stat -c '%u %g %a' "$guest") == '0 0 755' && ! -L $guest ]]
# shellcheck source=scripts/fcos-lab-rollout-guest.sh
source "$guest"
trap 'printf "Lab enrollment stopped at %s:%s\n" "$target" "$LINENO" >&2' ERR
trusted_directory "$store" '0 0 700'
[[ $(stat -c '%u %g %a' "$policy") == '0 0 600' && ! -L $policy ]]
jq -e 'keys == ["foundation","host","machine_id","witness"]' "$policy" >/dev/null
host=$(jq -er .host "$policy")
foundation=$(jq -er .foundation "$policy")
witness=$(jq -er .witness "$policy")
[[ $host == "$target" && $foundation =~ ^$sha$ ]]
[[ $witness =~ ^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$ ]]
[[ $(cat /etc/machine-id) == "$(jq -er .machine_id "$policy")" ]]
exec 9>"$store/lock"
flock -n 9
case "$host:$(uname -m)" in
    cx23:x86_64|cx33:x86_64) platform=linux/amd64 ;;
    cax21:aarch64) platform=linux/arm64 ;;
    *) exit 1 ;;
esac
mapfile -t inputs < <(grep -vE '^(#|$)' "$peer/release-paths.txt")
scratch=$(mktemp -d "$stage/enrollment-proof.XXXXXXXX")
trap 'rm -rf -- "$scratch"' EXIT
head -c 4194305 > "$scratch/input.tar"
test "$(stat -c %s "$scratch/input.tar")" -le 4194304
test "$(sha256sum < "$scratch/input.tar")" = "$payload_sha  -"
printf '%s\n' api-proof.txt frontend-proof.txt | cmp -s - <(tar -tf "$scratch/input.tar")
refresh
test "$(git_object rev-parse "$branch")" = "$revision"
# Refuse to execute bytes other than the reviewed one-time enrollment.
cmp -s "${BASH_SOURCE[0]}" <(git_object show "$revision:scripts/fcos-lab-adopt-address-baseline.sh")
git_object show "$revision:docs/synthetic-address-contract-cutover.md" > "$scratch/contract"
grep -Fxq '## Post-cutover enrollment' "$scratch/contract"
grep -Fq '62126b55ff35c255997e59c4a4356f360b8990a36a3b085a597141bfdd3aa889' "$scratch/contract"
grep -Fq '650271e203e03a473618dbe7f7bcb1e9e9a26e4627ce4a27cef2c7f932e87e93' "$scratch/contract"
wanted=$(fingerprint "$revision")
admitted "$revision" "$wanted"
backend_helper_hash >/dev/null
test "$(sha256sum < "$assets/assets/fcos-poc-db-roles.sh")" = \
    "$(git_object show "$revision:scripts/fcos-poc-db-roles.sh" | sha256sum)"
api_pins=$(backend_pins "$revision")
mapfile -t pins <<<"$api_pins"
[[ ${#pins[@]} == 5 && ${pins[0]} == abb3bed3db54aa20335e054342ffa5f55b09b1be &&
   ${pins[1]} == sha256:fec1bf683cc4cb545d0b7e1af7038b0b5f317499388b22f828c9b5735c3e4c1e ]]
front_source=$(frontend_field "$revision" FRONTEND_SOURCE_COMMIT "$sha")
front_index=$(frontend_field "$revision" FRONTEND_DIGEST "$digest")
[[ "$front_source" == 0a5bcc9f218703c5a602556f7cbfad82a254f722 &&
   "$front_index" == sha256:3c859855647284cbeee9ddf26dee547265d992e86f8e6630b8fd8a727205cb15 ]]
tar -xOf "$scratch/input.tar" frontend-proof.txt > "$scratch/proof"
verify_archived_frontend "$front_index" "$front_source"
front_child=$(jq -er --arg arch "${platform#linux/}" '
    [.manifests[] | select(.platform.os == "linux" and .platform.architecture == $arch)] |
    select(length == 1) | .[0].digest' "$scratch/index.json")
[[ $front_child =~ ^$digest$ ]]
tar -xOf "$scratch/input.tar" api-proof.txt > "$scratch/proof"
verify_archived_backend "${pins[@]}"
config_for(){
    local ref=$1 expected_user=$2 commit=$3 raw
    raw=$(runtime podman image inspect --format \
        '{{.Id}} {{.Digest}} {{.Architecture}} {{.Config.User}} {{index .Labels "org.opencontainers.image.revision"}}' "$ref")
    [[ $raw =~ ^([^[:space:]]+)\ "${ref##*@}"\ "${platform#linux/}"\ ($expected_user)\ "$commit"$ ]]
    normalize_image "${BASH_REMATCH[1]}"
}
front_ref="$image@$front_child"
front_config=$(config_for "$front_ref" '101:101' "$front_source")
backend_images='{}'
for role in nginx fpm; do
    child=$(cat "$scratch/$role.child")
    [[ $child =~ ^$digest$ ]]
    ref="$api_image@$child"
    config=$(config_for "$ref" '10001(:10001)?|secpal' "${pins[0]}")
    backend_images=$(jq -c --arg role "$role" --arg ref "$ref" --arg config "$config" \
        '.[$role]={ref:$ref,config:$config}' <<< "$backend_images")
done
candidate=$(record "$revision" "$wanted" "$front_ref" "$front_config" update "$front_index" |
    jq -c --argjson images "$backend_images" --arg pair "${pins[1]}" --arg expiry "${pins[4]}" \
        '.backend = ($images+{pair:$pair,expires:$expiry})')
previous=$(cat "$store/accepted.json")
if [[ $previous == "$candidate" && "$foundation" == "$revision" ]]; then
    check_installed
    matches "$candidate"
    printf '%s %s\n' "$target" "$wanted"
    exit
fi
jq -e '.revision=="1d99496ca4e2fb9da1141b8297ca7557e114fc5d"
      and .fingerprint=="68add65629e51fb10b541cd6c4a07679464e777fdf99ac7d9698c59c57eb29bb"' <<< "$previous" >/dev/null
jq -e --argjson accepted "$previous" '.next == $accepted' "$store/prepared.json" >/dev/null
migrations_idle
test "$(sql "SELECT NOT rolcanlogin FROM pg_roles WHERE rolname='secpal_poc_migrate'")" = t
test "$(sql 'SELECT system_identifier FROM pg_control_system()')" = "$cluster"
test "$(cat "$store/cluster-id")" = "$cluster"
test "$(backend_schema --no-owner --no-privileges)" = 62126b55ff35c255997e59c4a4356f360b8990a36a3b085a597141bfdd3aa889
test "$(backend_ledger_hash)" = 650271e203e03a473618dbe7f7bcb1e9e9a26e4627ce4a27cef2c7f932e87e93
compare_offer(){
    cmp -s <(jq -S -c . "$source_offer") <(render_source_offer "$front_source" | jq -S -c .)
}
compare_offer
migrate="$units/$slot-migrate.container.d/90-rollout.conf"
release_asset "$migrate"
cmp -s "$migrate" "$stage/new/migrate.conf"
[[ $(find "${migrate%/*}" -mindepth 1 -maxdepth 1 -printf '%f') == '90-rollout.conf' ]]
backup=$(mktemp -d "$store/pre-address-enrollment.XXXXXXXX")
cp -a "$store/accepted.json" "$store/prepared.json" "$policy" "$migrate" "$source_offer" "$backup/"
identities=$(untouched_instances)
restore(){
    local rc=$?
    if ((rc != 0)); then
        cp -a "$backup/accepted.json" "$backup/prepared.json" "$store/" || :
        cp -a "$backup/guest.json" "$policy" || :
        mkdir -p "${migrate%/*}" && cp -a "$backup/90-rollout.conf" "$migrate" || :
        cp -a "$backup/source-offer.json" "$source_offer" || :
        runtime systemctl --user daemon-reload || :
    fi
    rm -rf -- "$scratch"
    exit "$rc"
}
trap restore EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
unlink "$migrate"
rmdir "${migrate%/*}"
runtime systemctl --user daemon-reload
write_release_asset "$source_offer" render_source_offer "$front_source"
check_installed
matches "$candidate"
health "$candidate"
[[ $(untouched_instances) == "$identities" ]]
persist_accepted "$candidate"
new_policy=$(mktemp "${policy%/*}/.guest-baseline.XXXXXXXX")
jq --arg foundation "$revision" '.foundation=$foundation' "$policy" > "$new_policy"
chmod 0600 "$new_policy"
chcon --reference="$policy" "$new_policy"
mv -fT "$new_policy" "$policy"
unlink "$store/prepared.json"
sync -f "$store"
test "$(cat "$store/accepted.json")" = "$candidate"
rm -rf -- "$scratch"
trap - EXIT
printf '%s %s\n' "$target" "$wanted"
