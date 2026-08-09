#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

if [[ "$#" -ne 9 ]]; then
  printf 'ERROR: expected provider region profile address SHA run ID attempt key and evidence directory.\n' >&2
  exit 1
fi

provider="$1"
region="$2"
profile="$3"
address="$4"
target_sha="$5"
run_id="$6"
run_attempt="$7"
private_key="$8"
evidence_dir="$9"

[[ "$provider" == digitalocean ]]
[[ "$region" == fra1 ]]
[[ "$profile" == intel || "$profile" == amd ]]
[[ "$target_sha" =~ ^[0-9a-f]{40}$ ]]
[[ "$run_id" =~ ^[1-9][0-9]{0,19}$ ]]
[[ "$run_attempt" =~ ^[1-9][0-9]{0,2}$ ]]
[[ -f "$private_key" && ! -L "$private_key" ]]
[[ "$(stat -c '%a' "$private_key")" == 600 ]]
python3 - "$address" <<'PY'
import ipaddress
import sys

address = ipaddress.ip_address(sys.argv[1])
if address.version != 4 or not address.is_global:
    raise SystemExit("remote address is not a public IPv4 address")
PY

install -d -m 0700 "$evidence_dir"
known_hosts="$(dirname "$evidence_dir")/known_hosts"
first_scan="$(mktemp "$evidence_dir/.host-key-first.XXXXXX")"
second_scan="$(mktemp "$evidence_dir/.host-key-second.XXXXXX")"
trap 'rm -f -- "$first_scan" "$second_scan"' EXIT

host_key_ready=false
for _ in {1..30}; do
  if ssh-keyscan -T 5 -t ed25519 "$address" > "$first_scan" 2>/dev/null &&
    sleep 2 &&
    ssh-keyscan -T 5 -t ed25519 "$address" > "$second_scan" 2>/dev/null &&
    [[ "$(grep -cve '^$' "$first_scan")" -eq 1 ]] &&
    cmp -s "$first_scan" "$second_scan"; then
    host_key_ready=true
    break
  fi
  sleep 5
done
if [[ "$host_key_ready" != true ]]; then
  printf 'ERROR: unable to obtain one stable Ed25519 host key.\n' >&2
  exit 1
fi
install -m 0600 "$first_scan" "$known_hosts"
ssh-keygen -H -f "$known_hosts" >/dev/null
rm -f -- "$known_hosts.old"
ssh-keygen -lf "$known_hosts"

ssh_options=(
  -i "$private_key"
  -o BatchMode=yes
  -o IdentitiesOnly=yes
  -o PasswordAuthentication=no
  -o KbdInteractiveAuthentication=no
  -o StrictHostKeyChecking=yes
  -o "UserKnownHostsFile=$known_hosts"
  -o ConnectTimeout=15
  -o ServerAliveInterval=15
  -o ServerAliveCountMax=3
)

# Expansion intentionally occurs on the disposable remote host.
# shellcheck disable=SC2016
timeout --signal=TERM --kill-after=15s 12m \
  ssh "${ssh_options[@]}" "secpal-ci@$address" \
  'cloud-init status --wait >/dev/null && test "$(id -u)" -ne 0'

started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
set +e
timeout --signal=TERM --kill-after=30s 42m \
  ssh "${ssh_options[@]}" "secpal-ci@$address" /bin/bash -s -- "$target_sha" <<'REMOTE'
set -euo pipefail
target_sha="$1"
[[ "$target_sha" =~ ^[0-9a-f]{40}$ ]]
checkout=/home/secpal-ci/deployment-target
if [[ -e "$checkout" || -L "$checkout" ]]; then
  printf 'ERROR: target checkout path is not new.\n' >&2
  exit 1
fi
install -d -m 0700 "$checkout"
git -C "$checkout" init --quiet
git -C "$checkout" remote add origin https://github.com/SecPal/deployment.git
GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0 \
  git -C "$checkout" -c credential.helper= fetch --quiet --depth=1 origin "$target_sha"
git -C "$checkout" -c advice.detachedHead=false checkout --quiet --detach FETCH_HEAD
actual_sha="$(git -C "$checkout" rev-parse --verify 'HEAD^{commit}')"
[[ "$actual_sha" == "$target_sha" ]]
if [[ ! -x "$checkout/scripts/ci-cloud/target-conformance.sh" ]]; then
  printf 'ERROR: selected target has no executable cloud conformance entrypoint.\n' >&2
  exit 1
fi
set +e
(
  cd "$checkout"
  ulimit -f 32768
  env -i \
    HOME=/home/secpal-ci \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    SECPAL_TARGET_SHA="$target_sha" \
    timeout --signal=TERM --kill-after=30s 40m \
    bash scripts/ci-cloud/target-conformance.sh
) >/tmp/secpal-target-conformance.log 2>&1
status=$?
set -e
exit "$status"
REMOTE
target_status=$?
set -e
ended_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

evidence_json="$evidence_dir/evidence.json"
ssh "${ssh_options[@]}" "secpal-ci@$address" \
  python3 - "$provider" "$region" "$profile" "$target_sha" \
  "$run_id" "$run_attempt" "$started_at" "$ended_at" "$target_status" \
  < scripts/ci-cloud/collect-host-evidence.py > "$evidence_json"

python3 scripts/ci-cloud/validate-evidence.py \
  "$evidence_json" "$evidence_dir/summary.md" --require-passed
