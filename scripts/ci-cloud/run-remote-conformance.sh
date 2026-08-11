#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

if [[ "$#" -ne 12 ]]; then
  printf 'ERROR: expected provider location profile address SHA run ID attempt key evidence directory image slug image ID and machine type.\n' >&2
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
provider_image_slug="${10}"
provider_image_id="${11}"
machine_type="${12}"

[[ "$target_sha" =~ ^[0-9a-f]{40}$ ]]
[[ "$run_id" =~ ^[1-9][0-9]{0,19}$ ]]
[[ "$run_attempt" =~ ^[1-9][0-9]{0,2}$ ]]
case "$provider/$region/$profile/$provider_image_slug/$machine_type" in
  digitalocean/fra1/intel/debian-13-x64/s-4vcpu-8gb-intel | \
    digitalocean/fra1/amd/debian-13-x64/s-4vcpu-8gb-amd)
    [[ "$provider_image_id" =~ ^[1-9][0-9]{0,19}$ ]]
    ;;
  gcp/europe-west3-a/axion/debian-cloud/debian-13-arm64/c4a-standard-4)
    [[ "$provider_image_id" =~ ^https://www.googleapis.com/compute/v1/projects/debian-cloud/global/images/debian-13-trixie-arm64-v[0-9]{8}$ ]]
    ;;
  *)
    printf 'ERROR: remote provider selection is outside the closed allowlist.\n' >&2
    exit 1
    ;;
esac
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
orchestration_started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
known_hosts="$(dirname "$evidence_dir")/known_hosts"
evidence_json="$evidence_dir/evidence.json"
evidence_summary="$evidence_dir/summary.md"
bootstrap_stage="host-key"
host_setup_failure_json="null"
host_key_observations_json="null"
first_scan=""
second_scan=""
host_key_connection_refused=0
host_key_connection_timeout=0
host_key_no_key=0
host_key_multiple_keys=0
host_key_changed_key=0
host_key_other=0
last_host_key_observation=""

record_host_key_observation() {
  local observation="$1"

  case "$observation" in
    connection_refused) ((host_key_connection_refused += 1)) ;;
    connection_timeout) ((host_key_connection_timeout += 1)) ;;
    no_key) ((host_key_no_key += 1)) ;;
    multiple_keys) ((host_key_multiple_keys += 1)) ;;
    changed_key) ((host_key_changed_key += 1)) ;;
    other) ((host_key_other += 1)) ;;
    *)
      printf 'ERROR: internal host-key observation is outside the closed set.\n' >&2
      return 1
      ;;
  esac
  if [[ "$observation" != "$last_host_key_observation" ]]; then
    printf 'Host-key observation: %s\n' "$observation" >&2
    last_host_key_observation="$observation"
  fi
}

classify_host_key_scan() {
  local status="$1"
  local line_count="$2"
  local reachability="$3"

  case "$reachability" in
    connection_refused | connection_timeout | other)
      printf '%s\n' "$reachability"
      return 0
      ;;
    reachable) ;;
    *) return 1 ;;
  esac
  if ((line_count > 1)); then
    printf 'multiple_keys\n'
  elif ((line_count == 0)); then
    printf 'no_key\n'
  elif ((status != 0)); then
    printf 'other\n'
  else
    printf 'other\n'
  fi
}

observe_failed_host_key_scan() {
  local status="$1"
  local line_count="$2"
  local reachability

  if ((line_count > 1)); then
    printf 'multiple_keys\n'
    return 0
  fi
  reachability="$(
    python3 scripts/ci-cloud/probe-ssh-port.py "$address"
  )" || return 1
  classify_host_key_scan "$status" "$line_count" "$reachability"
}

render_host_key_observations() {
  printf -v host_key_observations_json \
    '{"changed_key":%d,"connection_refused":%d,"connection_timeout":%d,"multiple_keys":%d,"no_key":%d,"other":%d}' \
    "$host_key_changed_key" "$host_key_connection_refused" \
    "$host_key_connection_timeout" "$host_key_multiple_keys" \
    "$host_key_no_key" "$host_key_other"
}

record_remote_failure() {
  local status=$?
  trap - EXIT
  set +e
  [[ -z "$first_scan" ]] || rm -f -- "$first_scan"
  [[ -z "$second_scan" ]] || rm -f -- "$second_scan"
  if [[ "$bootstrap_stage" == host-key ]]; then
    render_host_key_observations
  fi
  if [[ "$status" -ne 0 &&
    (! -s "$evidence_json" || ! -s "$evidence_summary") ]]; then
    rm -f -- "$evidence_json" "$evidence_summary"
    if ! python3 scripts/ci-cloud/write-bootstrap-failure.py \
      "$evidence_dir" "$provider" "$region" "$profile" "$target_sha" \
      "$run_id" "$run_attempt" "$provider_image_slug" \
      "$provider_image_id" "$machine_type" "$orchestration_started_at" \
      "$bootstrap_stage" "$status" "$host_setup_failure_json" \
      "$host_key_observations_json"; then
      printf 'ERROR: unable to preserve bounded remote failure evidence.\n' >&2
    fi
  fi
  exit "$status"
}

trap record_remote_failure EXIT
first_scan="$(mktemp "$evidence_dir/.host-key-first.XXXXXX")"
second_scan="$(mktemp "$evidence_dir/.host-key-second.XXXXXX")"

host_key_ready=false
bootstrap_deadline=$((SECONDS + 15 * 60))
while ((SECONDS < bootstrap_deadline)); do
  : >"$first_scan"
  set +e
  ssh-keyscan -T 5 -t ed25519 "$address" >"$first_scan" 2>/dev/null
  first_scan_status=$?
  set -e
  first_scan_lines="$(grep -cve '^$' "$first_scan" || true)"
  if [[ "$first_scan_status" -ne 0 || "$first_scan_lines" -ne 1 ]]; then
    if ! first_scan_observation="$(
      observe_failed_host_key_scan \
        "$first_scan_status" "$first_scan_lines"
    )"; then
      printf 'ERROR: unable to obtain closed SSH reachability evidence.\n' >&2
      exit 1
    fi
    record_host_key_observation "$first_scan_observation"
    sleep 5
    continue
  fi

  sleep 2
  : >"$second_scan"
  set +e
  ssh-keyscan -T 5 -t ed25519 "$address" >"$second_scan" 2>/dev/null
  second_scan_status=$?
  set -e
  second_scan_lines="$(grep -cve '^$' "$second_scan" || true)"
  if [[ "$second_scan_status" -ne 0 || "$second_scan_lines" -ne 1 ]]; then
    if ! second_scan_observation="$(
      observe_failed_host_key_scan \
        "$second_scan_status" "$second_scan_lines"
    )"; then
      printf 'ERROR: unable to obtain closed SSH reachability evidence.\n' >&2
      exit 1
    fi
    record_host_key_observation "$second_scan_observation"
  elif cmp -s "$first_scan" "$second_scan"; then
    host_key_ready=true
    break
  else
    record_host_key_observation changed_key
  fi
  sleep 5
done
if [[ "$host_key_ready" != true ]]; then
  render_host_key_observations
  printf '%s%s\n' \
    'ERROR: unable to obtain one stable Ed25519 host key; closed observations: ' \
    "$host_key_observations_json" >&2
  exit 1
fi
install -m 0600 "$first_scan" "$known_hosts"
ssh-keygen -H -f "$known_hosts" >/dev/null 2>&1
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

bootstrap_stage="bootstrap"
operator_ssh_ready=false
diagnostic_ssh_seen=false
diagnostic_ssh_output=""
diagnostic_setup_failure=""
while ((SECONDS < bootstrap_deadline)); do
  if timeout --signal=TERM --kill-after=5s 20s \
    ssh "${ssh_options[@]}" "secpal-ci@$address" true \
    >/dev/null 2>&1; then
    operator_ssh_ready=true
    break
  fi
  set +e
  diagnostic_probe_output="$(
    timeout --signal=TERM --kill-after=5s 20s \
      ssh "${ssh_options[@]}" "secpal-ci-diagnostic@$address" true 2>&1
  )"
  diagnostic_probe_status=$?
  set -e
  diagnostic_probe_first_line="${diagnostic_probe_output%%$'\n'*}"
  if [[ "$diagnostic_probe_status" -eq 125 &&
    "$diagnostic_probe_first_line" == SECPAL_CI_DIAGNOSTIC_SSH ]]; then
    diagnostic_ssh_seen=true
    diagnostic_ssh_output="${diagnostic_probe_output#*$'\n'}"
    diagnostic_setup_failure_count="$(
      grep -c '^SECPAL_CI_HOST_SETUP_FAILURE ' \
        <<<"$diagnostic_ssh_output" || true
    )"
    if [[ "$diagnostic_setup_failure_count" -eq 1 ]]; then
      diagnostic_setup_failure="$(
        grep -m1 '^SECPAL_CI_HOST_SETUP_FAILURE ' \
          <<<"$diagnostic_ssh_output"
      )"
      diagnostic_setup_failure="${diagnostic_setup_failure#SECPAL_CI_HOST_SETUP_FAILURE }"
      set +e
      validated_setup_failure="$(
        printf '%s\n' "$diagnostic_setup_failure" |
          python3 scripts/ci-cloud/host-setup-failure.py validate
      )"
      validated_setup_failure_status=$?
      set -e
      if [[ "$validated_setup_failure_status" -eq 0 ]]; then
        host_setup_failure_json="$validated_setup_failure"
        break
      fi
    fi
  fi
  sleep 5
done
if [[ "$operator_ssh_ready" != true ]]; then
  if [[ "$diagnostic_ssh_seen" == true ]]; then
    printf 'ERROR: native bootstrap did not reach trusted host setup.\n' >&2
    printf '%s\n' "$diagnostic_ssh_output" >&2
  else
    printf '%s%s\n' \
      'ERROR: operator SSH access did not become ready; trusted host setup, ' \
      'network reachability, or sshd may have failed.' >&2
  fi
  exit 1
fi

set +e
operator_identity_diagnostic="$(
  timeout --signal=TERM --kill-after=15s 12m \
    ssh "${ssh_options[@]}" "secpal-ci@$address" /bin/bash -s <<'REMOTE'
set -euo pipefail
if [[ "$(id -u)" -ne 20000 || "$(id -un)" != secpal-ci ]]; then
  printf 'remote operator identity violates the closed bootstrap contract\n'
  exit 1
fi
REMOTE
)"
operator_identity_status=$?
set -e
if [[ "$operator_identity_status" -ne 0 ]]; then
  printf 'ERROR: remote operator identity failed bootstrap admission.\n' >&2
  if [[ -n "$operator_identity_diagnostic" ]]; then
    printf '%s\n' "$operator_identity_diagnostic" >&2
  fi
  set +e
  setup_diagnostic="$(
    timeout --signal=TERM --kill-after=5s 20s \
      ssh "${ssh_options[@]}" "secpal-ci@$address" \
      /usr/bin/python3 -I - read \
      < scripts/ci-cloud/host-setup-failure.py
  )"
  setup_diagnostic_status=$?
  set -e
  if [[ "$setup_diagnostic_status" -eq 0 && -n "$setup_diagnostic" ]]; then
    host_setup_failure_json="$setup_diagnostic"
    printf 'Trusted host setup failure: %s\n' \
      "$host_setup_failure_json" >&2
  fi
  exit "$operator_identity_status"
fi

bootstrap_stage="root-ssh"
set +e
timeout --signal=TERM --kill-after=5s 20s \
  ssh "${ssh_options[@]}" "root@$address" true >/dev/null 2>&1
root_probe_status=$?
operator_recheck_status=1
if [[ "$root_probe_status" -eq 255 ]]; then
  timeout --signal=TERM --kill-after=5s 20s \
    ssh "${ssh_options[@]}" "secpal-ci@$address" true >/dev/null 2>&1
  operator_recheck_status=$?
fi
set -e
root_ssh_denied=false
if [[ "$root_probe_status" -eq 255 && "$operator_recheck_status" -eq 0 ]]; then
  root_ssh_denied=true
fi

started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
bootstrap_stage="target"
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
) >/dev/null 2>&1
status=$?
set -e
exit "$status"
REMOTE
target_status=$?
set -e
ended_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

bootstrap_stage="collector"
ssh "${ssh_options[@]}" "secpal-ci@$address" \
  /usr/bin/env -i \
  HOME=/home/secpal-ci \
  LANG=C.UTF-8 \
  LC_ALL=C.UTF-8 \
  PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  /usr/bin/python3 -I - "$provider" "$region" "$profile" "$target_sha" \
  "$run_id" "$run_attempt" "$started_at" "$ended_at" "$target_status" \
  "$root_ssh_denied" "$provider_image_slug" "$provider_image_id" \
  "$machine_type" \
  < scripts/ci-cloud/collect-host-evidence.py > "$evidence_json"

bootstrap_stage="validation"
python3 scripts/ci-cloud/validate-evidence.py \
  "$evidence_json" "$evidence_summary" --require-passed
