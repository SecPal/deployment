#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

if [[ "$#" -ne 5 ]]; then
  printf 'ERROR: expected GCP project, zone, exact instance name, bootstrap identity, and live IPv4 output.\n' >&2
  exit 2
fi

project_id="$1"
zone="$2"
instance_name="$3"
bootstrap_service_account="$4"
ipv4_output="$5"
access_token="${GOOGLE_OAUTH_ACCESS_TOKEN:-}"
admission_key="secpal-ci-cloud-identity-admitted"

[[ "$project_id" == secpal-dev ]]
[[ "$zone" == europe-west3-a ]]
[[ "$instance_name" =~ ^spci-[1-9][0-9]{0,19}-[1-9][0-9]{0,2}-instance$ ]]
[[ "$bootstrap_service_account" =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]@secpal-dev\.iam\.gserviceaccount\.com$ ]]
[[ "$bootstrap_service_account" != gcp-service-account@secpal-dev.iam.gserviceaccount.com ]]
if [[ "$ipv4_output" != /*/ipv4_address ]]; then
  printf 'ERROR: live GCP IPv4 output is outside the closed path format.\n' >&2
  exit 2
fi
if [[ ! "$access_token" =~ ^[A-Za-z0-9._~-]{20,4096}$ ]]; then
  printf 'ERROR: GCP access token is outside the closed in-memory format.\n' >&2
  exit 2
fi

api_root="https://compute.googleapis.com/compute/v1/projects/$project_id/zones/$zone"
instance_path="instances/$instance_name"
temporary_directory="$(mktemp -d)"
published_ipv4_tmp=""
transition_deadline=$((SECONDS + 900))

cleanup() {
  if [[ -n "$published_ipv4_tmp" ]]; then
    rm -f -- "$published_ipv4_tmp"
  fi
  rm -rf -- "$temporary_directory"
}
trap cleanup EXIT

api_request() {
  local method="$1"
  local path="$2"
  local payload="${3:-}"
  local response
  local -a arguments=(
    --disable
    --proto '=https'
    --tlsv1.2
    --noproxy '*'
    --fail
    --silent
    --show-error
    --connect-timeout 10
    --max-time 30
    --max-filesize 1048576
  )

  response="$(mktemp "$temporary_directory/response.XXXXXX")"
  chmod 0600 "$response"
  if [[ "$method" == POST ]]; then
    arguments+=(
      --request POST
      --header 'Content-Type: application/json'
      --data "$payload"
    )
  else
    [[ "$method" == GET && -z "$payload" ]]
  fi
  printf 'header = "Authorization: Bearer %s"\n' "$access_token" |
    curl "${arguments[@]}" --config - "$api_root/$path" >"$response"
  [[ -s "$response" && "$(stat -c '%s' -- "$response")" -le 1048576 ]]
  jq -e 'type == "object"' "$response" >/dev/null
  cat -- "$response"
  rm -f -- "$response"
}

wait_for_operation() {
  local operation_name="$1"
  local attempt response status

  [[ "$operation_name" =~ ^[a-z0-9][a-z0-9-]{0,127}$ ]]
  for ((attempt = 1; attempt <= 60 && SECONDS < transition_deadline; attempt += 1)); do
    response="$(api_request GET "operations/$operation_name")"
    status="$(jq -er '.status' <<<"$response")"
    case "$status" in
      DONE)
        if ! jq -e \
          '(.error // null) == null and (.httpErrorStatusCode // null) == null' \
          <<<"$response" >/dev/null; then
          printf 'ERROR: bounded GCP operation failed.\n' >&2
          return 1
        fi
        return 0
        ;;
      PENDING | RUNNING) ;;
      *)
        printf 'ERROR: GCP operation returned an unknown status.\n' >&2
        return 1
        ;;
    esac
    sleep 5
  done
  printf 'ERROR: GCP operation exceeded its bounded transition window.\n' >&2
  return 1
}

wait_for_instance_status() {
  local expected_status="$1"
  local attempt response status

  [[ "$expected_status" == RUNNING || "$expected_status" == TERMINATED ]]
  for ((attempt = 1; attempt <= 60 && SECONDS < transition_deadline; attempt += 1)); do
    response="$(api_request GET "$instance_path")"
    jq -e --arg name "$instance_name" '.name == $name' \
      <<<"$response" >/dev/null
    status="$(jq -er '.status' <<<"$response")"
    if [[ "$status" == "$expected_status" ]]; then
      printf '%s' "$response"
      return 0
    fi
    case "$status" in
      PROVISIONING | STAGING | RUNNING | STOPPING | TERMINATED) ;;
      *)
        printf 'ERROR: GCP instance returned an unknown status.\n' >&2
        return 1
        ;;
    esac
    sleep 5
  done
  printf 'ERROR: GCP instance status exceeded its bounded transition window.\n' >&2
  return 1
}

admission_state() {
  local instance="$1"

  jq -er --arg key "$admission_key" '
    [.metadata.items[]? | select(.key == $key)] as $entries |
    if ($entries | length) == 0 then
      "absent"
    elif ($entries | length) == 1 and $entries[0].value == "true" then
      "admitted"
    else
      error("invalid or duplicate cloud-identity admission metadata")
    end
  ' <<<"$instance"
}

verify_identity_free() {
  local instance="$1"

  jq -e '((.serviceAccounts // []) | length) == 0' \
    <<<"$instance" >/dev/null
}

validate_public_ipv4() {
  local candidate="$1"

  python3 - "$candidate" <<'PY'
import ipaddress
import sys

try:
    address = ipaddress.ip_address(sys.argv[1])
except ValueError:
    raise SystemExit("GCP fixture address is not an IP address") from None
if address.version != 4 or not address.is_global:
    raise SystemExit("GCP fixture address is not a public IPv4 address")
print(address)
PY
}

public_ipv4_from_instance() {
  local instance="$1"
  local candidate

  if ! candidate="$(
    jq -er '
      [.networkInterfaces[]?.accessConfigs[]?] as $configs |
      if ($configs | length) == 0 or
        (($configs | length) == 1 and
          (($configs[0].natIP // null) == null))
      then ""
      elif ($configs | length) == 1 and
        ($configs[0].natIP | type) == "string"
      then $configs[0].natIP
      else error("ambiguous or invalid external IPv4 access configuration")
      end
    ' <<<"$instance"
  )"; then
    printf 'ERROR: running GCP fixture has an ambiguous external address.\n' >&2
    return 1
  fi
  if [[ -z "$candidate" ]]; then
    return 75
  fi
  if ! validate_public_ipv4 "$candidate"; then
    printf 'ERROR: running GCP fixture address failed public IPv4 admission.\n' >&2
    return 1
  fi
}

wait_for_admitted_identity_free_public_ipv4() {
  local attempt response status live_ipv4 address_status

  for ((attempt = 1; attempt <= 60 && SECONDS < transition_deadline; attempt += 1)); do
    response="$(api_request GET "$instance_path")"
    jq -e --arg name "$instance_name" '.name == $name' \
      <<<"$response" >/dev/null
    status="$(jq -er '.status' <<<"$response")"
    case "$status" in
      RUNNING)
        if ! verify_identity_free "$response"; then
          printf 'ERROR: GCP VM cloud identity is attached in the final running state.\n' >&2
          return 1
        fi
        if [[ "$(admission_state "$response")" != admitted ]]; then
          printf 'ERROR: trusted GCP identity admission is absent from the final running state.\n' >&2
          return 1
        fi
        address_status=0
        live_ipv4="$(public_ipv4_from_instance "$response")" || address_status=$?
        case "$address_status" in
          0)
            printf '%s' "$live_ipv4"
            return 0
            ;;
          75) ;;
          *) return 1 ;;
        esac
        ;;
      PROVISIONING | STAGING | STOPPING | TERMINATED) ;;
      *)
        printf 'ERROR: GCP instance returned an unknown final status.\n' >&2
        return 1
        ;;
    esac
    sleep 5
  done
  printf 'ERROR: GCP fixture did not reach its complete network and identity postcondition.\n' >&2
  return 1
}

publish_current_ipv4() {
  local candidate="$1"
  local output_directory validated_ipv4

  if ! validated_ipv4="$(validate_public_ipv4 "$candidate")"; then
    printf 'ERROR: live GCP IPv4 handoff failed public-address admission.\n' >&2
    return 1
  fi

  output_directory="${ipv4_output%/*}"
  if [[ ! -d "$output_directory" || -L "$output_directory" ||
    "$(stat -c '%u:%a' -- "$output_directory")" != "$(id -u):700" ||
    -e "$ipv4_output" || -L "$ipv4_output" ]]; then
    printf 'ERROR: live GCP IPv4 output location is not a fresh private directory.\n' >&2
    return 1
  fi
  published_ipv4_tmp="$(mktemp "$output_directory/.ipv4_address.XXXXXX")"
  chmod 0600 "$published_ipv4_tmp"
  printf '%s\n' "$validated_ipv4" >"$published_ipv4_tmp"
  mv -T -- "$published_ipv4_tmp" "$ipv4_output"
  published_ipv4_tmp=""
  printf 'Recorded the verified live GCP fixture address.\n'
}

set_admission_metadata() {
  local instance="$1"
  local expected_status="$2"
  local metadata_payload operation_name admitted_instance

  [[ "$(admission_state "$instance")" == absent ]]
  metadata_payload="$(
    jq -ce --arg key "$admission_key" '
      (.metadata // null) as $metadata |
      ($metadata.items // []) as $items |
      if ($metadata.fingerprint | type) != "string" or
        ($metadata.fingerprint | length) == 0 or
        any($items[]?; .key == $key) then
        error("unsafe instance metadata admission state")
      else
        {
          fingerprint: $metadata.fingerprint,
          items: ($items + [{key: $key, value: "true"}])
        }
      end
    ' <<<"$instance"
  )"
  operation_name="$(
    api_request POST "$instance_path/setMetadata" "$metadata_payload" |
      jq -er '.name'
  )"
  wait_for_operation "$operation_name"
  admitted_instance="$(wait_for_instance_status "$expected_status")"
  verify_identity_free "$admitted_instance"
  [[ "$(admission_state "$admitted_instance")" == admitted ]]
  printf '%s' "$admitted_instance"
}

initial_instance="$(api_request GET "$instance_path")"
jq -e --arg name "$instance_name" \
  '.name == $name and .status == "RUNNING"' \
  <<<"$initial_instance" >/dev/null
initial_admission="$(admission_state "$initial_instance")"
if verify_identity_free "$initial_instance"; then
  if [[ "$initial_admission" == absent ]]; then
    printf 'Admitting the already identity-free running GCP fixture.\n'
    initial_instance="$(set_admission_metadata "$initial_instance" RUNNING)"
  fi
  live_ipv4="$(wait_for_admitted_identity_free_public_ipv4)"
  publish_current_ipv4 "$live_ipv4"
  printf 'GCP fixture is already running without an attached cloud identity.\n'
  exit 0
fi
if [[ "$initial_admission" != absent ]] || ! jq -e \
  --arg email "$bootstrap_service_account" \
  '(.serviceAccounts | length) == 1 and
   .serviceAccounts[0].email == $email and
   ((.serviceAccounts[0].scopes // []) | length) == 0' \
  <<<"$initial_instance" >/dev/null; then
  printf 'ERROR: GCP fixture did not start with the closed bootstrap identity.\n' >&2
  exit 1
fi

printf 'Stopping exact GCP fixture before identity removal.\n'
stop_operation="$(
  api_request POST "$instance_path/stop" '{}' | jq -er '.name'
)"
wait_for_operation "$stop_operation"
stopped_instance="$(wait_for_instance_status TERMINATED)"
[[ "$(admission_state "$stopped_instance")" == absent ]]
jq -e --arg email "$bootstrap_service_account" \
  '(.serviceAccounts | length) == 1 and
   .serviceAccounts[0].email == $email and
   ((.serviceAccounts[0].scopes // []) | length) == 0' \
  <<<"$stopped_instance" >/dev/null

printf 'Removing every service account from the stopped GCP fixture.\n'
identity_operation="$(
  api_request POST "$instance_path/setServiceAccount" \
    '{"scopes":[]}' | jq -er '.name'
)"
wait_for_operation "$identity_operation"
detached_instance="$(wait_for_instance_status TERMINATED)"
if ! verify_identity_free "$detached_instance"; then
  printf 'ERROR: GCP VM cloud identity remains attached while stopped.\n' >&2
  exit 1
fi
[[ "$(admission_state "$detached_instance")" == absent ]]

printf 'Recording trusted admission only after verified identity removal.\n'
detached_instance="$(
  set_admission_metadata "$detached_instance" TERMINATED
)"

printf 'Starting the identity-free GCP fixture.\n'
start_operation="$(
  api_request POST "$instance_path/start" '{}' | jq -er '.name'
)"
wait_for_operation "$start_operation"
live_ipv4="$(wait_for_admitted_identity_free_public_ipv4)"
publish_current_ipv4 "$live_ipv4"
printf 'GCP fixture is running without an attached cloud identity.\n'
