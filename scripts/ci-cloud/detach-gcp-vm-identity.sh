#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

if [[ "$#" -ne 4 ]]; then
  printf 'ERROR: expected GCP project, zone, exact instance name, and bootstrap identity.\n' >&2
  exit 2
fi

project_id="$1"
zone="$2"
instance_name="$3"
bootstrap_service_account="$4"
access_token="${GOOGLE_OAUTH_ACCESS_TOKEN:-}"
admission_key="secpal-ci-cloud-identity-admitted"

[[ "$project_id" == secpal-dev ]]
[[ "$zone" == europe-west3-a ]]
[[ "$instance_name" =~ ^spci-[1-9][0-9]{0,19}-[1-9][0-9]{0,2}-instance$ ]]
[[ "$bootstrap_service_account" =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]@secpal-dev\.iam\.gserviceaccount\.com$ ]]
[[ "$bootstrap_service_account" != gcp-service-account@secpal-dev.iam.gserviceaccount.com ]]
if [[ ! "$access_token" =~ ^[A-Za-z0-9._~-]{20,4096}$ ]]; then
  printf 'ERROR: GCP access token is outside the closed in-memory format.\n' >&2
  exit 2
fi

api_root="https://compute.googleapis.com/compute/v1/projects/$project_id/zones/$zone"
instance_path="instances/$instance_name"
temporary_directory="$(mktemp -d)"
transition_deadline=$((SECONDS + 900))

cleanup() {
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
    set_admission_metadata "$initial_instance" RUNNING >/dev/null
  fi
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
running_instance="$(wait_for_instance_status RUNNING)"
if ! verify_identity_free "$running_instance"; then
  printf 'ERROR: GCP VM cloud identity reappeared after start.\n' >&2
  exit 1
fi
if [[ "$(admission_state "$running_instance")" != admitted ]]; then
  printf 'ERROR: trusted GCP identity admission disappeared after start.\n' >&2
  exit 1
fi

printf 'GCP fixture is running without an attached cloud identity.\n'
