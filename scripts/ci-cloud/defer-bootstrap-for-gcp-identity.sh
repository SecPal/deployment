#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

export LC_ALL=C

admission_path="instance/attributes/secpal-ci-cloud-identity-admitted"
identity_path="instance/service-accounts/"
admission_deadline=$((SECONDS + 900))
waiting_reported=false
identity_admitted=false

probe_metadata_response() {
  local metadata_path="$1"
  local probe_output probe_status

  [[ "$metadata_path" =~ ^instance/[a-z0-9_./-]{1,128}$ ]]
  set +e
  probe_output="$(
    # This literal is intentionally evaluated only by the isolated child Bash.
    # shellcheck disable=SC2016
    timeout --signal=TERM --kill-after=1s 5s \
      /bin/bash --noprofile --norc -c '
        set -euo pipefail
        metadata_path="$1"
        carriage_return="$(printf "\\r")"
        exec 3<>/dev/tcp/169.254.169.254/80
        printf "%s\r\n" \
          "GET /computeMetadata/v1/$metadata_path HTTP/1.1" \
          "Host: metadata.google.internal" \
          "Metadata-Flavor: Google" \
          "Connection: close" "" >&3
        IFS= read -r status_line <&3
        status_line="${status_line%"$carriage_return"}"
        [[ "$status_line" =~ ^HTTP/(1\.0|1\.1)\ ([0-9]{3})(\ .*)?$ ]]
        http_status="${BASH_REMATCH[2]}"

        header_count=0
        headers_complete=false
        while IFS= read -r header_line <&3; do
          header_line="${header_line%"$carriage_return"}"
          ((header_count += 1))
          [[ "$header_count" -le 64 && "${#header_line}" -le 1024 ]]
          if [[ -z "$header_line" ]]; then
            headers_complete=true
            break
          fi
        done
        [[ "$headers_complete" == true ]]

        response_body="$(head -c 4097 <&3)"
        [[ "${#response_body}" -le 4096 ]]
        printf "%s\n" "$http_status"
        printf "%s" "$response_body" | base64 -w 0
      ' bash "$metadata_path"
  )"
  probe_status=$?
  set -e
  if [[ "$probe_status" -ne 0 ]]; then
    printf 'ERROR: unable to verify the GCP VM cloud-identity gate.\n' >&2
    return 1
  fi
  printf '%s' "$probe_output"
}

classify_metadata_response() {
  local response="$1"
  local response_kind="$2"

  if [[ "$response" == *$'\n'* ]]; then
    metadata_http_status="${response%%$'\n'*}"
    metadata_body_base64="${response#*$'\n'}"
  else
    metadata_http_status="$response"
    metadata_body_base64=""
  fi
  [[ "$metadata_http_status" =~ ^[0-9]{3}$ ]]
  [[ "${#metadata_body_base64}" -le 5464 ]]
  [[ -z "$metadata_body_base64" || \
    "$metadata_body_base64" =~ ^[A-Za-z0-9+/]+={0,2}$ ]]

  case "$response_kind:$metadata_http_status" in
    admission:404)
      metadata_state=missing
      ;;
    admission:200)
      [[ "$metadata_body_base64" == dHJ1ZQ== ]]
      metadata_state=admitted
      ;;
    identity:200)
      if [[ -z "$metadata_body_base64" ]]; then
        metadata_state=absent
      else
        metadata_state=present
      fi
      ;;
    *)
      printf 'ERROR: GCP VM cloud-identity gate returned an unexpected metadata response.\n' >&2
      return 1
      ;;
  esac
}

while ((SECONDS < admission_deadline)); do
  admission_response="$(probe_metadata_response "$admission_path")"
  classify_metadata_response "$admission_response" admission
  admission_status="$metadata_http_status"
  admission_state="$metadata_state"

  identity_response="$(probe_metadata_response "$identity_path")"
  classify_metadata_response "$identity_response" identity
  identity_status="$metadata_http_status"
  identity_state="$metadata_state"

  if [[ "$admission_state" == admitted && "$identity_state" == absent ]]; then
    identity_admitted=true
    break
  fi
  if [[ "$admission_state" == admitted ]]; then
    printf 'ERROR: trusted GCP admission appeared while cloud identity remained.\n' >&2
    exit 1
  fi
  if [[ "$admission_status" != 404 || "$identity_status" != 200 ]]; then
    printf 'ERROR: GCP VM cloud-identity gate returned unexpected HTTP states.\n' >&2
    exit 1
  fi
  if [[ "$waiting_reported" == false ]]; then
    printf 'GCP bootstrap is waiting for trusted GCP identity admission.\n'
    waiting_reported=true
  fi
  sleep 2
done

if [[ "$identity_admitted" != true ]]; then
  printf 'ERROR: trusted GCP identity admission exceeded its bounded window.\n' >&2
  exit 1
fi
