#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

admission_path="instance/attributes/secpal-ci-cloud-identity-admitted"
identity_path="instance/service-accounts/"
admission_deadline=$((SECONDS + 900))
waiting_reported=false
identity_admitted=false

probe_metadata_status() {
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
        exec 3<>/dev/tcp/169.254.169.254/80
        printf "%s\r\n" \
          "GET /computeMetadata/v1/$metadata_path HTTP/1.1" \
          "Host: metadata.google.internal" \
          "Metadata-Flavor: Google" \
          "Connection: close" "" >&3
        IFS=" " read -r http_version http_status ignored <&3
        case "$http_version" in HTTP/1.0 | HTTP/1.1) ;; *) exit 1 ;; esac
        [[ "$http_status" =~ ^[0-9]{3}$ ]]
        printf "%s" "$http_status"
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

while ((SECONDS < admission_deadline)); do
  admission_status="$(probe_metadata_status "$admission_path")"
  identity_status="$(probe_metadata_status "$identity_path")"

  if [[ "$admission_status" == 200 && "$identity_status" == 404 ]]; then
    identity_admitted=true
    break
  fi
  if [[ "$admission_status" == 200 ]]; then
    printf 'ERROR: trusted GCP admission appeared while cloud identity remained.\n' >&2
    exit 1
  fi
  if [[ "$admission_status" != 404 || \
    ("$identity_status" != 200 && "$identity_status" != 404) ]]; then
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
