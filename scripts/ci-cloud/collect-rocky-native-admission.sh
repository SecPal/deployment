#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

set -euo pipefail

if [[ "$#" -ne 4 ]]; then
  printf 'usage: collect-rocky-native-admission.sh TARGET_SHA CONTROL_SHA RUN_ID RUN_ATTEMPT\n' >&2
  exit 2
fi

readonly target_sha="$1" control_sha="$2" run_id="$3" run_attempt="$4"
[[ "$target_sha" =~ ^[0-9a-f]{40}$ ]]
[[ "$control_sha" =~ ^[0-9a-f]{40}$ ]]
[[ "$run_id" =~ ^[1-9][0-9]{0,19}$ ]]
[[ "$run_attempt" =~ ^[1-9][0-9]{0,2}$ ]]

readonly root=/var/lib/secpal-rocky/evidence
readonly output="$root/native-package-observation.json"
readonly diagnostic="$root/native-package-observation-failure.json"
rm -f -- "$output" "$diagnostic"
set +e
/usr/local/sbin/secpal-collect-rocky-preparation \
  --native-package-admission --target-sha "$target_sha" \
  --control-sha "$control_sha" --run-id "$run_id" \
  --run-attempt "$run_attempt" --output "$output" \
  --diagnostic-output "$diagnostic"
status=$?
set -e
if [[ "$status" -ne 0 ]]; then
  [[ -f "$diagnostic" && ! -L "$diagnostic" ]]
  /opt/secpal-control/scripts/ci-cloud/rocky-control.py \
    validate-collection-diagnostic "$diagnostic"
  chown secpal-cloud:secpal-cloud "$diagnostic"
  chmod 0400 "$diagnostic"
  exit 92
fi
/opt/secpal-control/scripts/ci-cloud/rocky-control.py \
  validate-native-observation "$output" \
  --target-sha "$target_sha" --control-sha "$control_sha" \
  --run-id "$run_id" --run-attempt "$run_attempt"
chown secpal-cloud:secpal-cloud "$output"
chmod 0400 "$output"
