#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

if [[ "$#" -ne 4 ]]; then
  printf 'usage: wait-github-artifact.sh REPOSITORY RUN_ID ARTIFACT DESTINATION\n' >&2
  exit 64
fi
readonly repository="$1"
readonly run_id="$2"
readonly artifact_name="$3"
readonly destination="$4"
readonly token="${GITHUB_TOKEN:-}"

[[ "$repository" == SecPal/deployment ]]
[[ "$run_id" =~ ^[1-9][0-9]{0,19}$ ]]
[[ "$artifact_name" =~ ^rocky-cloud-(access-request|access-ready)-[1-9][0-9]{0,19}-[1-9][0-9]{0,2}$ ]]
[[ "$destination" == /*/rocky-exchange ]]
[[ -n "$token" && "$token" != *[[:space:]]* ]]
install -d -m 0700 "$destination"

for attempt in {1..600}; do
  artifact_id="$(
    GH_TOKEN="$token" gh api \
      "repos/$repository/actions/runs/$run_id/artifacts?per_page=100" \
      --jq ".artifacts[] | select(.name == \"$artifact_name\" and .expired == false) | .id" |
      head -n 2
  )"
  if [[ "$artifact_id" =~ ^[1-9][0-9]{0,19}$ ]]; then
    archive="$(mktemp "$destination/.artifact.XXXXXX.zip")"
    chmod 0600 "$archive"
    GH_TOKEN="$token" gh api \
      -H 'Accept: application/vnd.github+json' \
      "repos/$repository/actions/artifacts/$artifact_id/zip" >"$archive"
    unzip -q "$archive" -d "$destination"
    rm -f -- "$archive"
    exit 0
  fi
  [[ -z "$artifact_id" ]]
  [[ "$attempt" -lt 600 ]]
  sleep 5
done

printf 'ERROR: bounded artifact wait expired.\n' >&2
exit 1
