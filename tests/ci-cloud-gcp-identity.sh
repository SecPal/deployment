#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
IDENTITY_SCRIPT="$ROOT_DIR/scripts/ci-cloud/detach-gcp-vm-identity.sh"
GATE_SCRIPT="$ROOT_DIR/scripts/ci-cloud/defer-bootstrap-for-gcp-identity.sh"
TEMP_DIR="$(mktemp -d)"
FAKE_BIN="$TEMP_DIR/bin"
STATE="$TEMP_DIR/state"
CALLS="$TEMP_DIR/calls"
GATE_STATE="$TEMP_DIR/gate-state"

cleanup() {
  rm -rf -- "$TEMP_DIR"
}
trap cleanup EXIT

install -d -m 0700 "$FAKE_BIN"

cat >"$FAKE_BIN/curl" <<'FAKE_CURL'
#!/usr/bin/env bash
set -euo pipefail

method=GET
data=""
authorization=false
url=""
while (($# > 0)); do
  case "$1" in
    --request)
      method="$2"
      shift 2
      ;;
    --data)
      data="$2"
      shift 2
      ;;
    --header)
      shift 2
      ;;
    --config)
      [[ "$2" == - ]]
      IFS= read -r curl_config
      [[ "$curl_config" == \
        "header = \"Authorization: Bearer $SECPAL_TEST_TOKEN\"" ]]
      authorization=true
      shift 2
      ;;
    --proto | --max-time | --connect-timeout | --max-filesize)
      shift 2
      ;;
    --disable | --tlsv1.2 | --fail | --silent | --show-error | --location)
      shift
      ;;
    --noproxy)
      [[ "$2" == "*" ]]
      shift 2
      ;;
    https://compute.googleapis.com/*)
      url="$1"
      shift
      ;;
    *)
      printf 'unexpected curl argument: %s\n' "$1" >&2
      exit 90
      ;;
  esac
done

[[ "$authorization" == true && -n "$url" ]]
path="${url#https://compute.googleapis.com/compute/v1/}"
printf '%s %s %s\n' "$method" "$path" "$data" >>"$SECPAL_TEST_CALLS"

case "$method $path" in
  "GET projects/secpal-dev/zones/europe-west3-a/instances/spci-12345-2-instance")
    case "$(<"$SECPAL_TEST_STATE")" in
      running-attached)
        printf '%s\n' '{"name":"spci-12345-2-instance","status":"RUNNING","metadata":{"fingerprint":"test-fingerprint","items":[{"key":"startup-script","value":"trusted"}]},"serviceAccounts":[{"email":"secpal-ci-bootstrap@secpal-dev.iam.gserviceaccount.com","scopes":[]}]}'
        ;;
      running-wrong-identity)
        printf '%s\n' '{"name":"spci-12345-2-instance","status":"RUNNING","metadata":{"fingerprint":"test-fingerprint","items":[]},"serviceAccounts":[{"email":"unexpected@secpal-dev.iam.gserviceaccount.com","scopes":[]}]}'
        ;;
      running-scoped-identity)
        printf '%s\n' '{"name":"spci-12345-2-instance","status":"RUNNING","metadata":{"fingerprint":"test-fingerprint","items":[]},"serviceAccounts":[{"email":"secpal-ci-bootstrap@secpal-dev.iam.gserviceaccount.com","scopes":["https://www.googleapis.com/auth/cloud-platform"]}]}'
        ;;
      terminated-attached)
        printf '%s\n' '{"name":"spci-12345-2-instance","status":"TERMINATED","metadata":{"fingerprint":"test-fingerprint","items":[{"key":"startup-script","value":"trusted"}]},"serviceAccounts":[{"email":"secpal-ci-bootstrap@secpal-dev.iam.gserviceaccount.com","scopes":[]}]}'
        ;;
      terminated-detached)
        printf '%s\n' '{"name":"spci-12345-2-instance","status":"TERMINATED","metadata":{"fingerprint":"test-fingerprint","items":[{"key":"startup-script","value":"trusted"}]}}'
        ;;
      running-detached)
        printf '%s\n' '{"name":"spci-12345-2-instance","status":"RUNNING","metadata":{"fingerprint":"test-fingerprint","items":[{"key":"startup-script","value":"trusted"}]},"serviceAccounts":[]}'
        ;;
      terminated-admitted)
        printf '%s\n' '{"name":"spci-12345-2-instance","status":"TERMINATED","metadata":{"fingerprint":"admitted-fingerprint","items":[{"key":"startup-script","value":"trusted"},{"key":"secpal-ci-cloud-identity-admitted","value":"true"}]}}'
        ;;
      running-admitted)
        printf '%s\n' '{"name":"spci-12345-2-instance","status":"RUNNING","metadata":{"fingerprint":"admitted-fingerprint","items":[{"key":"startup-script","value":"trusted"},{"key":"secpal-ci-cloud-identity-admitted","value":"true"}]},"serviceAccounts":[]}'
        ;;
      *) exit 91 ;;
    esac
    ;;
  "POST projects/secpal-dev/zones/europe-west3-a/instances/spci-12345-2-instance/stop")
    printf '%s\n' terminated-attached >"$SECPAL_TEST_STATE"
    printf '%s\n' '{"name":"1234567890"}'
    ;;
  "POST projects/secpal-dev/zones/europe-west3-a/instances/spci-12345-2-instance/setServiceAccount")
    [[ "$data" == '{"scopes":[]}' ]]
    if [[ "$SECPAL_TEST_KEEP_IDENTITY" == true ]]; then
      printf '%s\n' terminated-attached >"$SECPAL_TEST_STATE"
    else
      printf '%s\n' terminated-detached >"$SECPAL_TEST_STATE"
    fi
    printf '%s\n' '{"name":"operation-identity"}'
    ;;
  "POST projects/secpal-dev/zones/europe-west3-a/instances/spci-12345-2-instance/setMetadata")
    jq -e '
      .fingerprint == "test-fingerprint" and
      ([.items[] | select(.key == "secpal-ci-cloud-identity-admitted" and
        .value == "true")] | length) == 1 and
      ([.items[] | select(.key == "startup-script" and
        .value == "trusted")] | length) == 1
    ' <<<"$data" >/dev/null
    case "$(<"$SECPAL_TEST_STATE")" in
      terminated-detached)
        printf '%s\n' terminated-admitted >"$SECPAL_TEST_STATE"
        ;;
      running-detached)
        printf '%s\n' running-admitted >"$SECPAL_TEST_STATE"
        ;;
      *) exit 93 ;;
    esac
    printf '%s\n' '{"name":"operation-metadata"}'
    ;;
  "POST projects/secpal-dev/zones/europe-west3-a/instances/spci-12345-2-instance/start")
    [[ "$(<"$SECPAL_TEST_STATE")" == terminated-admitted ]]
    printf '%s\n' running-admitted >"$SECPAL_TEST_STATE"
    printf '%s\n' '{"name":"operation-start"}'
    ;;
  "GET projects/secpal-dev/zones/europe-west3-a/operations/1234567890" | \
    "GET projects/secpal-dev/zones/europe-west3-a/operations/operation-identity" | \
    "GET projects/secpal-dev/zones/europe-west3-a/operations/operation-metadata" | \
    "GET projects/secpal-dev/zones/europe-west3-a/operations/operation-start")
    if [[ "$SECPAL_TEST_OPERATION_ERROR" == true && \
      "$path" == */operation-identity ]]; then
      printf '%s\n' \
        '{"status":"DONE","error":{"errors":[{"code":"FAILED"}]}}'
    else
      printf '%s\n' '{"status":"DONE"}'
    fi
    ;;
  *)
    printf 'unexpected request: %s %s\n' "$method" "$path" >&2
    exit 92
    ;;
esac
FAKE_CURL
chmod 0700 "$FAKE_BIN/curl"

cat >"$FAKE_BIN/sleep" <<'FAKE_SLEEP'
#!/usr/bin/env bash
set -euo pipefail
[[ "$#" -eq 1 && "$1" == 5 ]]
FAKE_SLEEP
chmod 0700 "$FAKE_BIN/sleep"

run_transition() {
  PATH="$FAKE_BIN:/usr/bin:/bin" \
    GOOGLE_OAUTH_ACCESS_TOKEN=test-access-token-with-bounded-content \
    SECPAL_TEST_TOKEN=test-access-token-with-bounded-content \
    SECPAL_TEST_STATE="$STATE" \
    SECPAL_TEST_CALLS="$CALLS" \
    SECPAL_TEST_KEEP_IDENTITY="$1" \
    SECPAL_TEST_OPERATION_ERROR="$2" \
    "$IDENTITY_SCRIPT" secpal-dev europe-west3-a spci-12345-2-instance \
    secpal-ci-bootstrap@secpal-dev.iam.gserviceaccount.com
}

printf '%s\n' running-attached >"$STATE"
: >"$CALLS"
run_transition false false
[[ "$(<"$STATE")" == running-admitted ]]
[[ "$(grep -c 'setServiceAccount' "$CALLS")" -eq 1 ]]
[[ "$(grep -c 'setMetadata' "$CALLS")" -eq 1 ]]
[[ "$(grep -c '/start ' "$CALLS")" -eq 1 ]]
[[ "$(tail -n 1 "$CALLS")" == \
  'GET projects/secpal-dev/zones/europe-west3-a/instances/spci-12345-2-instance ' ]]

printf '%s\n' running-detached >"$STATE"
: >"$CALLS"
run_transition false false
[[ "$(<"$STATE")" == running-admitted ]]
[[ "$(grep -c 'setMetadata' "$CALLS")" -eq 1 ]]
if grep -Eq '/(stop|setServiceAccount|start) ' "$CALLS"; then
  printf 'identity-free fixture was mutated unexpectedly\n' >&2
  exit 1
fi

printf '%s\n' running-admitted >"$STATE"
: >"$CALLS"
run_transition false false
[[ "$(<"$STATE")" == running-admitted ]]
if grep -Eq '/(stop|setServiceAccount|setMetadata|start) ' "$CALLS"; then
  printf 'admitted identity-free fixture was mutated unexpectedly\n' >&2
  exit 1
fi

for invalid_state in running-wrong-identity running-scoped-identity; do
  printf '%s\n' "$invalid_state" >"$STATE"
  : >"$CALLS"
  set +e
  run_transition false false
  status=$?
  set -e
  [[ "$status" -ne 0 ]]
  if grep -Eq 'POST ' "$CALLS"; then
    printf 'invalid bootstrap identity was mutated unexpectedly\n' >&2
    exit 1
  fi
done

printf '%s\n' running-attached >"$STATE"
: >"$CALLS"
set +e
run_transition true false
status=$?
set -e
[[ "$status" -ne 0 ]]
[[ "$(<"$STATE")" == terminated-attached ]]
if grep -q '/start ' "$CALLS"; then
  printf 'identity-retaining fixture was started unexpectedly\n' >&2
  exit 1
fi

printf '%s\n' running-attached >"$STATE"
: >"$CALLS"
set +e
run_transition false true
status=$?
set -e
[[ "$status" -ne 0 ]]
if grep -q '/start ' "$CALLS"; then
  printf 'fixture was started after a failed identity operation\n' >&2
  exit 1
fi

cat >"$FAKE_BIN/timeout" <<'FAKE_METADATA_TIMEOUT'
#!/usr/bin/env bash
set -euo pipefail

[[ "$*" == *"/bin/bash --noprofile --norc -c"* ]]
[[ "$*" == *"/dev/tcp/169.254.169.254/80"* ]]
[[ "$*" == *"Metadata-Flavor: Google"* ]]
if [[ "$SECPAL_TEST_GATE_MODE" == transport-error ]]; then
  exit 7
fi
if [[ "$*" == *"secpal-ci-cloud-identity-admitted"* ]]; then
  case "$(<"$SECPAL_TEST_GATE_STATE")" in
    waiting) printf '%s' 404 ;;
    admitted) printf '%s\n%s' 200 dHJ1ZQ== ;;
    inconsistent) printf '%s\n%s' 200 dHJ1ZQ== ;;
    identity-not-found) printf '%s' 404 ;;
  esac
else
  case "$(<"$SECPAL_TEST_GATE_STATE")" in
    waiting) printf '%s\n%s' 200 ZGVmYXVsdC8= ;;
    admitted) printf '%s' 200 ;;
    inconsistent) printf '%s\n%s' 200 ZGVmYXVsdC8= ;;
    identity-not-found) printf '%s' 404 ;;
  esac
fi
FAKE_METADATA_TIMEOUT
chmod 0700 "$FAKE_BIN/timeout"

cat >"$FAKE_BIN/sleep" <<'FAKE_GATE_SLEEP'
#!/usr/bin/env bash
set -euo pipefail
[[ "$#" -eq 1 && "$1" == 2 ]]
printf '%s\n' admitted >"$SECPAL_TEST_GATE_STATE"
FAKE_GATE_SLEEP
chmod 0700 "$FAKE_BIN/sleep"

printf '%s\n' waiting >"$GATE_STATE"
gate_output="$(
  PATH="$FAKE_BIN:/usr/bin:/bin" SECPAL_TEST_GATE_MODE=normal \
    SECPAL_TEST_GATE_STATE="$GATE_STATE" \
    "$GATE_SCRIPT"
)"
[[ "$gate_output" == *"waiting for trusted GCP identity admission"* ]]
[[ "$(<"$GATE_STATE")" == admitted ]]

INLINE_GATE="$TEMP_DIR/inline-gate"
{
  printf '%s\n' '#!/usr/bin/env bash'
  tail -n +2 "$GATE_SCRIPT"
  printf '%s\n' "printf 'embedded bootstrap continued.\\n'"
} >"$INLINE_GATE"
chmod 0700 "$INLINE_GATE"
printf '%s\n' admitted >"$GATE_STATE"
inline_output="$(
  PATH="$FAKE_BIN:/usr/bin:/bin" SECPAL_TEST_GATE_MODE=normal \
    SECPAL_TEST_GATE_STATE="$GATE_STATE" "$INLINE_GATE"
)"
[[ "$inline_output" == *"embedded bootstrap continued."* ]]

for gate_mode in inconsistent identity-not-found transport-error; do
  printf '%s\n' "$gate_mode" >"$GATE_STATE"
  set +e
  PATH="$FAKE_BIN:/usr/bin:/bin" SECPAL_TEST_GATE_MODE="$gate_mode" \
    SECPAL_TEST_GATE_STATE="$GATE_STATE" "$GATE_SCRIPT"
  status=$?
  set -e
  [[ "$status" -ne 0 ]]
done

printf 'GCP VM identity transition contract passed.\n'
