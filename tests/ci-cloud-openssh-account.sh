#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

readonly TEST_USER=secpal-ci-smoke
readonly TEST_UID=20000
readonly TEST_GID=20000
readonly ISOLATED_ROOT=/run/secpal-ci-openssh-smoke
server_pid=""

write_shadow() {
  local directory="$1" password_marker="$2"

  {
    printf 'root:*NP*:20000:0:99999:7:::\n'
    printf 'sshd:*:20000:0:99999:7:::\n'
    printf '%s:%s:20000:0:99999:7:::\n' "$TEST_USER" "$password_marker"
  } >"$directory/shadow"
  chmod 0600 "$directory/shadow"
}

ssh_probe() {
  local directory="$1" port="$2"

  ssh -F /dev/null \
    -o GlobalKnownHostsFile=/dev/null \
    -i "$directory/client-key" \
    -o BatchMode=yes \
    -o IdentitiesOnly=yes \
    -o KbdInteractiveAuthentication=no \
    -o PasswordAuthentication=no \
    -o PreferredAuthentications=publickey \
    -o StrictHostKeyChecking=yes \
    -o "UserKnownHostsFile=$directory/known-hosts" \
    -o ConnectTimeout=3 \
    -p "$port" \
    "$TEST_USER@127.0.0.1" true
}

run_isolated_smoke() {
  local directory="$1" port="$2"
  local attempt status

  # shellcheck disable=SC2317,SC2329 # Invoked indirectly by the EXIT trap.
  cleanup_server() {
    local cleanup_status=$?
    trap - EXIT
    set +e
    [[ -z "$server_pid" ]] || kill "$server_pid" 2>/dev/null
    [[ -z "$server_pid" ]] || wait "$server_pid" 2>/dev/null
    exit "$cleanup_status"
  }
  trap cleanup_server EXIT

  mount --make-rprivate /
  mount -t tmpfs -o mode=0755 tmpfs /run
  install -d -o root -g root -m 0755 /run/sshd "$ISOLATED_ROOT"
  mount --bind "$directory" "$ISOLATED_ROOT"
  mount --bind "$directory/passwd" /etc/passwd
  mount --bind "$directory/group" /etc/group
  mount --bind "$directory/shadow" /etc/shadow

  /usr/sbin/sshd -t -f "$directory/sshd-config"
  /usr/sbin/sshd -D -e -f "$directory/sshd-config" \
    >"$directory/sshd.log" 2>&1 &
  server_pid=$!

  for ((attempt = 0; attempt < 30; attempt++)); do
    if ssh_probe "$directory" "$port" >/dev/null 2>&1; then
      break
    fi
    sleep 0.1
  done
  if ((attempt == 30)); then
    printf 'ERROR: *NP* account did not admit its public key.\n' >&2
    sed -n '1,80p' "$directory/sshd.log" >&2
    exit 1
  fi

  write_shadow "$directory" '!'
  set +e
  ssh_probe "$directory" "$port" >/dev/null 2>&1
  status=$?
  set -e
  if [[ "$status" -ne 255 ]]; then
    printf 'ERROR: OpenSSH admitted a leading-! locked account.\n' >&2
    exit 1
  fi

  write_shadow "$directory" '*NP*'
  if ! ssh_probe "$directory" "$port" >/dev/null 2>&1; then
    printf 'ERROR: restoring *NP* did not restore public-key admission.\n' >&2
    sed -n '1,80p' "$directory/sshd.log" >&2
    exit 1
  fi

  kill "$server_pid"
  wait "$server_pid" || true
  server_pid=""
  sed 's/^UsePAM no$/UsePAM yes/' "$directory/sshd-config" \
    >"$directory/sshd-config.pam"
  chmod 0600 "$directory/sshd-config.pam"
  /usr/sbin/sshd -t -f "$directory/sshd-config.pam"
  /usr/sbin/sshd -D -e -f "$directory/sshd-config.pam" \
    >"$directory/sshd-pam.log" 2>&1 &
  server_pid=$!
  for ((attempt = 0; attempt < 30; attempt++)); do
    if ssh_probe "$directory" "$port" >/dev/null 2>&1; then
      break
    fi
    sleep 0.1
  done
  if ((attempt == 30)); then
    printf 'ERROR: *NP* account failed production-like PAM public-key admission.\n' >&2
    sed -n '1,80p' "$directory/sshd-pam.log" >&2
    exit 1
  fi

  printf 'OpenSSH public-key account accessibility smoke passed.\n'
}

if [[ "${1:-}" == --isolated ]]; then
  [[ "$#" -eq 3 && "$2" == /* && "$3" =~ ^[1-9][0-9]{3,4}$ ]] || {
    printf 'ERROR: invalid isolated OpenSSH smoke context.\n' >&2
    exit 1
  }
  run_isolated_smoke "$2" "$3"
  exit 0
fi

[[ "$#" -eq 0 ]] || {
  printf 'ERROR: this test accepts no arguments.\n' >&2
  exit 1
}
for command in getent mount python3 ssh ssh-keygen unshare; do
  command -v "$command" >/dev/null || {
    printf 'ERROR: required OpenSSH smoke tool is missing: %s\n' "$command" >&2
    exit 1
  }
done
[[ -x /usr/sbin/sshd ]] || {
  printf 'ERROR: /usr/sbin/sshd is required for the OpenSSH smoke.\n' >&2
  exit 1
}

ROOT_DIR="$(git rev-parse --show-toplevel)"
TEMP_DIR="$(mktemp -d)"
cleanup_temp() {
  local status=$?
  trap - EXIT
  rm -rf -- "$TEMP_DIR"
  exit "$status"
}
trap cleanup_temp EXIT

# The production AuthorizedKeysFile path is root-owned but searchable by the
# target account (0755 parents, 0644 public key). Private keys below remain
# root-only mode 0600.
chmod 0755 "$TEMP_DIR"
install -d -m 0755 "$TEMP_DIR/home"
printf 'root:x:0:0:root:%s/home:/bin/sh\n' "$ISOLATED_ROOT" \
  >"$TEMP_DIR/passwd"
printf 'sshd:x:989:65534:sshd user:/run/sshd:/usr/sbin/nologin\n' \
  >>"$TEMP_DIR/passwd"
printf '%s:x:%s:%s:OpenSSH smoke:%s:/bin/sh\n' \
  "$TEST_USER" "$TEST_UID" "$TEST_GID" "$ISOLATED_ROOT/home" \
  >>"$TEMP_DIR/passwd"
printf 'root:x:0:\nnogroup:x:65534:\n%s:x:%s:\n' \
  "$TEST_USER" "$TEST_GID" >"$TEMP_DIR/group"
chmod 0644 "$TEMP_DIR/passwd" "$TEMP_DIR/group"
write_shadow "$TEMP_DIR" '*NP*'

ssh-keygen -q -t ed25519 -N '' -C account-smoke-client \
  -f "$TEMP_DIR/client-key"
ssh-keygen -q -t ed25519 -N '' -C account-smoke-host \
  -f "$TEMP_DIR/host-key"
chmod 0600 "$TEMP_DIR/client-key" "$TEMP_DIR/host-key"
install -m 0644 "$TEMP_DIR/client-key.pub" "$TEMP_DIR/authorized-keys"

PORT="$(python3 - <<'PY'
import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
    listener.bind(("127.0.0.1", 0))
    print(listener.getsockname()[1])
PY
)"
read -r host_key_type host_key_data _ <"$TEMP_DIR/host-key.pub"
printf '[127.0.0.1]:%s %s %s\n' \
  "$PORT" "$host_key_type" "$host_key_data" >"$TEMP_DIR/known-hosts"

cat >"$TEMP_DIR/sshd-config" <<EOF
Port $PORT
AddressFamily inet
ListenAddress 127.0.0.1
HostKey $TEMP_DIR/host-key
PidFile $TEMP_DIR/sshd.pid
AuthorizedKeysFile $ISOLATED_ROOT/authorized-keys
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PubkeyAcceptedAlgorithms ssh-ed25519
PermitRootLogin no
AllowUsers $TEST_USER@127.0.0.1
DisableForwarding yes
PermitTTY no
PermitUserEnvironment no
PermitUserRC no
# The user namespace reports the host root filesystem as unmapped ownership.
# Production StrictModes/path metadata are covered separately; this smoke
# isolates OpenSSH's account-accessibility decision.
StrictModes no
UseDNS no
UsePAM no
LogLevel VERBOSE
EOF
chmod 0600 "$TEMP_DIR/sshd-config"

if [[ "$EUID" -eq 0 ]]; then
  unshare --mount --pid --fork --kill-child \
    "$ROOT_DIR/tests/ci-cloud-openssh-account.sh" \
    --isolated "$TEMP_DIR" "$PORT"
  exit 0
fi

current_user="$(id -un)"
current_uid="$(id -u)"
current_gid="$(id -g)"
subuid_entry="$(
  awk -F: -v user="$current_user" '$1 == user && $3 >= 65536 {
    print $2 ":" $3
    exit
  }' /etc/subuid
)"
subgid_entry="$(
  awk -F: -v user="$current_user" '$1 == user && $3 >= 65536 {
    print $2 ":" $3
    exit
  }' /etc/subgid
)"
[[ -n "$subuid_entry" && -n "$subgid_entry" ]] || {
  printf 'ERROR: a 65536-ID subordinate range is required for the isolated OpenSSH smoke.\n' >&2
  exit 1
}
subuid_start="${subuid_entry%%:*}"
subgid_start="${subgid_entry%%:*}"

unshare --user --mount --pid --fork --kill-child \
  --map-users "0:$current_uid:1" \
  --map-users "1:$subuid_start:65536" \
  --map-groups "0:$current_gid:1" \
  --map-groups "1:$subgid_start:65536" \
  "$ROOT_DIR/tests/ci-cloud-openssh-account.sh" \
  --isolated "$TEMP_DIR" "$PORT"
