#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

diagnostic_key=/run/secpal-ci-diagnostic-authorized-key
diagnostic_command=/run/secpal-ci-cloud-init-diagnostic
diagnostic_config=/run/secpal-ci-diagnostic-sshd.conf
diagnostic_unit=secpal-ci-diagnostic-sshd
diagnostic_service="${diagnostic_unit}.service"
diagnostic_user=secpal-ci-diagnostic
active_operator_root=/var/lib/secpal-ci
active_operator_key="$active_operator_root/authorized-keys/secpal-ci"
completion_marker="$active_operator_root/host-setup-complete"
key_tmp=""
command_tmp=""
config_tmp=""
diagnostic_identity_created=false
diagnostic_fallback_armed=false

cleanup() {
  local status=$?
  trap - EXIT
  set +e
  [[ -z "$key_tmp" ]] || rm -f -- "$key_tmp"
  [[ -z "$command_tmp" ]] || rm -f -- "$command_tmp"
  [[ -z "$config_tmp" ]] || rm -f -- "$config_tmp"
  if [[ "$status" -ne 0 ]]; then
    if [[ "$diagnostic_fallback_armed" == true ]]; then
      systemctl mask --now ssh.service ssh.socket >/dev/null 2>&1 || true
      systemctl start "$diagnostic_service" >/dev/null 2>&1 || true
    else
      rm -f -- "$diagnostic_key" "$diagnostic_command" "$diagnostic_config"
      if [[ "$diagnostic_identity_created" == true ]]; then
        userdel "$diagnostic_user" 2>/dev/null || true
        if getent group "$diagnostic_user" >/dev/null; then
          groupdel "$diagnostic_user" 2>/dev/null || true
        fi
      fi
    fi
  fi
  exit "$status"
}

trap cleanup EXIT

is_ipv4() {
  local value="$1" octet
  local -a octets

  IFS=. read -r -a octets <<<"$value"
  [[ "${#octets[@]}" -eq 4 ]] || return 1
  for octet in "${octets[@]}"; do
    [[ "$octet" =~ ^(0|[1-9][0-9]{0,2})$ ]] || return 1
    ((10#$octet <= 255)) || return 1
  done
}

completed_setup_is_valid() {
  local root_metadata directory_metadata key_metadata marker_metadata
  local ssh_service_state

  [[ -d "$active_operator_root" && ! -L "$active_operator_root" &&
    -d "$active_operator_root/authorized-keys" &&
    ! -L "$active_operator_root/authorized-keys" &&
    -f "$active_operator_key" && ! -L "$active_operator_key" &&
    -f "$completion_marker" && ! -L "$completion_marker" ]] || return 1
  root_metadata="$(stat -c '%u:%g:%a' -- "$active_operator_root")" || return 1
  directory_metadata="$(
    stat -c '%u:%g:%a' -- "$active_operator_root/authorized-keys"
  )" || return 1
  key_metadata="$(stat -c '%u:%g:%a' -- "$active_operator_key")" || return 1
  marker_metadata="$(stat -c '%u:%g:%a' -- "$completion_marker")" || return 1
  [[ "$root_metadata" == 0:0:755 && "$directory_metadata" == 0:0:755 &&
    "$key_metadata" == 0:0:644 && "$marker_metadata" == 0:0:400 ]] || return 1
  [[ "$(wc -l <"$completion_marker")" -eq 1 ]] || return 1
  grep -Fqx 'SECPAL_CI_HOST_SETUP_COMPLETE' "$completion_marker" || return 1
  printf '%s\n' "$ssh_public_key" |
    cmp -s -- - "$active_operator_key" || return 1
  ssh-keygen -l -E sha256 -f "$active_operator_key" >/dev/null || return 1
  sshd -t || return 1
  ssh_service_state="$(systemctl is-enabled ssh.service 2>/dev/null || true)"
  [[ "$ssh_service_state" == enabled ]] || return 1
}

if [[ "$#" -ne 4 ]] || ! is_ipv4 "$2" ||
  [[ ! "$3" =~ ^[1-9][0-9]{0,19}$ ||
    ! "$4" =~ ^[1-9][0-9]{0,2}$ ]]; then
  printf 'ERROR: diagnostic SSH context is outside the closed format.\n' >&2
  exit 1
fi

ssh_public_key="$1"
runner_ipv4="$2"
read -r key_type key_data key_comment key_extra <<<"$ssh_public_key"
if [[ "$key_type" != ssh-ed25519 ||
  ! "$key_data" =~ ^[A-Za-z0-9+/]+={0,2}$ ||
  "$key_comment" != "secpal-ci-$3-$4" || -n "${key_extra:-}" ]]; then
  printf 'ERROR: diagnostic SSH key is outside the closed format.\n' >&2
  exit 1
fi

if completed_setup_is_valid; then
  exit 0
fi
rm -f -- "$completion_marker" "$active_operator_key"

install -d -o root -g root -m 0755 /run/sshd
if getent passwd "$diagnostic_user" >/dev/null ||
  getent group "$diagnostic_user" >/dev/null; then
  printf 'ERROR: diagnostic SSH identity already exists.\n' >&2
  exit 1
fi
groupadd --system "$diagnostic_user"
diagnostic_identity_created=true
useradd --system --gid "$diagnostic_user" --no-create-home \
  --home-dir /nonexistent --shell /bin/sh "$diagnostic_user"
usermod --lock "$diagnostic_user"

key_tmp="$(mktemp /run/.secpal-ci-diagnostic-key.XXXXXX)"
command_tmp="$(mktemp /run/.secpal-ci-diagnostic-command.XXXXXX)"
config_tmp="$(mktemp /run/.secpal-ci-diagnostic-config.XXXXXX)"
chmod 0600 "$key_tmp" "$config_tmp"
chmod 0700 "$command_tmp"

printf '%s\n' "$ssh_public_key" >"$key_tmp"
ssh-keygen -l -E sha256 -f "$key_tmp" >/dev/null
printf 'restrict,command="%s" %s\n' \
  "$diagnostic_command" "$ssh_public_key" >"$key_tmp"

cat >"$command_tmp" <<'DIAGNOSTIC'
#!/usr/bin/env bash
set -uo pipefail

printf 'SECPAL_CI_DIAGNOSTIC_SSH\n'
set +e
/usr/bin/cloud-init status --long 2>&1 | /usr/bin/head -c 8192
printf '\n'
setup_failure="$(
  /usr/local/sbin/secpal-ci-host-setup-failure read 2>/dev/null
)"
setup_failure_status=$?
if [[ "$setup_failure_status" -eq 0 && -n "$setup_failure" ]]; then
  printf 'SECPAL_CI_HOST_SETUP_FAILURE %s\n' "$setup_failure"
fi
exit 125
DIAGNOSTIC

cat >"$config_tmp" <<EOF
Port 22
AddressFamily inet
ListenAddress 0.0.0.0
HostKey /etc/ssh/ssh_host_ed25519_key
PidFile /run/secpal-ci-diagnostic-sshd.pid
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
PubkeyAuthentication yes
AuthenticationMethods publickey
AuthorizedKeysCommand none
AuthorizedKeysFile $diagnostic_key
AuthorizedPrincipalsCommand none
AuthorizedPrincipalsFile none
TrustedUserCAKeys none
UseDNS no
UsePAM yes
AllowUsers secpal-ci-diagnostic@$runner_ipv4
ForceCommand /run/secpal-ci-cloud-init-diagnostic
DisableForwarding yes
PermitTTY no
PermitUserRC no
EOF

ssh-keygen -A
sshd -t -f "$config_tmp"
mv -T -- "$key_tmp" "$diagnostic_key"
key_tmp=""
mv -T -- "$command_tmp" "$diagnostic_command"
command_tmp=""
mv -T -- "$config_tmp" "$diagnostic_config"
config_tmp=""
chmod 0600 "$diagnostic_key" "$diagnostic_config"
chmod 0755 "$diagnostic_command"

if ! systemd-run --quiet \
  --unit="$diagnostic_unit" \
  --on-active=10m \
  --timer-property=AccuracySec=1s \
  --service-type=exec \
  /usr/sbin/sshd -D -e -f "$diagnostic_config"; then
  rm -f -- "$diagnostic_key" "$diagnostic_command" "$diagnostic_config"
  exit 1
fi
diagnostic_fallback_armed=true
if ! systemctl mask --now ssh.service ssh.socket; then
  printf 'ERROR: unable to mask primary SSH after arming diagnostics.\n' >&2
  exit 1
fi
if systemctl is-active --quiet ssh.service ||
  systemctl is-active --quiet ssh.socket ||
  ! systemctl is-active --quiet "${diagnostic_unit}.timer"; then
  printf 'ERROR: SSH fallback transition did not reach its closed state.\n' >&2
  exit 1
fi
diagnostic_identity_created=false
