#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

diagnostic_key=/run/secpal-ci-diagnostic-authorized-key
diagnostic_command=/run/secpal-ci-cloud-init-diagnostic
diagnostic_config=/run/secpal-ci-diagnostic-sshd.conf
diagnostic_unit=secpal-ci-diagnostic-sshd
diagnostic_user=secpal-ci-diagnostic
key_tmp=""
command_tmp=""
config_tmp=""
diagnostic_identity_created=false

cleanup() {
  [[ -z "$key_tmp" ]] || rm -f -- "$key_tmp"
  [[ -z "$command_tmp" ]] || rm -f -- "$command_tmp"
  [[ -z "$config_tmp" ]] || rm -f -- "$config_tmp"
  if [[ "$diagnostic_identity_created" == true ]]; then
    userdel "$diagnostic_user" 2>/dev/null || true
    groupdel "$diagnostic_user" 2>/dev/null || true
  fi
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

systemctl mask --now ssh.service ssh.socket
install -d -o root -g root -m 0755 /run/sshd
if getent passwd "$diagnostic_user" >/dev/null ||
  getent group "$diagnostic_user" >/dev/null; then
  printf 'ERROR: diagnostic SSH identity already exists.\n' >&2
  exit 1
fi
groupadd --system "$diagnostic_user"
useradd --system --gid "$diagnostic_user" --no-create-home \
  --home-dir /nonexistent --shell /bin/sh "$diagnostic_user"
usermod --lock "$diagnostic_user"
diagnostic_identity_created=true

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
diagnostic_identity_created=false
