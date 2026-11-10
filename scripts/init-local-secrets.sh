#!/bin/sh
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -eu

SECRET_DIR="${SECPAL_SECRET_DIR:-/run/secpal-secrets}"
POSTGRES_DATA_DIR="${SECPAL_POSTGRES_DATA_DIR:-}"
PRIVATE_STORAGE_DIR="${SECPAL_PRIVATE_STORAGE_DIR:-/app/storage/app/private}"
API_UID="${SECPAL_API_UID:-10001}"
API_GID="${SECPAL_API_GID:-10001}"
POSTGRES_UID="${SECPAL_POSTGRES_UID:-999}"
TEMP_DIR=""
INITIALIZATION_ACTIVE=0

fail() {
  printf 'ERROR: unable to initialize the local ephemeral secret contract.\n' >&2
  exit 1
}

require_metadata() {
  metadata_path="$1"
  metadata_expected_owner="$2"
  metadata_expected_group="$3"
  metadata_expected_mode="$4"

  if [ -L "$metadata_path" ] || [ ! -f "$metadata_path" ] ||
    [ "$(stat -c '%u' "$metadata_path")" != "$metadata_expected_owner" ] ||
    [ "$(stat -c '%g' "$metadata_path")" != "$metadata_expected_group" ] ||
    [ "$(stat -c '%a' "$metadata_path")" != "$metadata_expected_mode" ]; then
    fail
  fi
}

prepare_fpm_delivery() {
  SECPAL_DELIVERY_SOURCE="${1:-}" php <<'PHP'
<?php
// Disposable fixture delivery uses the unchanged production PHP bootstrap.
$root = getenv('SECPAL_SECRET_DIR') ?: '/run/secpal-secrets';
$source = getenv('SECPAL_DELIVERY_SOURCE');
$uid = (int) (getenv('SECPAL_API_UID') ?: 10001);
$gid = (int) (getenv('SECPAL_API_GID') ?: 10001);
$postgres = (int) (getenv('SECPAL_POSTGRES_UID') ?: 999);
$files = ['api/app-key' => [$uid, $gid, 0400], 'api/app-previous-keys' => [$uid, $gid, 0400],
    'api/tenant-kek' => [$uid, $gid, 0600], 'database/postgres-username' => [$uid, $gid, 0400],
    'database/postgres-password' => [$uid, $gid, 0400], 'database/postgres-ca.crt' => [$uid, $gid, 0400],
    'postgresql/pg_hba.conf' => [$postgres, $postgres, 0400], 'postgresql/server.crt' => [$postgres, $postgres, 0644], 'postgresql/server.key' => [$postgres, $postgres, 0400]];
$fail = static function (): never { fwrite(STDERR, "Invalid fixture PHP/TLS delivery.\n"); exit(78); };
if ($source !== '') {
    foreach (['api', 'database', 'postgresql'] as $name) {
        if (file_exists("$root/$name") || is_link("$root/$name") || !mkdir("$root/$name", 0710)) $fail();
        if (!chgrp("$root/$name", $name === 'postgresql' ? $postgres : $gid) || !chmod("$root/$name", 0710)) $fail();
    }
    $config = "$source/openssl.cnf";
    file_put_contents($config, "[req]\ndistinguished_name=dn\n[dn]\n[v3]\nbasicConstraints=critical,CA:TRUE\nsubjectAltName=DNS:db.secpal.internal,DNS:postgres\nkeyUsage=critical,digitalSignature,keyEncipherment,keyCertSign\nextendedKeyUsage=serverAuth\n");
    $key = openssl_pkey_new(['config' => $config, 'private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    $csr = $key ? openssl_csr_new(['commonName' => 'db.secpal.internal'], $key, ['config' => $config, 'digest_alg' => 'sha256']) : false;
    $cert = $csr ? openssl_csr_sign($csr, null, $key, 2, ['config' => $config, 'x509_extensions' => 'v3', 'digest_alg' => 'sha256']) : false;
    if (!$cert || !openssl_x509_export($cert, $pem) || !openssl_pkey_export($key, $private, null, ['config' => $config])) $fail();
    if (!unlink($config)) $fail();
    $values = ['api/app-key' => file_get_contents("$source/app-key"), 'api/app-previous-keys' => '',
        'api/tenant-kek' => file_get_contents("$source/tenant-kek"), 'database/postgres-username' => "secpal_local\n",
        'database/postgres-password' => file_get_contents("$source/postgres-password"), 'database/postgres-ca.crt' => $pem,
        'postgresql/pg_hba.conf' => "local all all trust\nhostssl all all 0.0.0.0/0 scram-sha-256\nhostssl all all ::/0 scram-sha-256\nhost all all 0.0.0.0/0 reject\nhost all all ::/0 reject\n",
        'postgresql/server.crt' => $pem, 'postgresql/server.key' => $private];
    foreach ($values as $name => $value) {
        $stream = fopen("$root/$name", 'x');
        if (!$stream || $value === false || fwrite($stream, $value) !== strlen($value)) $fail();
        fclose($stream);
        [$owner, $group, $mode] = $files[$name];
        if (!chown("$root/$name", $owner) || !chgrp("$root/$name", $group) || !chmod("$root/$name", $mode)) $fail();
    }
}
foreach ($files as $name => [$owner, $group, $mode]) {
    $stat = lstat("$root/$name");
    if (!$stat || ($stat['mode'] & 0170000) !== 0100000 || ($stat['mode'] & 0777) !== $mode
        || $stat['uid'] !== $owner || $stat['gid'] !== $group || $stat['nlink'] !== 1) $fail();
}
PHP
}

cleanup() {

  if [ "$INITIALIZATION_ACTIVE" -eq 1 ]; then
    for name in api database postgresql; do
      if [ -d "$SECRET_DIR/$name" ] && [ ! -L "$SECRET_DIR/$name" ]; then
        rm -rf -- "$SECRET_DIR/$name" || true
      fi
    done
    for name in app-key postgres-password tenant-kek; do
      if [ -f "$SECRET_DIR/$name" ] || [ -L "$SECRET_DIR/$name" ]; then
        rm -f -- "$SECRET_DIR/$name" || true
      fi
    done
  fi
  if [ -n "$TEMP_DIR" ] && [ -d "$TEMP_DIR" ]; then
    rm -rf -- "$TEMP_DIR" || true
  fi
}

handle_signal() {
  status="$1"
  trap - EXIT HUP INT TERM
  cleanup
  exit "$status"
}

trap cleanup EXIT
trap 'handle_signal 129' HUP
trap 'handle_signal 130' INT
trap 'handle_signal 143' TERM

if [ "$(id -u)" -ne 0 ]; then
  fail
fi

case "$SECRET_DIR" in
  /*) ;;
  *) fail ;;
esac

case "$PRIVATE_STORAGE_DIR" in
  /*) ;;
  *) fail ;;
esac

case "$POSTGRES_DATA_DIR" in
  /*) ;;
  *) fail ;;
esac

if [ -L "$PRIVATE_STORAGE_DIR" ] ||
  { [ -e "$PRIVATE_STORAGE_DIR" ] && [ ! -d "$PRIVATE_STORAGE_DIR" ]; }; then
  fail
fi

install -d -m 0711 "$SECRET_DIR"
install -d -m 0700 -o "$POSTGRES_UID" -g "$POSTGRES_UID" "$POSTGRES_DATA_DIR"
install -d -m 0750 -o "$API_UID" -g "$API_GID" "$PRIVATE_STORAGE_DIR"

if [ -L "$PRIVATE_STORAGE_DIR" ] || [ ! -d "$PRIVATE_STORAGE_DIR" ] ||
  [ "$(stat -c '%u' "$PRIVATE_STORAGE_DIR")" != "$API_UID" ] ||
  [ "$(stat -c '%g' "$PRIVATE_STORAGE_DIR")" != "$API_GID" ] ||
  [ "$(stat -c '%a' "$PRIVATE_STORAGE_DIR")" != 750 ]; then
  fail
fi

present=0
for name in app-key postgres-password tenant-kek; do
  if [ -e "$SECRET_DIR/$name" ] || [ -L "$SECRET_DIR/$name" ]; then
    present=$((present + 1))
  fi
done

if [ "$present" -ne 0 ] && [ "$present" -ne 3 ]; then
  for name in app-key postgres-password tenant-kek; do
    if [ -f "$SECRET_DIR/$name" ] || [ -L "$SECRET_DIR/$name" ]; then
      rm -f -- "$SECRET_DIR/$name"
    elif [ -e "$SECRET_DIR/$name" ]; then
      fail
    fi
  done
  present=0
fi

if [ "$present" -eq 3 ]; then
  require_metadata "$SECRET_DIR/app-key" "$API_UID" "$API_GID" 400
  require_metadata "$SECRET_DIR/postgres-password" "$POSTGRES_UID" "$API_GID" 440
  require_metadata "$SECRET_DIR/tenant-kek" "$API_UID" "$API_GID" 400

  if [ "$(stat -c '%s' "$SECRET_DIR/app-key")" -ne 52 ] ||
    [ "$(stat -c '%s' "$SECRET_DIR/postgres-password")" -ne 65 ] ||
    [ "$(stat -c '%s' "$SECRET_DIR/tenant-kek")" -ne 32 ]; then
    fail
  fi
  prepare_fpm_delivery
  exit 0
fi

INITIALIZATION_ACTIVE=1
TEMP_DIR="$(mktemp -d "$SECRET_DIR/.init.XXXXXX")"
chmod 0700 "$TEMP_DIR"

php -r 'fwrite(STDOUT, "base64:".base64_encode(random_bytes(32)).PHP_EOL);' >"$TEMP_DIR/app-key"
php -r 'fwrite(STDOUT, bin2hex(random_bytes(32)).PHP_EOL);' >"$TEMP_DIR/postgres-password"
php -r 'fwrite(STDOUT, random_bytes(32));' >"$TEMP_DIR/tenant-kek"

prepare_fpm_delivery "$TEMP_DIR"

chown "$API_UID:$API_GID" "$TEMP_DIR/app-key" "$TEMP_DIR/tenant-kek"
chmod 0400 "$TEMP_DIR/app-key" "$TEMP_DIR/tenant-kek"
chown "$POSTGRES_UID:$API_GID" "$TEMP_DIR/postgres-password"
chmod 0440 "$TEMP_DIR/postgres-password"

for name in app-key postgres-password tenant-kek; do
  mv -- "$TEMP_DIR/$name" "$SECRET_DIR/$name"
done

rmdir "$TEMP_DIR"
TEMP_DIR=""
INITIALIZATION_ACTIVE=0

printf 'Local ephemeral runtime secrets initialized without revealing values.\n'
