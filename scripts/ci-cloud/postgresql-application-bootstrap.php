<?php
// SPDX-FileCopyrightText: 2026 SecPal Contributors
// SPDX-License-Identifier: MIT

declare(strict_types=1);

// Accepted-main qualification input only. No candidate code/configuration is
// loaded; synthetic secrets remain PHP process-local and never enter argv/env.
$path = '/run/secpal-pg/application/credentials.json';
$metadata = @lstat($path);
if ($metadata === false || ($metadata['mode'] & 0170000) !== 0100000
    || ($metadata['mode'] & 0777) !== 0600 || $metadata['uid'] !== posix_geteuid()
    || $metadata['gid'] !== posix_getegid() || $metadata['nlink'] !== 1
    || $metadata['size'] > 4096) {
    exit(78);
}
$values = json_decode((string) file_get_contents($path), true, 16, JSON_THROW_ON_ERROR);
if (!is_array($values) || array_keys($values) !== ['APP_KEY', 'DB_PASSWORD']
    || !is_string($values['APP_KEY']) || !preg_match('/\Abase64:[A-Za-z0-9+\/]{43}=\z/D', $values['APP_KEY'])
    || !is_string($values['DB_PASSWORD']) || !preg_match('/\A[0-9a-f]{64}\z/D', $values['DB_PASSWORD'])) {
    exit(78);
}
foreach ($values as $name => $value) {
    $_ENV[$name] = $value;
    $_SERVER[$name] = $value;
}
unset($values, $name, $value);

// libpq defaults, service files and URI/test overrides never select transport.
// Only the fixed trusted application DB_* inputs and its actual config apply.
foreach (array_keys(getenv()) as $name) {
    if (str_starts_with($name, 'PG') || in_array($name, ['DB_URL', 'SECPAL_TEST_DATABASE', 'SECPAL_TEST_SCHEMA'], true)) {
        putenv($name);
        unset($_ENV[$name], $_SERVER[$name]);
    }
}
putenv('PGCONNECT_TIMEOUT=3');
