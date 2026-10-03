<?php
// SPDX-FileCopyrightText: 2026 SecPal Contributors
// SPDX-License-Identifier: MIT

declare(strict_types=1);

/**
 * Load production application secrets into PHP's in-process configuration.
 *
 * Values are deliberately not published through the OS environment, command
 * arguments, logs, or generated configuration. Production always uses the
 * canonical application and separately mounted database delivery roots.
 */

$secretRoot = '/run/secpal/secrets/api';
$databaseRoot = '/run/secpal/secrets/database';
if (defined('SECPAL_TEST_SECRET_ROOT')) {
    $testRoot = constant('SECPAL_TEST_SECRET_ROOT');
    if (!is_string($testRoot)) {
        fwrite(STDERR, "ERROR: production application secret contract is invalid.\n");
        exit(78);
    }
    $secretRoot = $testRoot;
    $databaseRoot = $testRoot.'/database';
}

$fail = static function (): never {
    fwrite(STDERR, "ERROR: production application secret contract is invalid.\n");
    exit(78);
};

if (!is_string($secretRoot) || $secretRoot === '' || $secretRoot[0] !== '/') {
    $fail();
}
if (!function_exists('posix_geteuid') || !function_exists('posix_getegid')) {
    $fail();
}
$expectedUid = posix_geteuid();
$expectedGid = posix_getegid();

$readFile = static function (string $root, string $name, int $mode) use (
    $fail,
    $expectedUid,
    $expectedGid,
): string {
    $path = $root.'/'.$name;
    $metadata = @lstat($path);
    if ($metadata === false || ($metadata['mode'] & 0170000) !== 0100000
        || ($metadata['mode'] & 0777) !== $mode
        || $metadata['nlink'] !== 1
        || $metadata['uid'] !== $expectedUid
        || $metadata['gid'] !== $expectedGid
        || $metadata['size'] > 4096) {
        $fail();
    }
    $value = @file_get_contents($path, false, null, 0, 4097);
    if ($value === false || strlen($value) > 4096) {
        $fail();
    }
    return $value;
};

$stripOptionalFinalLf = static function (string $value) use ($fail): string {
    if (str_contains($value, "\r")) {
        $fail();
    }
    if (str_ends_with($value, "\n")) {
        $value = substr($value, 0, -1);
    }
    if (str_contains($value, "\n")) {
        $fail();
    }
    return $value;
};

$appKey = $stripOptionalFinalLf($readFile($secretRoot, 'app-key', 0400));
$previous = $readFile($secretRoot, 'app-previous-keys', 0400);
$databasePassword = $stripOptionalFinalLf($readFile($databaseRoot, 'postgres-password', 0400));
$databaseUsername = $stripOptionalFinalLf($readFile($databaseRoot, 'postgres-username', 0400));
$databaseCa = $readFile($databaseRoot, 'postgres-ca.crt', 0400);
$kekPath = $secretRoot.'/tenant-kek';
$kekMetadata = @lstat($kekPath);

$reservedDatabaseNames = ['postgres' => true, 'secpal_owner' => true, 'secpal_runtime' => true, 'secpal_migration' => true, 'secpal_backup' => true, 'secpal_replication' => true];
$keyPattern = '/\Abase64:[A-Za-z0-9+\/]{43}=\z/D';
$previousBody = str_ends_with($previous, "\n") ? substr($previous, 0, -1) : $previous;
$previousKeys = $previousBody === '' ? [] : explode("\n", $previousBody);
if (!preg_match($keyPattern, $appKey)
    || str_contains($previous, "\r")
    || !is_array($previousKeys)
    || count($previousKeys) > 3
    || count(array_unique($previousKeys)) !== count($previousKeys)
    || array_filter($previousKeys, static fn (string $key): bool => !preg_match($keyPattern, $key)) !== []
    || !preg_match('/\A[A-Za-z0-9._~!#$%&*+\-\/=?^]{24,128}\z/D', $databasePassword)
    || !preg_match('/\A[a-z][a-z0-9_]{0,62}\z/D', $databaseUsername)
    || isset($reservedDatabaseNames[$databaseUsername])
    || !str_starts_with($databaseCa, "-----BEGIN CERTIFICATE-----\n")
    || $kekMetadata === false
    || ($kekMetadata['mode'] & 0170000) !== 0100000
    || ($kekMetadata['mode'] & 0777) !== 0600
    || $kekMetadata['nlink'] !== 1
    || $kekMetadata['uid'] !== $expectedUid
    || $kekMetadata['gid'] !== $expectedGid
    || $kekMetadata['size'] !== 32) {
    $fail();
}

foreach (array_keys(getenv()) as $name) {
    if (str_starts_with($name, 'PG') || in_array($name, ['DB_URL', 'DATABASE_URL', 'SECPAL_TEST_DATABASE', 'SECPAL_TEST_SCHEMA'], true)) {
        putenv($name);
        unset($_ENV[$name], $_SERVER[$name]);
    }
}
foreach (array_unique(array_merge(array_keys($_ENV), array_keys($_SERVER))) as $name) {
    if (str_starts_with((string) $name, 'PG') || in_array($name, ['DB_URL', 'DATABASE_URL', 'SECPAL_TEST_DATABASE', 'SECPAL_TEST_SCHEMA'], true)) {
        unset($_ENV[$name], $_SERVER[$name]);
    }
}
$values = [
    'APP_KEY' => $appKey,
    'APP_PREVIOUS_KEYS' => implode(',', $previousKeys),
    'DB_PASSWORD' => $databasePassword,
    'KEK_PATH' => $kekPath,
    'DB_USERNAME' => $databaseUsername,
    'DB_SSLMODE' => 'verify-full',
    'DB_SSLROOTCERT' => $databaseRoot.'/postgres-ca.crt',
    'DB_HOST' => 'db.secpal.internal',
    'DB_PORT' => '5432',
    'DB_DATABASE' => 'secpal',
    'DB_CONNECTION' => 'pgsql',
    'CACHE_STORE' => 'database',
    'QUEUE_CONNECTION' => 'database',
    'SESSION_DRIVER' => 'database',
];
foreach ($values as $name => $value) {
    $_ENV[$name] = $value;
    $_SERVER[$name] = $value;
}

unset($appKey, $previous, $previousKeys, $databasePassword, $databaseUsername, $databaseCa, $previousBody, $values);
