<?php
// SPDX-FileCopyrightText: 2026 SecPal Contributors
// SPDX-License-Identifier: MIT

declare(strict_types=1);

/**
 * Load production application secrets into PHP's in-process configuration.
 *
 * Values are deliberately not published through the OS environment, command
 * arguments, logs, or generated configuration. The root path is a non-secret deployment
 * constant; production sets it to /run/secpal/secrets/api.
 */

$secretRoot = $_SERVER['SECPAL_SECRET_ROOT'] ?? '/run/secpal/secrets/api';

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

$readFile = static function (string $name, int $mode) use (
    $secretRoot,
    $fail,
    $expectedUid,
    $expectedGid,
): string {
    $path = $secretRoot.'/'.$name;
    $metadata = @lstat($path);
    if ($metadata === false || ($metadata['mode'] & 0170000) !== 0100000
        || ($metadata['mode'] & 0777) !== $mode
        || $metadata['nlink'] !== 1
        || $metadata['uid'] !== $expectedUid
        || $metadata['gid'] !== $expectedGid) {
        $fail();
    }
    $value = @file_get_contents($path);
    if ($value === false || strlen($value) > 4096) {
        $fail();
    }
    return $value;
};

$appKey = rtrim($readFile('app-key', 0400), "\n");
$previous = $readFile('app-previous-keys', 0400);
$databasePassword = rtrim($readFile('postgres-password', 0400), "\n");
$valkeyPassword = rtrim($readFile('valkey-password', 0400), "\n");
$kekPath = $secretRoot.'/tenant-kek';
$kekMetadata = @lstat($kekPath);

$keyPattern = '/\Abase64:[A-Za-z0-9+\/]{43}=\z/D';
$previousKeys = $previous === '' ? [] : preg_split('/\n/', rtrim($previous, "\n"));
if (!preg_match($keyPattern, $appKey)
    || !is_array($previousKeys)
    || count($previousKeys) > 3
    || count(array_unique($previousKeys)) !== count($previousKeys)
    || array_filter($previousKeys, static fn (string $key): bool => !preg_match($keyPattern, $key)) !== []
    || !preg_match('/\A[A-Za-z0-9._~!#$%&*+\-\/=?^]{24,128}\z/D', $databasePassword)
    || !preg_match('/\A[A-Za-z0-9._~!#$%&*+\-\/=?^]{24,128}\z/D', $valkeyPassword)
    || $kekMetadata === false
    || ($kekMetadata['mode'] & 0170000) !== 0100000
    || ($kekMetadata['mode'] & 0777) !== 0600
    || $kekMetadata['nlink'] !== 1
    || $kekMetadata['uid'] !== $expectedUid
    || $kekMetadata['gid'] !== $expectedGid
    || $kekMetadata['size'] !== 32) {
    $fail();
}

$values = [
    'APP_KEY' => $appKey,
    'APP_PREVIOUS_KEYS' => implode(',', $previousKeys),
    'DB_PASSWORD' => $databasePassword,
    'KEK_PATH' => $kekPath,
    'REDIS_PASSWORD' => $valkeyPassword,
];
foreach ($values as $name => $value) {
    $_ENV[$name] = $value;
    $_SERVER[$name] = $value;
}

unset($appKey, $previous, $previousKeys, $databasePassword, $valkeyPassword, $values);
