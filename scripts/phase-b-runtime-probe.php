<?php

// SPDX-FileCopyrightText: 2026 SecPal Contributors
// SPDX-License-Identifier: MIT

declare(strict_types=1);

require '/app/vendor/autoload.php';

$application = require '/app/bootstrap/app.php';
$application->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();

$operation = $argv[1] ?? '';
$key = $argv[2] ?? '';

if (! preg_match('/\Aphase-b-(?:cache|queue-(?:general|hash-chain))-[a-z0-9]+\z/', $key)) {
    fwrite(STDERR, "Invalid Phase B probe key.\n");
    exit(64);
}

switch ($operation) {
    case 'cache-put':
        $value = $argv[3] ?? '';
        if (! preg_match('/\Aphase-b-cache-value-[a-z0-9]+\z/', $value)) {
            fwrite(STDERR, "Invalid Phase B cache probe value.\n");
            exit(64);
        }
        cache()->put($key, $value, 60);
        break;

    case 'cache-get':
        echo (string) cache()->get($key, '');
        break;

    case 'cache-forget':
        cache()->forget($key);
        break;

    case 'queue-dispatch':
        $queue = $argv[3] ?? '';
        if (! in_array($queue, ['default', 'activity-hash-chain'], true)) {
            fwrite(STDERR, "Invalid Phase B probe queue.\n");
            exit(64);
        }
        dispatch(static function () use ($key): void {
            cache()->put($key, gethostname(), 60);
        })->onConnection('redis')->onQueue($queue);
        break;

    default:
        fwrite(STDERR, "Invalid Phase B probe operation.\n");
        exit(64);
}
