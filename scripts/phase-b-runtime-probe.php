<?php

// SPDX-FileCopyrightText: 2026 SecPal Contributors
// SPDX-License-Identifier: MIT

declare(strict_types=1);

require '/app/vendor/autoload.php';

$application = require '/app/bootstrap/app.php';
$application->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();

$operation = $argv[1] ?? '';
$key = $argv[2] ?? '';

if (! preg_match('/\Aintegration-(?:cache|queue-(?:general|hash-chain))-[a-z0-9]+\z/', $key)) {
    fwrite(STDERR, "Invalid integration probe key.\n");
    exit(64);
}

switch ($operation) {
    case 'transport':
        $pdo = $application->make('db')->connection()->getPdo();
        $tls = $pdo->query("SELECT CASE WHEN ssl THEN 'tls' ELSE 'plain' END FROM pg_stat_ssl WHERE pid = pg_backend_pid()")->fetchColumn();
        // Disposable fixture authority only: inspect rules and password kind,
        // never retrieve a password hash or infer authentication from a default.
        $rules = $pdo->query("SELECT type || ':' || auth_method FROM pg_hba_file_rules WHERE type LIKE 'host%' ORDER BY rule_number")->fetchAll(PDO::FETCH_COLUMN);
        $scram = $pdo->query("SELECT CASE WHEN rolpassword LIKE 'SCRAM-SHA-256$%' THEN 'scram' ELSE 'other' END FROM pg_authid WHERE rolname = current_user")->fetchColumn();
        if ($tls !== 'tls' || $scram !== 'scram' || $rules !== ['hostssl:scram-sha-256', 'hostssl:scram-sha-256', 'host:reject', 'host:reject']) {
            exit(78);
        }
        try {
            new PDO(
                'pgsql:host=db.secpal.internal;dbname=secpal;sslmode=disable',
                config('database.connections.pgsql.username'),
                config('database.connections.pgsql.password'),
            );
        } catch (PDOException) {
            break;
        }
        fwrite(STDERR, "Plain PostgreSQL transport was unexpectedly accepted.\n");
        exit(78);

    case 'cache-put':
        $value = $argv[3] ?? '';
        if (! preg_match('/\Aintegration-cache-value-[a-z0-9]+\z/', $value)) {
            fwrite(STDERR, "Invalid integration cache probe value.\n");
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
            fwrite(STDERR, "Invalid integration probe queue.\n");
            exit(64);
        }
        dispatch(static function () use ($key): void {
            cache()->put($key, gethostname(), 60);
        })->onConnection('database')->onQueue($queue);
        break;

    default:
        fwrite(STDERR, "Invalid integration probe operation.\n");
        exit(64);
}
