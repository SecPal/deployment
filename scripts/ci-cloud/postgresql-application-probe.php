<?php
// SPDX-FileCopyrightText: 2026 SecPal Contributors
// SPDX-License-Identifier: MIT

declare(strict_types=1);

// The controller selects one fixed operation. This file is accepted-main probe
// construction, never an arbitrary PHP interpreter or candidate PASS script.
$operation = $argv[1] ?? '';
if (!in_array($operation, ['pdo', 'initialize', 'seed', 'ready', 'live'], true) || count($argv) !== 2) {
    exit(78);
}

if ($operation === 'ready' || $operation === 'live') {
    $context = stream_context_create(['http' => ['ignore_errors' => true, 'timeout' => 8]]);
    $body = @file_get_contents('http://127.0.0.1:8080/health/'.$operation, false, $context);
    $header = $http_response_header[0] ?? '';
    if ($body === false || strlen($body) > 4096 || !preg_match('/\AHTTP\/1\.[01] (200|503) /D', $header, $match)) {
        exit(1);
    }
    $document = json_decode($body, true, 8, JSON_THROW_ON_ERROR);
    if (!is_array($document) || array_keys($document) !== ['status', 'timestamp']
        || !in_array($document['status'], ['ready', 'not_ready', 'alive'], true)
        || !is_string($document['timestamp']) || strlen($document['timestamp']) > 64) {
        exit(1);
    }
    echo json_encode(['http_status' => (int) $match[1], 'body_status' => $document['status']], JSON_THROW_ON_ERROR);
    exit(0);
}

// Preserve the application's actual production/artisan trust-input guard.
$_SERVER['argv'] = ['/app/artisan', 'secpal-qualification'];
require '/app/vendor/autoload.php';
$application = require '/app/bootstrap/app.php';
try {
    $application->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
} catch (RuntimeException $error) {
    if ($operation !== 'pdo' || $error->getMessage() !== 'Production PostgreSQL requires DB_SSLMODE=verify-full.') {
        exit(1);
    }
    echo json_encode(['connected' => false, 'stage' => 'configuration', 'reason' => 'tls-policy'], JSON_THROW_ON_ERROR);
    exit(0);
}

if ($operation === 'initialize') {
    Illuminate\Support\Facades\DB::statement('SET ROLE secpal_owner');
    // Match fresh production initialization before any tenant or runtime state.
    $result = Illuminate\Support\Facades\Artisan::call('migrate', ['--force' => true]);
    // Framework output is not evidence and may include database diagnostics.
    exit($result === 0 ? 0 : 1);
}

if ($operation === 'seed') {
    if (Illuminate\Support\Facades\Artisan::call('tenant:setup') !== 0) {
        exit(1);
    }
    $application->make(App\Services\RuntimeHeartbeatService::class)->recordSchedulerHeartbeat();
    exit(0);
}

try {
    $pdo = Illuminate\Support\Facades\DB::connection()->getPdo();
    $tls = $pdo->query('SELECT version FROM pg_stat_ssl WHERE pid=pg_backend_pid() AND ssl')->fetchColumn();
    echo json_encode([
        'connected' => true, 'stage' => 'connection', 'driver' => $pdo->getAttribute(PDO::ATTR_DRIVER_NAME),
        'host' => config('database.connections.pgsql.host'),
        'sslmode' => config('database.connections.pgsql.sslmode'),
        'sslrootcert' => config('database.connections.pgsql.sslrootcert'), 'tls' => $tls,
    ], JSON_THROW_ON_ERROR);
} catch (PDOException $error) {
    // Classify the client failure, never retain its potentially secret message.
    // PDO PgSQL constructor failures use driver code 7; errorInfo owns SQLSTATE.
    if (($error->errorInfo[0] ?? (string) $error->getCode()) !== '08006') {
        exit(1);
    }
    $message = $error->getMessage();
    $reason = match (true) {
        str_contains($message, 'does not match host name') => 'hostname',
        str_contains($message, 'certificate verify failed') => 'certificate',
        str_contains($message, 'password authentication failed') => 'authentication',
        default => null,
    };
    if ($reason === null) {
        exit(1);
    }
    echo json_encode(['connected' => false, 'stage' => 'connection', 'reason' => $reason], JSON_THROW_ON_ERROR);
}
