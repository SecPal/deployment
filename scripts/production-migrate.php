<?php
// SPDX-FileCopyrightText: 2026 SecPal Contributors
// SPDX-License-Identifier: MIT

declare(strict_types=1);

// Explicit oneshot only: ordinary runtime roles never mount migration credentials.
// API owns source admission, import locking, atomic activation and retention.
// Never interpret addresses:check success alone as release readiness.
$_SERVER['argv'] = ['/app/artisan', 'migrate', '--force'];
$operation = 'application-bootstrap';
try {
    require '/app/vendor/autoload.php';
    $application = require '/app/bootstrap/app.php';
    $application->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
    $operation = 'release-source-admission';
    $admission = $application->make(App\Services\AddressData\AddressDataSourceAdmission::class);
    $expectedHash = $admission->expectedSha256(config('address_data.expected_sha256'));
    $admission->remoteSourceUrl(config('address_data.source_url'));

    $operation = 'schema-migration';
    Illuminate\Support\Facades\DB::statement('SET ROLE secpal_owner');
    $result = Illuminate\Support\Facades\Artisan::call('migrate', ['--force' => true]);
    if ($result !== 0) {
        fwrite(STDERR, "ERROR: schema-migration returned nonzero.\n");
        exit($result);
    }

    // Close the DDL session before opening a direct runtime-only connection.
    // Reuse the bootstrap's strict file/identity admission; no secret enters
    // argv, the OS environment, Artisan output or generated configuration.
    $operation = 'import-database-session';
    Illuminate\Support\Facades\DB::disconnect();
    $credentials = secpalDatabaseCredentials('/run/secpal/secrets/import');
    config([
        'database.connections.pgsql.username' => $credentials['username'],
        'database.connections.pgsql.password' => $credentials['password'],
        'database.connections.pgsql.sslrootcert' => $credentials['sslrootcert'],
    ]);
    unset($credentials);
    Illuminate\Support\Facades\DB::purge('pgsql');
    // A reconnect would lose the API's session advisory lock. Fail closed;
    // only a new explicit one-shot may retry the operation.
    Illuminate\Support\Facades\DB::connection()->setReconnector(static function (): never {
        throw new RuntimeException('Import database session lost.');
    });

    $operation = 'address-import';
    // The release URL is admitted by the API. Do not follow a response to a
    // different source; deployment grants no moving URL or redirect egress.
    Illuminate\Support\Facades\Http::globalOptions(['allow_redirects' => false]);
    $result = Illuminate\Support\Facades\Artisan::call('addresses:import', ['--no-interaction' => true]);
    if ($result !== 0) {
        fwrite(STDERR, "ERROR: address-import returned nonzero; retry the explicit one-shot.\n");
        exit($result);
    }

    $operation = 'address-status';
    $result = Illuminate\Support\Facades\Artisan::call('addresses:check', ['--no-interaction' => true]);
    if ($result !== 0) {
        fwrite(STDERR, "ERROR: address-status returned nonzero.\n");
        exit($result);
    }
    // Consume the API-owned active-import selector and release configuration.
    $active = $application->make(App\Services\AddressData\AddressSuggestionService::class)
        ->activeImport(config('address_data.country'));
    if ($active === null || $active->status !== App\Models\AddressDataImport::STATUS_SUCCEEDED
        || $active->row_count < 1 || !is_string($active->source_sha256)
        || !hash_equals($expectedHash, $active->source_sha256)) {
        throw new RuntimeException('Approved address dataset is not active.');
    }
    fwrite(STDOUT, "Schema migration and release address reconciliation succeeded.\n");
    exit(0);
} catch (Throwable $error) {
    // Closed operation names only: framework exceptions can contain secrets.
    fwrite(STDERR, "ERROR: {$operation} failed.\n");
    exit(1);
}
