<?php
// SPDX-FileCopyrightText: 2026 SecPal Contributors
// SPDX-License-Identifier: MIT

declare(strict_types=1);

// Explicit oneshot only: bootstrap mounts migration credentials, never runtime.
// Setting the non-inherited owner role applies to the same application PDO
// session used by migrations; no role setting leaks into runtime processes.
$_SERVER['argv'] = ['/app/artisan', 'migrate', '--force'];
require '/app/vendor/autoload.php';
$application = require '/app/bootstrap/app.php';
try {
    $application->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
    Illuminate\Support\Facades\DB::statement('SET ROLE secpal_owner');
    $result = Illuminate\Support\Facades\Artisan::call('migrate', ['--force' => true]);
    exit($result === 0 ? 0 : 1);
} catch (Throwable $error) {
    fwrite(STDERR, "ERROR: explicit PostgreSQL migration failed.\n");
    exit(1);
}
