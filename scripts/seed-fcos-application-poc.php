<?php

// SPDX-FileCopyrightText: 2026 SecPal Contributors
// SPDX-License-Identifier: MIT

declare(strict_types=1);

require '/run/secpal/bootstrap/production-secret-bootstrap.php';
require '/app/vendor/autoload.php';
$app = require '/app/bootstrap/app.php';
$app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();

$password = trim(stream_get_contents(STDIN, 128));
if (! $app->environment('local')
    || config('database.connections.pgsql.host') !== 'db.secpal.internal'
    || config('database.connections.pgsql.username') !== 'secpal_local'
    || ! preg_match('/^[a-f0-9]{48}$/D', $password)) {
    fwrite(STDERR, "Synthetic fixture seed rejected.\n");
    exit(64);
}

Illuminate\Support\Facades\DB::transaction(function () use ($app, $password) {
    $app->make(Database\Seeders\RolesAndPermissionsSeeder::class)->run();
    $app->make(Database\Seeders\OrganizationalUnitSeeder::class)->run();
    $tenant = App\Models\TenantKey::firstOrFail();
    $app->make(Spatie\Permission\PermissionRegistrar::class)->setPermissionsTeamId($tenant->id);
    $user = App\Models\User::updateOrCreate(
        ['email' => 'fcos-poc@secpal.example.invalid'],
        ['name' => 'FCOS Proof of Concept', 'password' => $password, 'tenant_id' => $tenant->id]
    );
    $user->forceFill(['email_verified_at' => now()])->save();
    $user->syncPermissions(App\Models\Permission::query()->where('guard_name', 'sanctum')->pluck('name')->all());
    $unit = App\Models\OrganizationalUnit::where('name', 'SecPal Holding')
        ->where('tenant_id', $tenant->id)->firstOrFail();
    foreach ([[0, 0], [1, 255]] as [$min, $max]) {
        App\Models\UserInternalOrganizationalScope::updateOrCreate(
            ['user_id' => $user->id, 'organizational_unit_id' => $unit->id,
                'min_viewable_rank' => $min, 'max_viewable_rank' => $max],
            ['access_level' => 'manage', 'include_descendants' => true, 'allow_self_access' => true,
                'min_assignable_rank' => 0, 'max_assignable_rank' => 255]
        );
    }
});

echo "Synthetic test account and organization seeded.\n";
