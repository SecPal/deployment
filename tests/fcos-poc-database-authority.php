<?php

// SPDX-FileCopyrightText: 2026 SecPal Contributors
// SPDX-License-Identifier: MIT

declare(strict_types=1);

require '/run/secpal/bootstrap/production-secret-bootstrap.php';
require '/app/vendor/autoload.php';
$app = require '/app/bootstrap/app.php';
$app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();

$stage = 'fixture';
try {
    if (! $app->environment('local')
        || config('database.connections.pgsql.username') !== 'secpal_poc_runtime') {
        throw new RuntimeException();
    }
    $pdo = $app->make('db')->connection()->getPdo();
    $stage = 'runtime-identity';
    $identity = $pdo->query("SELECT current_user AS principal,
        (current_user = session_user AND current_database() = 'secpal')::int AS own_session,
        (SELECT ssl::int FROM pg_stat_ssl WHERE pid = pg_backend_pid()) AS tls,
        (NOT (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls))::int AS restricted,
        has_schema_privilege(current_user, 'public', 'USAGE')::int AS schema_usage,
        has_database_privilege(current_user, 'postgres', 'CONNECT')::int AS unrelated_database
        FROM pg_roles WHERE rolname = current_user")->fetch(PDO::FETCH_ASSOC);
    if ($identity['principal'] !== 'secpal_poc_runtime' || (int) $identity['own_session'] !== 1
        || (int) $identity['tls'] !== 1 || (int) $identity['restricted'] !== 1
        || (int) $identity['schema_usage'] !== 1 || (int) $identity['unrelated_database'] !== 0) {
        throw new RuntimeException();
    }

    $stage = 'default-privileges';
    $pdo->beginTransaction();
    $created = $pdo->query("INSERT INTO public.fcos_privilege_witness (marker)
        VALUES ('synthetic') RETURNING id")->fetchColumn();
    $update = $pdo->prepare("UPDATE public.fcos_privilege_witness SET marker = 'updated' WHERE id = ?");
    $update->execute([$created]);
    $read = $pdo->prepare("SELECT marker FROM public.fcos_privilege_witness WHERE id = ?");
    $read->execute([$created]);
    $observed = $read->fetchColumn();
    $delete = $pdo->prepare("DELETE FROM public.fcos_privilege_witness WHERE id = ?");
    $delete->execute([$created]);
    $pdo->rollBack();
    if ((int) $created < 1 || $update->rowCount() !== 1 || $observed !== 'updated' || $delete->rowCount() !== 1) {
        throw new RuntimeException();
    }

    $denied = [];
    $queries = [
        'create-table' => 'CREATE TABLE public.fcos_denied (id integer)',
        'alter-table' => 'ALTER TABLE public.organizational_units ADD COLUMN fcos_denied integer',
        'drop-table' => 'DROP TABLE public.organizational_units CASCADE',
        'create-schema' => 'CREATE SCHEMA fcos_denied',
        'create-sequence' => 'CREATE SEQUENCE public.fcos_denied',
        'create-function' => 'CREATE OR REPLACE FUNCTION public.fcos_denied() RETURNS int LANGUAGE sql AS $$ SELECT 1 $$',
        'create-temp-table' => 'CREATE TEMP TABLE fcos_denied (id integer)',
        'truncate-table' => 'TRUNCATE TABLE public.fcos_privilege_witness',
        'change-migration-history' => 'UPDATE public.migrations SET batch = batch',
        'migration-login' => 'SET ROLE secpal_poc_migrate',
        'migration-role' => 'SET ROLE secpal_migration',
        'owner-role' => 'SET ROLE secpal_owner',
        'admin-role' => 'SET ROLE secpal_fixture_admin',
        'make-superuser' => 'ALTER ROLE secpal_poc_runtime SUPERUSER',
        'read-auth-catalog' => 'SELECT 1 FROM pg_authid LIMIT 1',
    ];
    foreach ($queries as $stage => $statement) {
        $pdo->beginTransaction();
        try {
            $pdo->exec($statement);
            throw new RuntimeException();
        } catch (PDOException $error) {
            if ($error->getCode() !== '42501') {
                throw $error;
            }
            $denied[$stage] = '42501';
        } finally {
            $pdo->rollBack();
        }
    }

    $connections = [
        'plaintext' => 'dbname=secpal;sslmode=disable',
        'unrelated-database' => 'dbname=postgres;sslmode=verify-full;sslrootcert=/run/secpal/secrets/database/postgres-ca.crt',
    ];
    foreach ($connections as $stage => $dsn) {
        try {
            new PDO('pgsql:host=db.secpal.internal;'.$dsn, 'secpal_poc_runtime',
                config('database.connections.pgsql.password'));
        } catch (PDOException $error) {
            $denied[$stage] = 'connection rejected';
            continue;
        }
        throw new RuntimeException();
    }

    echo json_encode([
        'principal' => $identity['principal'],
        'tls' => true,
        'future_table_dml_and_sequence' => true,
        'denied' => $denied,
    ], JSON_THROW_ON_ERROR), PHP_EOL;
} catch (Throwable $error) {
    fwrite(STDERR, "Database authority probe failed at $stage.\n");
    exit(1);
}
