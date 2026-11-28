<?php
// SPDX-FileCopyrightText: 2026 SecPal Contributors
// SPDX-License-Identifier: MIT

declare(strict_types=1);

require __DIR__.'/../scripts/fcos-lab-postgres-tls.php';

function requireCheck(bool $value, string $message): void
{
    if (!$value) {
        throw new RuntimeException($message);
    }
}

function verifySample(string $certificateFile, string $name, string $expected): void
{
    $context = stream_context_create(['ssl' => ['local_cert' => $certificateFile]]);
    $listener = stream_socket_server('tcp://127.0.0.1:0', $errno, $error, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $context);
    requireCheck($listener !== false, 'Could not open the disposable TLS peer.');
    $port = (int) substr(strrchr(stream_socket_get_name($listener, false), ':'), 1);
    $child = pcntl_fork();
    requireCheck($child !== -1, 'Could not start the disposable TLS peer.');
    if ($child === 0) {
        $stream = stream_socket_accept($listener, 3);
        if ($stream === false) {
            exit(1);
        }
        stream_set_timeout($stream, 3);
        if (fread($stream, 8) !== pack('NN', 8, 80877103)) {
            exit(1);
        }
        fwrite($stream, 'S');
        if (@stream_socket_enable_crypto($stream, true, STREAM_CRYPTO_METHOD_TLSv1_3_SERVER) === true) {
            // The client must close without sending a PostgreSQL startup packet.
            exit(fread($stream, 1) === '' && feof($stream) ? 0 : 1);
        }
        exit(0);
    }
    fclose($listener);
    $actual = postgresTlsExpiry('127.0.0.1', $port, $name, $certificateFile);
    pcntl_waitpid($child, $status);
    requireCheck(pcntl_wifexited($status) && pcntl_wexitstatus($status) === 0, 'The probe sent an unexpected PostgreSQL message.');
    requireCheck($actual['status'] === $expected, "Expected $expected, observed ".$actual['status']);
    if ($expected !== 'invalid_tls') {
        requireCheck(isset($actual['expires_at'], $actual['seconds_remaining']), 'Missing expiration evidence.');
    }
    requireCheck(
        postgresTlsExpiry('127.0.0.1', $port, $name, $certificateFile)['status'] === 'unreachable',
        'A closed PostgreSQL port must fail visibly.'
    );
}

umask(0077);
$config = tempnam(sys_get_temp_dir(), 'secpal-tls-config-');
$fixture = tempnam(sys_get_temp_dir(), 'secpal-tls-fixture-');
requireCheck(is_string($config) && is_string($fixture), 'Could not stage the disposable TLS fixture.');
try {
    file_put_contents($config, "[req]\ndistinguished_name=dn\n[dn]\n[v3]\nbasicConstraints=critical,CA:TRUE\n"
        ."subjectAltName=DNS:db.secpal.internal,DNS:postgres\nextendedKeyUsage=serverAuth\n");
    $options = ['config' => $config, 'digest_alg' => 'sha256', 'private_key_bits' => 2048, 'x509_extensions' => 'v3'];
    $key = openssl_pkey_new($options);
    requireCheck($key !== false, 'Could not generate a disposable key.');
    $request = openssl_csr_new(['commonName' => 'db.secpal.internal'], $key, $options);
    requireCheck($request !== false && openssl_pkey_export($key, $keyPem, null, $options), 'Could not generate a disposable request.');
    foreach ([365 => 'ok', 30 => 'warn_30d', 14 => 'warn_14d', 7 => 'warn_7d', 0 => 'invalid_tls'] as $days => $expected) {
        $certificate = openssl_csr_sign($request, null, $key, $days, $options);
        requireCheck($certificate !== false && openssl_x509_export($certificate, $certPem), 'Could not sign the disposable certificate.');
        file_put_contents($fixture, $certPem.$keyPem);
        if ($days === 0) {
            sleep(1);
        }
        verifySample($fixture, 'db.secpal.internal', $expected);
        if ($days === 365) {
            verifySample($fixture, 'wrong.secpal.internal', 'invalid_tls');
        }
    }
} finally {
    unlink($config);
    unlink($fixture);
}
echo "FCOS PostgreSQL TLS probe passed.\n";
