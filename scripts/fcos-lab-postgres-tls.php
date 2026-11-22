<?php
// SPDX-FileCopyrightText: 2026 SecPal Contributors
// SPDX-License-Identifier: MIT

declare(strict_types=1);

function postgresTlsExpiry(string $host, int $port, string $identity, string $ca): array
{
    if (!is_readable($ca)) {
        return ['status' => 'trust_unavailable'];
    }
    $context = stream_context_create(['ssl' => [
        'cafile' => $ca,
        'peer_name' => $identity,
        'verify_peer' => true,
        'verify_peer_name' => true,
        'capture_peer_cert' => true,
    ]]);
    $stream = @stream_socket_client("tcp://$host:$port", $errno, $error, 3, STREAM_CLIENT_CONNECT, $context);
    if ($stream === false) {
        return ['status' => 'unreachable'];
    }
    try {
        stream_set_timeout($stream, 3);
        // Send only PostgreSQL's SSLRequest. No startup packet or SQL follows.
        if (@fwrite($stream, pack('NN', 8, 80877103)) !== 8) {
            return ['status' => 'unreachable'];
        }
        $reply = @fread($stream, 1);
        if ($reply === false || $reply === '') {
            return ['status' => 'unreachable'];
        }
        if ($reply !== 'S' || @stream_socket_enable_crypto($stream, true, STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT) !== true) {
            return ['status' => 'invalid_tls'];
        }
        $certificate = stream_context_get_options($stream)['ssl']['peer_certificate'] ?? null;
        $expiry = $certificate instanceof OpenSSLCertificate
            ? (openssl_x509_parse($certificate)['validTo_time_t'] ?? null)
            : null;
        if (!is_int($expiry)) {
            return ['status' => 'invalid_tls'];
        }
        $remaining = $expiry - time();
        return [
            'status' => match (true) {
                $remaining <= 0 => 'invalid_tls',
                $remaining <= 7 * 86400 => 'warn_7d',
                $remaining <= 14 * 86400 => 'warn_14d',
                $remaining <= 30 * 86400 => 'warn_30d',
                default => 'ok',
            },
            'expires_at' => gmdate('Y-m-d\TH:i:s\Z', $expiry),
            'seconds_remaining' => $remaining,
        ];
    } finally {
        fclose($stream);
    }
}

// The installed user service passes this file to PHP on standard input.
if (($_SERVER['SCRIPT_FILENAME'] ?? null) === '') {
    $identity = 'db.secpal.internal';
    $result = postgresTlsExpiry($identity, 5432, $identity, '/run/secpal/secrets/database/postgres-ca.crt');
    echo json_encode(['schema' => 1, 'observed_at' => gmdate('Y-m-d\TH:i:s\Z')] + $result, JSON_THROW_ON_ERROR), "\n";
    exit(in_array($result['status'], ['ok', 'warn_30d', 'warn_14d', 'warn_7d'], true) ? 0 : 1);
}
