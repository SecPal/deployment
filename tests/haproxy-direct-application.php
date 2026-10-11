<?php

// SPDX-FileCopyrightText: 2026 SecPal Contributors
// SPDX-License-Identifier: MIT

// Local qualification probe for the API's pinned Symfony Request primitive.
// This is not a deployed endpoint or a substitute for the actual API runtime.

use Symfony\Component\HttpFoundation\Request;

if ($argc !== 2 || !is_dir($argv[1])) {
    fwrite(STDERR, "FAIL: pinned-framework-directory\n");
    exit(1);
}

$frameworkRoot = realpath($argv[1]);
spl_autoload_register(static function (string $class) use ($frameworkRoot): void {
    $prefix = 'Symfony\\Component\\HttpFoundation\\';
    if (str_starts_with($class, $prefix)) {
        $path = $frameworkRoot.'/'.str_replace('\\', '/', substr($class, strlen($prefix))).'.php';
        if (is_file($path)) {
            require $path;
        }
    }
});

try {
    $data = json_decode(stream_get_contents(STDIN, 16385), true, 16, JSON_THROW_ON_ERROR);
    $server = ['REMOTE_ADDR' => $data['peer'], 'SERVER_PORT' => 8080];
    foreach ($data['headers'] as $name => $value) {
        $server['HTTP_'.strtoupper(str_replace('-', '_', $name))] = $value;
    }
    Request::setTrustedProxies(['127.0.0.1'], Request::HEADER_X_FORWARDED_FOR |
        Request::HEADER_X_FORWARDED_HOST | Request::HEADER_X_FORWARDED_PROTO |
        Request::HEADER_X_FORWARDED_PORT);
    $request = Request::create('/', server: $server);
    echo json_encode(['client' => $request->getClientIp(), 'scheme' => $request->getScheme(),
        'host' => $request->getHost(), 'port' => $request->getPort()], JSON_THROW_ON_ERROR)."\n";
} catch (Throwable) {
    fwrite(STDERR, "FAIL: application-request-identity\n");
    exit(1);
}
